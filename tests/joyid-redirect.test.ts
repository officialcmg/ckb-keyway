import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";
import * as ccc from "@ckb-ccc/core";
import { p256 } from "@noble/curves/nist.js";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import {
  appendBuffer,
  base64URLStringToBuffer,
  buildJoyIDURL,
  bufferToBase64URLString,
  decodeSearch,
  encodeSearch,
  getRedirectResponse,
  utf8StringToBuffer,
} from "@joyid/common";
import { recoveryAccountAddress } from "../src/sdk/browser/account-recovery.ts";
import {
  captureJoyIdReturn,
  checkJoyIdResponse,
  chooseJoyIdTransport,
  isJoyIdRecord,
  joyIdBackupArguments,
  isReturnPath,
  joyIdRequest,
  JoyIdCancelledError,
  joyIdStateId,
  joyIdReturnUrl,
  readJoyIdReturn,
  resumeJoyIdRedirect,
  resetJoyIdHelperLoad,
  runJoyIdHelper,
  saveJoyIdRecord,
  stopBrowserNodeForRedirect,
  takeCapturedJoyIdReturn,
  takeJoyIdRecord,
  withoutJoyIdAnswer,
  type JoyIdRequestRecord,
  type JoyIdResponse,
} from "../src/sdk/browser/joyid-redirect.ts";
import { joyIdMainKey, recoveryBackupChallenge, verifyBackupOwnership } from "../src/sdk/browser/recovery-backups.ts";
import { parseJoyIdSignature, verifyWebAuthn, webAuthnChallenge } from "../src/sdk/browser/webauthn.ts";

const client = new ccc.ClientPublicTestnet({ url: "https://testnet.ckb.dev/" });
const sha256 = (bytes: Uint8Array) => new Uint8Array(createHash("sha256").update(bytes).digest());
const b64u = (bytes: Uint8Array) => Buffer.from(bytes).toString("base64url");
const APP = "https://app.example";

/** A JoyID main key: a P-256 passkey and its testnet JoyID address (lock args 0x0001 ‖ blake160(public key)). */
async function passkey() {
  const secret = p256.utils.randomSecretKey();
  const publicKey = p256.getPublicKey(secret, false).slice(1);
  const script = await client.getKnownScript(ccc.KnownScript.JoyId);
  const address = ccc.Address.fromScript({ codeHash: script.codeHash, hashType: script.hashType, args: ccc.hexFrom(ccc.bytesConcat([0x00, 0x01], ccc.hashCkbShort(publicKey))) }, client).toString();
  return { secret, publicKey, address, pubkey: Buffer.from(publicKey).toString("hex") };
}
type Passkey = Awaited<ReturnType<typeof passkey>>;

/**
 * What JoyID's page builds for a sign-message request, for both delivery modes (research/joyid-redirect §2):
 * startAuthentication over challenge = base64url(utf8(text)), generateSignedInfo, sendSignedMessageToDapp.
 */
function joyIdSignMessage(key: Passkey, request: { challenge: string; state?: unknown }, overrides: Record<string, unknown> = {}) {
  const challenge = bufferToBase64URLString(utf8StringToBuffer(request.challenge));
  const authData = ccc.bytesConcat(sha256(new TextEncoder().encode("testnet.joyid.dev")), [0x05], [0, 0, 0, 1]);
  const clientDataJSON = new TextEncoder().encode(JSON.stringify({ type: "webauthn.get", challenge, origin: "https://testnet.joyid.dev", crossOrigin: false }));
  const der = p256.sign(ccc.bytesConcat(authData, sha256(clientDataJSON)), key.secret, { prehash: true, format: "der", lowS: false });
  const message = bufferToBase64URLString(appendBuffer(base64URLStringToBuffer(b64u(authData)), base64URLStringToBuffer(b64u(clientDataJSON))));
  const data = { signature: b64u(der), message, challenge: request.challenge, alg: -7, pubkey: key.pubkey, keyType: "main_key", state: request.state, ...overrides };
  return { type: "SignMessage", data, state: request.state };
}

/** JoyID's redirect delivery: the message in `_data_` of the return URL, then decoded the way KeyWay reads it. */
function deliverByRedirect(message: unknown, redirectURL = `${APP}/app?joyid-redirect=true`): JoyIdResponse {
  const url = new URL(redirectURL);
  url.searchParams.set("_data_", encodeSearch(message as Record<string, unknown>));
  return readJoyIdReturn(url.href)!;
}

class MemoryStorage implements Storage {
  private items = new Map<string, string>();
  get length() { return this.items.size; }
  clear() { this.items.clear(); }
  getItem(key: string) { return this.items.get(key) ?? null; }
  key(index: number) { return [...this.items.keys()][index] ?? null; }
  removeItem(key: string) { this.items.delete(key); }
  setItem(key: string, value: string) { this.items.set(key, value); }
}

const ID = "0123456789abcdef0123456789abcdef";
const freshNonce = (ms = 10 * 60_000) => `${Date.now() + ms}.${"ab".repeat(16)}.${"cd".repeat(32)}`;

async function signRecord(key: Passkey, overrides: Partial<JoyIdRequestRecord> = {}): Promise<JoyIdRequestRecord> {
  const account = await recoveryAccountAddress(ccc.hexFrom(secp256k1.getPublicKey(secp256k1.utils.randomSecretKey(), true)), client);
  const challengeNonce = freshNonce();
  return {
    v: 1, id: ID, transport: "redirect", op: "backup-add", step: "sign", appId: null, userId: "user-1", account,
    joyIdAddress: key.address, challengeNonce, joyIdAppURL: "https://testnet.joyid.dev", name: "KeyWay", logo: `${APP}/icon.svg`,
    expiresAt: Number(challengeNonce.split(".")[0]), returnPath: "/app",
    ...overrides,
  };
}

const challengeOf = (record: JoyIdRequestRecord) => recoveryBackupChallenge(record.account, { kind: "joyid", address: record.joyIdAddress! }, record.challengeNonce!);
const context = { userId: "user-1", client };

test("a redirect-delivered JoyID signature is the window-delivered one, and KeyWay's checks accept it (P1)", async () => {
  const key = await passkey();
  const record = await signRecord(key);
  const request = joyIdRequest(record, `${APP}/app`) as Record<string, unknown>;
  const message = joyIdSignMessage(key, { challenge: request.challenge as string, state: request.state });

  // Window (popup) delivery: postMessage(message), runPopup resolves message.data.
  const byWindow = structuredClone(message).data;
  // Redirect delivery: the same object in `_data_`; getRedirectResponse and KeyWay's own reader agree.
  const back = new URL(`${APP}/app?joyid-redirect=true`);
  back.searchParams.set("_data_", encodeSearch(message));
  const byRedirect = getRedirectResponse(back.href) as typeof byWindow;
  assert.deepEqual(byRedirect, byWindow);
  assert.equal(typeof byRedirect.alg, "number");
  assert.deepEqual((readJoyIdReturn(back.href) as { data: unknown }).data, byWindow);

  // As CCC's signer would hand it to KeyWay.
  const asCcc = (data: typeof byWindow) => JSON.stringify({ signature: data.signature, alg: data.alg, message: data.message });
  assert.equal(asCcc(byRedirect), asCcc(byWindow));
  const identity = JSON.stringify({ keyType: "main_key", publicKey: byRedirect.pubkey });
  const publicKey = joyIdMainKey(identity, asCcc(byRedirect))!;
  assert.ok(verifyWebAuthn(parseJoyIdSignature(asCcc(byRedirect), publicKey), challengeOf(record)));
  assert.equal(bufferToBase64URLString(utf8StringToBuffer(challengeOf(record))), webAuthnChallenge(challengeOf(record)));
  const backup = await verifyBackupOwnership(client, record.account, { kind: "joyid", address: key.address, signature: asCcc(byRedirect), identity, challengeNonce: record.challengeNonce });
  assert.equal(backup.address, key.address);

  // And the resume path turns it into the proof CCC's signer would have produced.
  const result = await checkJoyIdResponse(record, readJoyIdReturn(back.href)!, context);
  assert.equal(result.step, "sign");
  assert.deepEqual(result.step === "sign" && result.proof, { kind: "joyid", address: key.address, signature: asCcc(byWindow), identity, challengeNonce: record.challengeNonce });
});

test("the request carries exactly the fields CCC's JoyID signer sends, plus state", async () => {
  const key = await passkey();
  const record = await signRecord(key);
  assert.deepEqual(Object.keys(joyIdRequest(record, `${APP}/app`)).sort(), ["address", "challenge", "isData", "joyidAppURL", "logo", "name", "redirectURL", "state"]);
  assert.deepEqual(Object.keys(joyIdRequest({ ...record, step: "auth" }, `${APP}/app`)).sort(), ["joyidAppURL", "logo", "name", "redirectURL", "state"]);
  const request = joyIdRequest(record, `${APP}/app`) as Record<string, unknown>;
  assert.equal(request.isData, false);
  assert.equal(request.challenge, challengeOf(record));
  // Auth never carries a challenge: JoyID would sign "JoyID authorize prefix:\n…", which KeyWay rejects.
  assert.equal("challenge" in joyIdRequest({ ...record, step: "auth" }, `${APP}/app`), false);
  const url = new URL(buildJoyIDURL(request as never, "redirect", "/sign-message"));
  assert.equal(url.origin, "https://testnet.joyid.dev");
  assert.equal(url.searchParams.get("type"), "redirect");
  const sent = decodeSearch(url.searchParams.get("_data_")!) as Record<string, unknown>;
  assert.equal(sent.redirectURL, `${APP}/app?joyid-redirect=true`);
  assert.deepEqual(sent.state, { v: 1, id: ID });
});

test("state survives encodeSearch/decodeSearch at the top level, also for Auth", () => {
  for (const id of [ID, "00000000000000000000000000000000", "12345678901234567890123456789012"]) {
    const auth = deliverByRedirect({ type: "Auth", data: { address: "ckt1x", keyType: "main_key", alg: -7 }, state: { v: 1, id } });
    assert.equal(joyIdStateId(auth.state), id);
    const sign = deliverByRedirect({ type: "SignMessage", data: { state: { v: 1, id } }, state: { v: 1, id } });
    assert.equal(joyIdStateId(sign.state), id);
  }
  assert.equal(joyIdStateId({ v: 1, id: "short" }), undefined);
  assert.equal(joyIdStateId({ v: 2, id: ID }), undefined);
  assert.equal(joyIdStateId("12345"), undefined);
});

test("a recorded request is used once", async () => {
  const storage = new MemoryStorage();
  const record = await signRecord(await passkey());
  saveJoyIdRecord(storage, record);
  assert.deepEqual(takeJoyIdRecord(storage, ID), record);
  assert.equal(takeJoyIdRecord(storage, ID), undefined);
  assert.equal(storage.length, 0);
  storage.setItem(`keyway:joyid:${ID}`, JSON.stringify({ ...record, returnPath: "//evil.example/" }));
  assert.equal(takeJoyIdRecord(storage, ID), undefined, "a tampered record is refused");
  assert.equal(storage.length, 0, "and deleted all the same");
  assert.equal(takeJoyIdRecord(storage, "../other"), undefined);
});

test("resume rejects anything but the answer this tab asked for", async () => {
  const key = await passkey();
  const other = await passkey();
  const record = await signRecord(key);
  const request = joyIdRequest(record, `${APP}/app`) as Record<string, unknown>;
  const good = deliverByRedirect(joyIdSignMessage(key, { challenge: challengeOf(record), state: request.state }));
  const answer = (overrides: Record<string, unknown>, top: Record<string, unknown> = {}) =>
    deliverByRedirect({ ...joyIdSignMessage(key, { challenge: challengeOf(record), state: request.state }, overrides), ...top });
  const storage = new MemoryStorage();
  const resume = (response: JoyIdResponse, rec: JoyIdRequestRecord | undefined, ctx: { userId?: string; now?: Date } = {}) =>
    resumeJoyIdRedirect(response, rec, { userId: "user-1", client, requestChallenge: async () => freshNonce(), ...ctx });

  // Unknown or consumed state: no record in this tab.
  saveJoyIdRecord(storage, record);
  assert.ok(takeJoyIdRecord(storage, joyIdStateId(good.state)));
  await assert.rejects(resume(good, takeJoyIdRecord(storage, joyIdStateId(good.state))), /doesn't match this request/);
  await assert.rejects(resume(deliverByRedirect({ ...joyIdSignMessage(key, { challenge: challengeOf(record) }), state: undefined }), undefined), /doesn't match this request/);
  // A record whose id isn't the answer's state.
  await assert.rejects(checkJoyIdResponse({ ...record, id: "f".repeat(32) }, good, context), /doesn't match this request/);
  // Expired.
  await assert.rejects(checkJoyIdResponse({ ...record, expiresAt: Date.now() - 1 }, good, context), /expired/);
  // A different user, or nobody signed in.
  await assert.rejects(checkJoyIdResponse(record, good, { ...context, userId: "user-2" }), /different sign-in/);
  await assert.rejects(checkJoyIdResponse(record, good, { ...context, userId: undefined }), /Sign in again/);
  // Step and type must match.
  await assert.rejects(checkJoyIdResponse({ ...record, step: "auth" }, good, context), /doesn't match this request/);
  await assert.rejects(checkJoyIdResponse(record, answer({}, { type: "Auth" }), context), /doesn't match this request/);
  // The exact challenge text: another nonce, another account, or a trailing space.
  await assert.rejects(checkJoyIdResponse({ ...record, challengeNonce: freshNonce(5 * 60_000) }, good, context), /doesn't match this request/);
  await assert.rejects(checkJoyIdResponse(record, answer({ challenge: `${challengeOf(record)} ` }), context), /doesn't match this request/);
  // A different JoyID signed (its own valid assertion over this challenge), or claims this address with its key.
  const otherSigned = deliverByRedirect(joyIdSignMessage(other, { challenge: challengeOf(record), state: request.state }));
  await assert.rejects(checkJoyIdResponse(record, otherSigned, context), /didn't sign the recovery approval/);
  // Sub keys and session keys, with JoyID's own wording.
  await assert.rejects(checkJoyIdResponse(record, answer({ keyType: "sub_key" }), context), /device added later/);
  await assert.rejects(checkJoyIdResponse(record, answer({ keyType: "main_session_key" }), context), /session key/);
  await assert.rejects(checkJoyIdResponse(record, answer({ keyType: "sub_session_key" }), context), /session key/);
  // Only ES256.
  await assert.rejects(checkJoyIdResponse(record, answer({ alg: -257 }), context), /session key/);
  await assert.rejects(checkJoyIdResponse(record, answer({ alg: -8 }), context), /doesn't match this request/);
  await assert.rejects(checkJoyIdResponse(record, answer({ alg: "-7" }), context), /doesn't match this request/);
  // A well-formed signature that doesn't verify for this key.
  await assert.rejects(checkJoyIdResponse(record, answer({ signature: (otherSigned.data as { signature: string }).signature }), context), /didn't sign/);
  // The user rejecting in JoyID is a cancel.
  const rejected = deliverByRedirect({ error: "User Rejected", type: "SignMessage", state: request.state });
  await assert.rejects(checkJoyIdResponse(record, rejected, context), (error: unknown) => error instanceof JoyIdCancelledError);
  // The genuine answer passes.
  const accepted = await checkJoyIdResponse(record, good, context);
  assert.equal(accepted.step, "sign");
});

test("an Auth answer must be a JoyID main key whose key matches its address", async () => {
  const key = await passkey();
  const other = await passkey();
  const record = { ...await signRecord(key), step: "auth" as const, joyIdAddress: undefined, challengeNonce: undefined, expiresAt: Date.now() + 60_000 };
  const auth = (data: Record<string, unknown>) => deliverByRedirect({ type: "Auth", data: { address: key.address, pubkey: key.pubkey, keyType: "main_key", alg: -7, ...data }, state: { v: 1, id: ID } });
  const result = await checkJoyIdResponse(record, auth({}), context);
  assert.deepEqual(result, { step: "auth", address: key.address, publicKey: `0x${key.pubkey}`, keyType: "main_key" });
  await assert.rejects(checkJoyIdResponse(record, auth({ pubkey: other.pubkey }), context), /doesn't match this request/);
  await assert.rejects(checkJoyIdResponse(record, auth({ keyType: "sub_key" }), context), /device added later/);
  await assert.rejects(checkJoyIdResponse(record, auth({ address: "ckt1qyqrdsefa43s6m882pcj53m4gdnj4k440axqswmu83" }), context), /isn't a JoyID address/);
  await assert.rejects(checkJoyIdResponse(record, auth({}), { ...context, now: new Date(record.expiresAt) }), /expired/);
});

test("after a redirect, a connect answer continues to the sign step with a fresh state and the nonce asked for then", async () => {
  const key = await passkey();
  const record: JoyIdRequestRecord = { ...await signRecord(key), step: "auth", joyIdAddress: undefined, challengeNonce: undefined, expiresAt: Date.now() + 60_000 };
  const assigned: string[] = [];
  const storage = new MemoryStorage();
  const globals = globalThis as Record<string, unknown>;
  const saved = { location: globals.location, sessionStorage: globals.sessionStorage, localStorage: globals.localStorage };
  globals.location = { origin: APP, assign: (url: string) => assigned.push(url) };
  globals.sessionStorage = storage;
  globals.localStorage = new MemoryStorage();
  try {
    let asked = 0;
    const nonce = freshNonce();
    const response = deliverByRedirect({ type: "Auth", data: { address: key.address, pubkey: key.pubkey, keyType: "main_key", alg: -7 }, state: { v: 1, id: ID } });
    const result = await resumeJoyIdRedirect(response, record, { userId: "user-1", client, requestChallenge: async () => { asked += 1; return nonce; } });
    assert.equal(result.status, "continuing");
    assert.equal(asked, 1);
    assert.equal(assigned.length, 1);
    const url = new URL(assigned[0]);
    assert.equal(url.pathname, "/sign-message");
    const sent = decodeSearch(url.searchParams.get("_data_")!) as Record<string, unknown>;
    assert.equal(sent.address, key.address);
    assert.equal(sent.challenge, recoveryBackupChallenge(record.account, { kind: "joyid", address: key.address }, nonce));
    const nextId = joyIdStateId(sent.state)!;
    assert.notEqual(nextId, ID);
    assert.equal(takeJoyIdRecord(storage, nextId)?.step, "sign");
    // The connection is kept where CCC's JoyID signer looks for it.
    assert.match((globals.localStorage as Storage).getItem("ccc-joy-id-signer")!, new RegExp(key.address));
  } finally {
    Object.assign(globals, saved);
  }
});

test("the answer leaves the address bar as soon as the SDK loads, before anything can fetch it", () => {
  const globals = globalThis as Record<string, unknown>;
  const saved = { window: globals.window, location: globals.location, history: globals.history };
  const calls: string[] = [];
  const answer = encodeSearch({ type: "SignMessage", data: { signature: "x" }, state: { v: 1, id: ID } });
  const run = (href: string) => {
    const location = { href };
    globals.window = {};
    globals.location = location;
    globals.history = { state: null, replaceState: (_: unknown, __: string, url: string) => { calls.push(url); location.href = new URL(url, href).href; } };
    captureJoyIdReturn();
    return location.href;
  };
  try {
    const href = `${APP}/app?mode=browser&joyid-redirect=true&_data_=${encodeURIComponent(answer)}`;
    assert.equal(run(href), `${APP}/app?mode=browser`);
    assert.equal(joyIdStateId(takeCapturedJoyIdReturn()?.state), ID);
    assert.equal(takeCapturedJoyIdReturn(), undefined);
    // The JoyID window keeps its marker.
    assert.equal(run(`${APP}/app?keyway-joyid=${ID}&joyid-redirect=true&_data_=${encodeURIComponent(answer)}`), `${APP}/app?keyway-joyid=${ID}`);
    takeCapturedJoyIdReturn();
    // Another library's JoyID answer is left alone.
    const foreign = encodeSearch({ type: "Auth", data: {}, state: "app-state" });
    calls.length = 0;
    assert.equal(run(`${APP}/login?joyid-redirect=true&_data_=${encodeURIComponent(foreign)}`), `${APP}/login?joyid-redirect=true&_data_=${encodeURIComponent(foreign)}`);
    assert.equal(calls.length, 0);
    assert.equal(takeCapturedJoyIdReturn(), undefined);
  } finally {
    Object.assign(globals, saved);
  }
  assert.equal(withoutJoyIdAnswer(`${APP}/a?x=1&joyid-redirect=true&_data_=y#h`), "/a?x=1#h");
});

test("transport: JoyID's own window unless the page is cross-origin isolated", () => {
  assert.equal(chooseJoyIdTransport("auto", { isolated: false, standalone: false }), "popup");
  assert.equal(chooseJoyIdTransport("auto", { isolated: true, standalone: false }), "window");
  assert.equal(chooseJoyIdTransport("auto", { isolated: true, standalone: true }), "redirect");
  assert.equal(chooseJoyIdTransport("window", { isolated: false, standalone: true }), "redirect");
  assert.equal(chooseJoyIdTransport("popup", { isolated: true, standalone: false }), "popup");
  assert.equal(chooseJoyIdTransport("redirect", { isolated: false, standalone: false }), "redirect");
});

test("return paths stay on this site", () => {
  for (const path of ["/", "/app", "/app?mode=browser", "/wallet#recovery"]) assert.ok(isReturnPath(path), path);
  for (const path of ["//evil.example", "/\\evil.example", "https://evil.example", "app", ""]) assert.equal(isReturnPath(path), false, path);
  assert.equal(isJoyIdRecord({ v: 1 }), false);
});

test("a full-page redirect stops a browser node cleanly, and refuses mid-payment", async () => {
  const calls: string[] = [];
  const node = (busy: boolean, running = true) => ({
    kind: "browser" as const,
    busy,
    starting: Promise.resolve().then(() => { calls.push("started"); }),
    running: () => running,
    stop: async () => { calls.push("stop"); },
  });
  await stopBrowserNodeForRedirect(node(false));
  assert.deepEqual(calls, ["started", "stop"]);
  calls.length = 0;
  await assert.rejects(stopBrowserNodeForRedirect(node(true)), /still running/);
  assert.equal(calls.includes("stop"), false);
  calls.length = 0;
  await stopBrowserNodeForRedirect({ ...node(false), kind: "hosted" });
  await stopBrowserNodeForRedirect(node(false, false));
  assert.equal(calls.includes("stop"), false);
});

/** A same-process BroadcastChannel: every channel with the name gets every other one's messages, in order. */
function fakeBroadcast() {
  const open = new Set<{ name: string; onmessage: ((event: MessageEvent) => void) | null }>();
  const sent: unknown[] = [];
  class Channel {
    onmessage: ((event: MessageEvent) => void) | null = null;
    constructor(readonly name: string) { open.add(this); }
    postMessage(data: unknown) {
      sent.push(structuredClone(data));
      for (const channel of open) if (channel !== this && channel.name === this.name) channel.onmessage?.({ data: structuredClone(data) } as MessageEvent);
    }
    close() { open.delete(this); }
  }
  const deliver = (data: unknown) => { for (const channel of open) channel.onmessage?.({ data } as MessageEvent); };
  return { Channel, sent, deliver };
}

test("the JoyID window answers only its own requests, and says when it is closed", async () => {
  const globals = globalThis as Record<string, unknown>;
  const saved = { window: globals.window, location: globals.location, history: globals.history, sessionStorage: globals.sessionStorage, BroadcastChannel: globals.BroadcastChannel };
  const broadcast = fakeBroadcast();
  const listeners = new Map<string, () => void>();
  const assigned: string[] = [];
  let closed = 0;
  try {
    globals.BroadcastChannel = broadcast.Channel;
    globals.sessionStorage = new MemoryStorage();
    globals.window = { addEventListener: (type: string, listener: () => void) => listeners.set(type, listener), removeEventListener: () => undefined, close: () => { closed += 1; } };
    globals.location = { href: `${APP}/app?keyway-joyid=${ID}`, origin: APP, assign: (url: string) => assigned.push(url) };
    const statuses: string[] = [];
    resetJoyIdHelperLoad();
    // React StrictMode runs the effect, cleans up and runs it again: the opening tab hears "ready" once.
    runJoyIdHelper(() => undefined)();
    const stop = runJoyIdHelper((status) => statuses.push(status));
    assert.deepEqual(broadcast.sent, [{ kind: "ready", helper: ID }]);
    const record = { ...await signRecord(await passkey()), transport: "window" as const, id: "a".repeat(32) };
    // Another window's request, a full-page request, or a JoyID app that isn't JoyID's: ignored.
    broadcast.deliver({ kind: "go", helper: "b".repeat(32), record });
    broadcast.deliver({ kind: "go", helper: ID, record: { ...record, transport: "redirect" } });
    broadcast.deliver({ kind: "go", helper: ID, record: { ...record, joyIdAppURL: "https://evil.example" } });
    broadcast.deliver({ kind: "close", helper: "b".repeat(32) });
    assert.equal(assigned.length, 0);
    assert.equal(closed, 0);
    // Its own request goes to JoyID, recorded once in this window; leaving for JoyID isn't "gone".
    broadcast.deliver({ kind: "go", helper: ID, record });
    assert.equal(assigned.length, 1);
    const url = new URL(assigned[0]);
    assert.equal(url.origin, "https://testnet.joyid.dev");
    assert.equal((decodeSearch(url.searchParams.get("_data_")!) as { redirectURL: string }).redirectURL, `${APP}/app?keyway-joyid=${ID}&joyid-redirect=true`);
    assert.ok(takeJoyIdRecord(globals.sessionStorage as Storage, record.id));
    listeners.get("pagehide")!();
    assert.equal(broadcast.sent.some((message) => (message as { kind: string }).kind === "gone"), false);
    stop();
    // A fresh window that the user closes before JoyID: the opening tab hears "gone".
    broadcast.sent.length = 0;
    resetJoyIdHelperLoad();
    const stopAgain = runJoyIdHelper(() => undefined);
    listeners.get("pagehide")!();
    assert.deepEqual(broadcast.sent, [{ kind: "ready", helper: ID }, { kind: "gone", helper: ID }]);
    stopAgain();
    assert.ok(statuses.includes("opening"));
    // Back from JoyID's page into this page from the browser's cache: the request is over.
    broadcast.sent.length = 0;
    resetJoyIdHelperLoad();
    const stopCached = runJoyIdHelper(() => undefined);
    broadcast.deliver({ kind: "go", helper: ID, record: { ...record, id: "d".repeat(32) } });
    (listeners.get("pageshow") as unknown as (event: { persisted: boolean }) => void)({ persisted: true });
    assert.deepEqual(broadcast.sent.at(-1), { kind: "gone", helper: ID });
    stopCached();
  } finally {
    Object.assign(globals, saved);
  }
});

test("JoyID return URLs stay on this site and drop stale JoyID parameters", () => {
  const globals = globalThis as Record<string, unknown>;
  const saved = globals.location;
  globals.location = { origin: APP };
  try {
    assert.equal(joyIdReturnUrl(`/app?mode=browser&keyway-joyid=${"c".repeat(32)}&_data_=x&joyid-redirect=true`, ID), `${APP}/app?mode=browser&keyway-joyid=${ID}`);
    assert.equal(joyIdReturnUrl("/app#recovery"), `${APP}/app#recovery`);
    assert.throws(() => joyIdReturnUrl("//evil.example/app"), /path on this site/);
    assert.throws(() => joyIdReturnUrl("https://evil.example/app"), /path on this site/);
  } finally {
    globals.location = saved;
  }
});

test("createJoyIdBackup's options are kept with or without a signer", () => {
  const signal = new AbortController().signal;
  const options = { transport: "window" as const, signal, onStage: () => undefined };
  const signer = { signMessage: async () => undefined } as unknown as ccc.Signer;
  assert.deepEqual(joyIdBackupArguments(undefined, options), [undefined, options]);
  assert.deepEqual(joyIdBackupArguments(options), [undefined, options]);
  assert.deepEqual(joyIdBackupArguments(signer, options), [signer, options]);
  assert.deepEqual(joyIdBackupArguments(signer), [signer, {}]);
  assert.deepEqual(joyIdBackupArguments(), [undefined, {}]);
});

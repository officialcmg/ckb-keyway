/**
 * Proof: a JoyID sign-message result delivered by REDIRECT decodes to the same bytes as the POPUP result, and
 * KeyWay's own checks (parseJoyIdSignature, verifyWebAuthn, verifyBackupOwnership) accept it unchanged.
 *
 * JoyID's page is closed source. Its two delivery paths are reproduced here from the live bundle
 * (evidence/joyid-app-excerpts.txt): generateSignedInfo + sendSignedMessageToDapp build ONE message object,
 * then sendMessageToDapp either postMessage()s it (popup) or puts encodeSearch(message) in `_data_` and
 * location.replace()s (redirect). The WebAuthn assertion is a real P-256 signature made here, shaped like
 * @simplewebauthn's startAuthentication() output, over challenge = base64url(utf8(text)) as JoyID's
 * useSignMessage(utf8StringToBuffer, t => bufferToBase64URLString(utf8StringToBuffer(t))) does.
 *
 * Run: node --import tsx research/joyid-redirect/proofs/redirect-equivalence.ts
 */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import * as ccc from "@ckb-ccc/core";
import { p256 } from "@noble/curves/nist.js";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import {
  buildJoyIDURL, decodeSearch, encodeSearch, getRedirectResponse, isRedirectFromJoyID,
  bufferToBase64URLString, utf8StringToBuffer, base64URLStringToBuffer, appendBuffer,
} from "@joyid/common";
import { recoveryBackupChallenge, verifyBackupOwnership, joyIdMainKey } from "../../../src/sdk/browser/recovery-backups";
import { parseJoyIdSignature, verifyWebAuthn, webAuthnChallenge } from "../../../src/sdk/browser/webauthn";
import { recoveryAccountAddress } from "../../../src/sdk/browser/account-recovery";

const log = (...a: unknown[]) => console.log(...a);
const sha256 = (b: Uint8Array) => new Uint8Array(createHash("sha256").update(b).digest());
const b64u = (b: Uint8Array) => Buffer.from(b).toString("base64url");

// --- A passkey (P-256) and its JoyID main-key address on testnet -------------------------------------------
const client = new ccc.ClientPublicTestnet();
const passkeyPriv = p256.utils.randomSecretKey();
const passkeyPub = p256.getPublicKey(passkeyPriv, false).slice(1); // 64 bytes X||Y
const joyIdScript = await client.getKnownScript(ccc.KnownScript.JoyId);
const joyIdAddress = ccc.Address.fromScript(
  { codeHash: joyIdScript.codeHash, hashType: joyIdScript.hashType, args: ccc.hexFrom(ccc.bytesConcat([0x00, 0x01], ccc.hashCkbShort(passkeyPub))) },
  client,
).toString();
const account = await recoveryAccountAddress(ccc.hexFrom(secp256k1.getPublicKey(secp256k1.utils.randomSecretKey(), true)), client);
const nonce = `${Date.now() + 15 * 60_000}.${"ab".repeat(16)}.${"cd".repeat(32)}`;
const text = recoveryBackupChallenge(account, { kind: "joyid", address: joyIdAddress }, nonce);
const appURL = "https://app.example/wallet?tab=recovery";

// --- 1. The REQUEST to JoyID: popup vs redirect ------------------------------------------------------------
// What CCC's CkbSigner.signMessageRaw sends (dist/barrel.mjs): {...getConfig(), challenge, isData: typeof m != "string", address}
const cccConfig = { redirectURL: appURL, joyidAppURL: "https://testnet.joyid.dev", name: "KeyWay", logo: "https://app.example/icon.svg" };
const request = { ...cccConfig, challenge: text, isData: false, address: joyIdAddress, state: { v: 1, id: "f".repeat(32) } };
const popupURL = new URL(buildJoyIDURL(request as never, "popup", "/sign-message"));
const redirectURL = new URL(buildJoyIDURL(request as never, "redirect", "/sign-message"));
const popupReq = decodeSearch(popupURL.searchParams.get("_data_")!) as Record<string, unknown>;
const redirectReq = decodeSearch(redirectURL.searchParams.get("_data_")!) as Record<string, unknown>;
log("1. request URL type param:", popupURL.searchParams.get("type"), "vs", redirectURL.searchParams.get("type"));
const differing = Object.keys({ ...popupReq, ...redirectReq }).filter((k) => JSON.stringify(popupReq[k]) !== JSON.stringify(redirectReq[k]));
log("   request fields that differ:", differing, "->", redirectReq.redirectURL);
assert.deepEqual(differing, ["redirectURL"]);
assert.equal(redirectReq.challenge, text);
assert.equal(redirectReq.isData, false);
log("   request URL length (redirect):", redirectURL.href.length, "chars");

// --- 2. JoyID's page signs (same code for both modes) ------------------------------------------------------
const challengeB64 = bufferToBase64URLString(utf8StringToBuffer(text)); // JoyID useSignMessage mapper for isData=false
assert.equal(challengeB64, webAuthnChallenge(text));
const authData = ccc.bytesConcat(sha256(new TextEncoder().encode("joyid.dev")), [0x05], [0, 0, 0, 1]); // 37 bytes, UP|UV
const clientDataJSON = new TextEncoder().encode(JSON.stringify({ type: "webauthn.get", challenge: challengeB64, origin: "https://testnet.joyid.dev", crossOrigin: false }));
const der = p256.sign(ccc.bytesConcat(authData, sha256(clientDataJSON)), passkeyPriv, { prehash: true, format: "der", lowS: false });
const assertion = { response: { authenticatorData: b64u(authData), clientDataJSON: b64u(clientDataJSON), signature: b64u(der) } };
// generateSignedInfo (JoyID bundle, de-minified)
const message = bufferToBase64URLString(appendBuffer(base64URLStringToBuffer(assertion.response.authenticatorData), base64URLStringToBuffer(assertion.response.clientDataJSON)));
const account0 = { alg: -7, pubkey: `0x${Buffer.from(passkeyPub).toString("hex")}`, keyType: "main_key" };
// sendSignedMessageToDapp (JoyID bundle, de-minified)
const Zr = { signature: assertion.response.signature, message, challenge: request.challenge, alg: account0.alg, pubkey: account0.pubkey.slice(2), keyType: account0.keyType, state: request.state };
const jsMessage = { type: "SignMessage", data: { ...Zr }, state: request.state };

// --- 3a. POPUP delivery: window.opener.postMessage(msg) -> runPopup resolves e.data.data -------------------
const popupData = structuredClone(jsMessage).data;
// --- 3b. REDIRECT delivery: url.searchParams.set("_data_", encodeSearch(msg)); location.replace(url.href) ---
const back = new URL(redirectReq.redirectURL as string);
back.searchParams.set("_data_", encodeSearch(jsMessage));
log("3. return URL is", back.origin + back.pathname, "with query keys", [...back.searchParams.keys()], "and fragment", JSON.stringify(back.hash));
log("   return URL length:", back.href.length, "chars (Vercel CDN limit 14 KB)");
assert.ok(isRedirectFromJoyID(back.href));
const redirectData = getRedirectResponse(back.href) as typeof popupData;

// --- 4. What CCC's signMessageRaw would return, from each ---------------------------------------------------
const asCcc = (d: typeof popupData) => JSON.stringify({ signature: d.signature, alg: d.alg, message: d.message });
log("4. signature JSON identical:", asCcc(popupData) === asCcc(redirectData));
assert.equal(asCcc(redirectData), asCcc(popupData));
for (const k of ["signature", "message", "challenge", "alg", "pubkey", "keyType"] as const) assert.deepEqual(redirectData[k], popupData[k], k);
assert.equal(typeof redirectData.alg, "number");
log("   field-by-field equal: signature, message, challenge, alg (number -7), pubkey, keyType; state =", JSON.stringify(redirectData.state));

// --- 5. KeyWay's checks accept the redirect result unchanged ------------------------------------------------
const identity = JSON.stringify({ keyType: redirectData.keyType, publicKey: ccc.hexFrom(`0x${redirectData.pubkey}`) }); // as CCC getIdentity() builds it
const pk = joyIdMainKey(identity, asCcc(redirectData))!;
const parsed = parseJoyIdSignature(asCcc(redirectData), pk);
log("5. verifyWebAuthn(redirect):", verifyWebAuthn(parsed, text));
assert.ok(verifyWebAuthn(parsed, text));
const backup = await verifyBackupOwnership(client, account, { kind: "joyid", address: joyIdAddress, signature: asCcc(redirectData), identity, challengeNonce: nonce });
log("   verifyBackupOwnership(redirect) ->", backup.kind, backup.address === joyIdAddress ? "(address matches)" : "MISMATCH");
assert.ok(!verifyWebAuthn(parsed, text + " "), "a different text must fail");

// --- 6. state round trip details -----------------------------------------------------------------------------
const top = decodeSearch(back.searchParams.get("_data_")!) as Record<string, unknown>;
log("6. top-level state:", JSON.stringify(top.state), "| data.state:", JSON.stringify(redirectData.state));
// Auth (connect) via redirect: JoyID's sendRawAuthMessageToDapp puts state only at top level, so getRedirectResponse() drops it.
const authBack = new URL(back.origin + back.pathname + "?joyid-redirect=true");
authBack.searchParams.set("_data_", encodeSearch({ type: "Auth", data: { address: joyIdAddress, pubkey: Zr.pubkey, keyType: "main_key", alg: -7 }, state: request.state }));
const authResult = getRedirectResponse(authBack.href) as Record<string, unknown>;
log("   Auth via getRedirectResponse has state?", "state" in authResult, "-> read top-level state with decodeSearch(_data_) instead:", JSON.stringify((decodeSearch(authBack.searchParams.get("_data_")!) as { state: unknown }).state));
// qss coercion: a bare numeric string state survives because encodeSearch JSON-quotes strings that parse as JSON.
for (const s of ["12345", "true", "abc", { id: "007" }]) {
  const u = new URL("https://a.example/?joyid-redirect=true");
  u.searchParams.set("_data_", encodeSearch({ type: "SignMessage", data: { ok: 1 }, state: s }));
  log("   state", JSON.stringify(s), "->", JSON.stringify((decodeSearch(u.searchParams.get("_data_")!) as { state: unknown }).state));
}
// Error path: user rejects -> {error:"User Rejected", type, state}
const rej = new URL(back.origin + back.pathname + "?joyid-redirect=true");
rej.searchParams.set("_data_", encodeSearch({ error: "User Rejected", type: "SignMessage", state: request.state }));
try { getRedirectResponse(rej.href); } catch (e) { log("   reject ->", (e as Error).constructor.name, (e as Error).message, JSON.stringify((e as { state?: unknown }).state)); }
log("ALL ASSERTIONS PASSED");

import assert from "node:assert/strict";
import test from "node:test";
import * as ccc from "@ckb-ccc/core";
import { p256 } from "@noble/curves/nist.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { clientDataMatches, parseJoyIdSignature, verifyWebAuthn, webAuthnChallenge, webAuthnSignatureBlob, type WebAuthnAssertion } from "../src/sdk/browser/webauthn.ts";

const base64url = (bytes: Uint8Array) => Buffer.from(bytes).toString("base64url");
const TEXT = `CKB transaction: 0x${"8a".repeat(32)}`;
const CHALLENGE = webAuthnChallenge(TEXT);
const AUTH_DATA = ccc.bytesConcat(sha256(new TextEncoder().encode("testnet.joyid.dev")), [0x05, 0, 0, 0, 0]);
const privateKey = p256.utils.randomSecretKey();
const publicKey = p256.getPublicKey(privateKey, false).slice(1);

function assertion(clientData: string, authData = AUTH_DATA): WebAuthnAssertion {
  const clientDataJson = new TextEncoder().encode(clientData);
  const rs = p256.sign(ccc.bytesConcat(authData, sha256(clientDataJson)), privateKey);
  return { publicKey, rs, authData, clientDataJson };
}

const browser = (challenge: string) =>
  `{"type":"webauthn.get","challenge":"${challenge}","origin":"https://testnet.joyid.dev","crossOrigin":false,"other_keys_can_be_added_here":"do not compare clientDataJSON against a template. See https://goo.gl/yabPex"}`;

test("the challenge is base64url of the text's UTF-8 bytes, as JoyID's sign-message page makes it", () => {
  assert.equal(webAuthnChallenge("Sign this for me"), "U2lnbiB0aGlzIGZvciBtZQ");
  assert.equal(CHALLENGE.length, 111);
});

test("verifies a real JoyID testnet assertion (iany.me), with its high s", () => {
  const signature = JSON.stringify({
    alg: -7,
    signature: "MEUCICF25qdO6nLreEoBHnyaw-9R6XFHbIu-NwsAI53t016qAiEAgmhlwTEMxoWxKj79R1rUkB_6nrhJfws82DqHkY_HnqQ",
    message: "K4sF4fAwPvuJj-TW3mARmMenuGSrvmohxzsueH4YfFIFAAAAAHsidHlwZSI6IndlYmF1dGhuLmdldCIsImNoYWxsZW5nZSI6IlUybG5iaUIwYUdseklHWnZjaUJ0WlEiLCJvcmlnaW4iOiJodHRwczovL3Rlc3RuZXQuam95aWQuZGV2IiwiY3Jvc3NPcmlnaW4iOmZhbHNlLCJvdGhlcl9rZXlzX2Nhbl9iZV9hZGRlZF9oZXJlIjoiZG8gbm90IGNvbXBhcmUgY2xpZW50RGF0YUpTT04gYWdhaW5zdCBhIHRlbXBsYXRlLiBTZWUgaHR0cHM6Ly9nb28uZ2wveWFiUGV4In0",
  });
  const key = "0x3538dfd53ad93d2e0a6e7f470295dcd71057d825e1f87229e5afe2a906aa7cfc099fdfa04442dac33548b6988af8af58d2052529088f7b73ef00800f7fbcddb3";
  const real = parseJoyIdSignature(signature, key);
  assert.equal(real.authData.length, 37);
  assert.ok(verifyWebAuthn(real, "Sign this for me"));
  assert.ok(!verifyWebAuthn(real, "Sign this for you"));
});

test("accepts this transaction's assertion and refuses everything the on-chain verifier refuses", () => {
  assert.ok(verifyWebAuthn(assertion(browser(CHALLENGE)), TEXT));
  assert.ok(verifyWebAuthn(assertion(`{ "challenge" : "${CHALLENGE}", "type":"webauthn.get" }`), TEXT));
  const refused = (clientData: string, reason: string) => assert.ok(!verifyWebAuthn(assertion(clientData), TEXT), reason);
  refused(browser(webAuthnChallenge(`CKB transaction: 0x${"8b".repeat(32)}`)), "another transaction");
  refused(`{"type":"webauthn.get","challenge":"x","origin":"${CHALLENGE}"}`, "challenge in another field");
  refused(`{"type":"webauthn.get","challenge":"x","origin":"\\",\\"challenge\\":\\"${CHALLENGE}\\""}`, "challenge smuggled in a string");
  refused(`{"type":"webauthn.get","x":{"challenge":"${CHALLENGE}"}}`, "challenge in a nested object");
  refused(`{"type":"webauthn.get","challenge":"x","challenge":"${CHALLENGE}"}`, "duplicate key");
  refused(`{"type":"webauthn.get","challenge":"${CHALLENGE}","challenge":"x"}`, "duplicate key, right one first");
  refused(`{"type":"webauthn.get","challenge":"x","chall\\u0065nge":"${CHALLENGE}"}`, "duplicate escaped key");
  refused(`{"type":"webauthn.create","challenge":"${CHALLENGE}"}`, "wrong type");
  refused(`{"challenge":"${CHALLENGE}"}`, "no type");
  refused(`${browser(CHALLENGE)} `, "trailing whitespace");
  refused(`${browser(CHALLENGE)}x`, "trailing garbage");
  refused(browser(CHALLENGE).slice(0, -1), "truncated");
  refused(`{"type":"webauthn.get","challenge":"${CHALLENGE}","n":01}`, "bad number");
  refused(`{"type":"webauthn.get","challenge":"${CHALLENGE}","x":${"[".repeat(12)}1${"]".repeat(12)}}`, "too deep");
  // Without user presence, or too short.
  assert.ok(!verifyWebAuthn(assertion(browser(CHALLENGE), ccc.bytesConcat(AUTH_DATA.slice(0, 32), [0x04, 0, 0, 0, 0])), TEXT));
  assert.ok(!verifyWebAuthn(assertion(browser(CHALLENGE), AUTH_DATA.slice(0, 36)), TEXT));
  // Tampered after signing.
  const good = assertion(browser(CHALLENGE));
  assert.ok(!verifyWebAuthn({ ...good, authData: ccc.bytesConcat(AUTH_DATA.slice(0, 36), [1]) }, TEXT));
  assert.ok(!verifyWebAuthn({ ...good, publicKey: p256.getPublicKey(p256.utils.randomSecretKey(), false).slice(1) }, TEXT));
  assert.ok(clientDataMatches(new TextEncoder().encode(browser(CHALLENGE)), CHALLENGE));
  assert.ok(!clientDataMatches(Uint8Array.from([0x7b, 0xff, 0x7d]), CHALLENGE), "not UTF-8");
});

test("reads CCC's JoyID signature JSON and lays out the verifier's blob", () => {
  const clientData = new TextEncoder().encode(browser(CHALLENGE));
  const der = p256.sign(ccc.bytesConcat(AUTH_DATA, sha256(clientData)), privateKey, { format: "der" });
  const parsed = parseJoyIdSignature(JSON.stringify({ alg: -7, signature: base64url(der), message: base64url(ccc.bytesConcat(AUTH_DATA, clientData)) }), publicKey);
  assert.ok(verifyWebAuthn(parsed, TEXT));
  const blob = webAuthnSignatureBlob(parsed, 768, 0);
  assert.equal(blob.length, 768);
  // Version 2, then the network byte that picks the approval text's address prefix.
  assert.equal(blob[0], 2);
  assert.equal(blob[1], 0);
  assert.equal(webAuthnSignatureBlob(parsed, 768, 1)[1], 1);
  assert.deepEqual(blob.slice(2, 66), publicKey);
  assert.deepEqual(blob.slice(66, 130), parsed.rs);
  assert.equal(blob[130] | (blob[131] << 8), 37);
  const clientAt = 132 + 37;
  assert.equal(blob[clientAt] | (blob[clientAt + 1] << 8), clientData.length);
  assert.deepEqual(blob.slice(clientAt + 2, clientAt + 2 + clientData.length), clientData);
  assert.ok(blob.slice(clientAt + 2 + clientData.length).every((byte) => byte === 0));
  assert.throws(() => webAuthnSignatureBlob(parsed, 200, 0), /doesn't fit/);
  assert.throws(() => webAuthnSignatureBlob(parsed, 1025, 0), /can't exceed 1024/);
  assert.throws(() => parseJoyIdSignature(JSON.stringify({ alg: -257, signature: "", message: "" }), publicKey), /not a passkey signature/);
});

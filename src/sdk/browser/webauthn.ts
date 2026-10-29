import * as ccc from "@ckb-ccc/core";
import { p256 } from "@noble/curves/nist.js";
import { sha256 } from "@noble/hashes/sha2.js";

/**
 * JoyID passkey (WebAuthn, P-256) assertions, checked the way KeyWay's on-chain verifier
 * (contracts/joyid-webauthn) checks them, so a signature the server accepts is one the chain accepts.
 */
export type WebAuthnAssertion = {
  /** 64-byte uncompressed public key X ‖ Y. */
  publicKey: Uint8Array;
  /** 64-byte r ‖ s. */
  rs: Uint8Array;
  authData: Uint8Array;
  clientDataJson: Uint8Array;
};

const JOYID_ES256 = -7;
/** JoyID's sign-message result splits its message after a 37-byte authenticatorData. */
const AUTH_DATA_LENGTH = 37;
const FLAG_USER_PRESENT = 0x01;
const MAX_KEYS = 32;
const MAX_DEPTH = 8;
/** The verifier keeps top-level keys in 256-byte buffers. */
const MAX_KEY = 256;
/** Omnilock reads at most 1024 signature bytes. */
export const MAX_WEBAUTHN_SIGNATURE = 1024;
const BLOB_VERSION = 1;

const base64url = (bytes: Uint8Array) => {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
};

function fromBase64url(text: unknown): Uint8Array {
  if (typeof text !== "string" || !/^[A-Za-z0-9_-]*$/.test(text)) throw new Error("not base64url");
  const binary = atob(text.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (text.length % 4)) % 4));
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

/** What the passkey signs as its challenge for a text: the text's UTF-8 bytes, as JoyID's sign-message page does. */
export function webAuthnChallenge(text: string): string {
  return base64url(new TextEncoder().encode(text));
}

/**
 * Reads what CCC's JoyID signer returns from `signMessageRaw(text)` / `signMessage(text).signature`:
 * JSON `{ signature: base64url(DER r, s), alg: -7, message: base64url(authenticatorData ‖ clientDataJSON) }`.
 */
export function parseJoyIdSignature(signatureJson: string, publicKey: ccc.HexLike): WebAuthnAssertion {
  const signed = JSON.parse(signatureJson) as { signature?: unknown; alg?: unknown; message?: unknown };
  if (signed.alg !== JOYID_ES256) throw new Error("not a passkey signature");
  const message = fromBase64url(signed.message);
  if (message.length <= AUTH_DATA_LENGTH) throw new Error("the assertion is too short");
  const rs = p256.Signature.fromBytes(fromBase64url(signed.signature), "der").toBytes("compact");
  const key = ccc.bytesFrom(publicKey);
  if (key.length !== 64) throw new Error("a passkey public key is 64 bytes");
  return { publicKey: key, rs, authData: message.slice(0, AUTH_DATA_LENGTH), clientDataJson: message.slice(AUTH_DATA_LENGTH) };
}

/**
 * Whether the assertion is the passkey's signature over `challengeText`: authenticatorData of at least 37
 * bytes with user presence, a clientDataJSON whose top-level type is "webauthn.get" and whose top-level
 * challenge is the text's, unique keys, and the P-256 signature over sha256(authData ‖ sha256(clientDataJSON)).
 */
export function verifyWebAuthn(assertion: WebAuthnAssertion, challengeText: string): boolean {
  const { publicKey, rs, authData, clientDataJson } = assertion;
  if (publicKey.length !== 64 || rs.length !== 64 || authData.length < AUTH_DATA_LENGTH) return false;
  if ((authData[32] & FLAG_USER_PRESENT) === 0) return false;
  if (!clientDataMatches(clientDataJson, webAuthnChallenge(challengeText))) return false;
  try {
    return p256.verify(rs, ccc.bytesConcat(authData, sha256(clientDataJson)), ccc.bytesConcat([4], publicKey), { lowS: false });
  } catch {
    return false;
  }
}

/**
 * The verifier's signature blob: version ‖ public key ‖ r ‖ s ‖ u16 LE length ‖ authenticatorData ‖ u16 LE length ‖
 * clientDataJSON, zero-padded to `slot` bytes.
 */
export function webAuthnSignatureBlob(assertion: WebAuthnAssertion, slot: number): Uint8Array {
  const { publicKey, rs, authData, clientDataJson } = assertion;
  const blob = ccc.bytesConcat([BLOB_VERSION], publicKey, rs, ccc.numLeToBytes(authData.length, 2), authData, ccc.numLeToBytes(clientDataJson.length, 2), clientDataJson);
  if (slot > MAX_WEBAUTHN_SIGNATURE) throw new Error(`A passkey signature can't exceed ${MAX_WEBAUTHN_SIGNATURE} bytes`);
  if (blob.length > slot) throw new Error("The passkey signature doesn't fit");
  return ccc.bytesConcat(blob, new Uint8Array(slot - blob.length));
}

/** The blob's length before padding. */
export function webAuthnSignatureLength(assertion: WebAuthnAssertion): number {
  return 1 + 64 + 64 + 2 + assertion.authData.length + 2 + assertion.clientDataJson.length;
}

/** The strict clientDataJSON rules of the on-chain verifier. */
export function clientDataMatches(json: Uint8Array, challenge: string): boolean {
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(json);
  } catch {
    return false;
  }
  try {
    const members = topLevelMembers(text);
    const keys = members.map(([key]) => key);
    if (new Set(keys).size !== keys.length || keys.length > MAX_KEYS) return false;
    const value = (key: string) => members.find(([name]) => name === key)?.[1];
    return value("type") === "webauthn.get" && value("challenge") === challenge;
  } catch {
    return false;
  }
}

/** The top-level object's members (string values unescaped, others undefined); throws on anything malformed. */
function topLevelMembers(text: string): Array<[string, string | undefined]> {
  let at = 0;
  const fail = (): never => { throw new Error("malformed"); };
  const whitespace = () => { while (at < text.length && " \t\n\r".includes(text[at])) at++; };
  const expect = (character: string) => { if (text[at] !== character) fail(); at++; };
  const string = (): string => {
    expect("\"");
    let out = "";
    for (;;) {
      if (at >= text.length) fail();
      const character = text[at++];
      if (character === "\"") return out;
      if (character.charCodeAt(0) < 0x20) fail();
      if (character !== "\\") { out += character; continue; }
      const escape = text[at++];
      const simple: Record<string, string> = { "\"": "\"", "\\": "\\", "/": "/", b: "\b", f: "\f", n: "\n", r: "\r", t: "\t" };
      if (escape in simple) { out += simple[escape]; continue; }
      if (escape !== "u") fail();
      const unit = () => { const hex = text.slice(at, at + 4); if (!/^[0-9a-fA-F]{4}$/.test(hex)) fail(); at += 4; return parseInt(hex, 16); };
      const code = unit();
      if (code >= 0xdc00 && code < 0xe000) fail();
      if (code >= 0xd800 && code < 0xdc00) {
        expect("\\");
        expect("u");
        const low = unit();
        if (low < 0xdc00 || low >= 0xe000) fail();
        out += String.fromCharCode(code, low);
      } else {
        out += String.fromCharCode(code);
      }
    }
  };
  const value = (depth: number): void => {
    if (depth > MAX_DEPTH) fail();
    const character = text[at];
    if (character === "\"") { string(); return; }
    if (character === "{" || character === "[") { container(character === "{" ? "}" : "]", depth); return; }
    for (const word of ["true", "false", "null"]) if (text.startsWith(word, at)) { at += word.length; return; }
    const number = /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/.exec(text.slice(at));
    if (!number || number[0].length === 0) fail();
    at += number![0].length;
  };
  const container = (close: string, depth: number) => {
    const object = close === "}";
    at++;
    whitespace();
    if (text[at] === close) { at++; return; }
    for (;;) {
      whitespace();
      if (object) { string(); whitespace(); expect(":"); whitespace(); }
      value(depth + 1);
      whitespace();
      const next = text[at++];
      if (next === ",") continue;
      if (next === close) return;
      fail();
    }
  };
  const members: Array<[string, string | undefined]> = [];
  expect("{");
  whitespace();
  if (text[at] === "}") {
    at++;
  } else {
    for (;;) {
      whitespace();
      const key = string();
      if (new TextEncoder().encode(key).length > MAX_KEY) fail();
      whitespace();
      expect(":");
      whitespace();
      if (text[at] === "\"") {
        members.push([key, string()]);
      } else {
        value(0);
        members.push([key, undefined]);
      }
      whitespace();
      const next = text[at++];
      if (next === ",") continue;
      if (next === "}") break;
      fail();
    }
  }
  if (at !== text.length) fail();
  return members;
}

// Audit (audit/omnilock-fable-5-1): the server accepts a JoyID ownership proof with the TypeScript clientDataJSON
// rules (src/sdk/browser/webauthn.ts) while the chain accepts a spend with the Rust verifier
// (contracts/joyid-webauthn). If the two disagree, a backup the server accepted may not be able to spend, or the
// reverse. This file states the expected verdict for each tricky case, checks the TypeScript side, and writes the
// cases to tests/fixtures/audit-fable51-clientdata-cases.json for contracts/tests/tests/audit_fable51_parity.rs,
// which checks the Rust side against the same verdicts.
import assert from "node:assert/strict";
import { writeFileSync } from "node:fs";
import test from "node:test";
import { clientDataMatches, webAuthnChallenge } from "../src/sdk/browser/webauthn.ts";

const MSG = "8a".repeat(32);
const TEXT = `CKB transaction: 0x${MSG}`;
const C = webAuthnChallenge(TEXT);
const ok = `"type":"webauthn.get","challenge":"${C}"`;

/** `expected` is the verdict both sides should give; `expectedTs` records a known divergence of the TypeScript side. */
type Case = { name: string; clientData: string; expected: boolean; expectedTs?: boolean };
const text = (name: string, clientData: string, expected: boolean, expectedTs?: boolean): Case =>
  ({ name, clientData: Buffer.from(clientData).toString("base64"), expected, ...(expectedTs === undefined ? {} : { expectedTs }) });
const bytes = (name: string, clientData: Uint8Array, expected: boolean): Case => ({ name, clientData: Buffer.from(clientData).toString("base64"), expected });

const keys = (count: number) => Array.from({ length: count }, (_, index) => `"k${index}":${index}`).join(",");
const nested = (depth: number) => "[".repeat(depth) + "1" + "]".repeat(depth);

export const cases: Case[] = [
  text("browser canonical", `{${ok},"origin":"https://testnet.joyid.dev","crossOrigin":false,"other_keys_can_be_added_here":"do not compare clientDataJSON against a template. See https://goo.gl/yabPex"}`, true),
  text("minimal", `{${ok}}`, true),
  text("reordered", `{"challenge":"${C}","origin":"x","type":"webauthn.get"}`, true),
  text("whitespace everywhere", ` \t\r\n{ \n"type" : "webauthn.get" ,\t"challenge"\n:\n"${C}" , "a" : [ 1 , 2 ] }\n`, false),
  text("whitespace inside only", `{ \n"type" : "webauthn.get" ,\t"challenge"\n:\n"${C}" , "a" : [ 1 , 2 ] }`, true),
  text("empty object", "{}", false),
  text("array at top", `[{${ok}}]`, false),
  text("trailing garbage", `{${ok}} `, false),
  text("trailing garbage 2", `{${ok}}{}`, false),
  // Finding (fixed): TextDecoder stripped a leading BOM (ignoreBOM defaulted to false) while Rust's from_utf8
  // keeps it, so the server accepted a clientDataJSON the chain refuses. The server now decodes with
  // ignoreBOM: true and refuses it too.
  text("leading BOM", `\ufeff{${ok}}`, false),
  text("duplicate type", `{"type":"webauthn.create",${ok}}`, false),
  text("duplicate challenge, second right", `{"challenge":"AAAA",${ok}}`, false),
  text("escaped key equals type", `{"ty\\u0070e":"webauthn.get","challenge":"${C}"}`, true),
  text("escaped key duplicate", `{"type":"webauthn.get","typ\\u0065":"webauthn.get","challenge":"${C}"}`, false),
  text("escaped value", `{"type":"webauthn\\u002eget","challenge":"${C}"}`, true),
  text("escaped slash in value", `{"type":"webauthn.get","challenge":"${C}","origin":"https:\\/\\/x"}`, true),
  text("challenge nested only", `{"type":"webauthn.get","extra":{"challenge":"${C}"}}`, false),
  text("challenge nested and top", `{"type":"webauthn.get","extra":{"challenge":"zzz"},"challenge":"${C}"}`, true),
  text("type not a string", `{"type":1,"challenge":"${C}"}`, false),
  text("challenge not a string", `{"type":"webauthn.get","challenge":["${C}"]}`, false),
  text("type with trailing space", `{"type":"webauthn.get ","challenge":"${C}"}`, false),
  text("key with trailing space", `{"type":"webauthn.get","challenge ":"${C}"}`, false),
  text("challenge padded", `{"type":"webauthn.get","challenge":"${C}="}`, false),
  text("challenge for uppercase hex", `{"type":"webauthn.get","challenge":"${webAuthnChallenge(`CKB transaction: 0x${MSG.toUpperCase()}`)}"}`, false),
  text("challenge standard base64", `{"type":"webauthn.get","challenge":"${Buffer.from(TEXT).toString("base64")}"}`, Buffer.from(TEXT).toString("base64") === C),
  text("32 keys", `{${ok},${keys(30)}}`, true),
  text("33 keys", `{${ok},${keys(31)}}`, false),
  text("depth 8", `{${ok},"n":${nested(8)}}`, true),
  text("depth 9", `{${ok},"n":${nested(9)}}`, false),
  text("key 256 bytes", `{${ok},"${"k".repeat(256)}":1}`, true),
  text("key 257 bytes", `{${ok},"${"k".repeat(257)}":1}`, false),
  text("key 256 bytes after escape", `{${ok},"${"k".repeat(255)}\\u006b":1}`, true),
  text("key 256 bytes but 4-byte char", `{${ok},"${"k".repeat(253)}\\ud83d\\ude00":1}`, false),
  text("long unrelated value", `{${ok},"v":"${"v".repeat(2000)}"}`, true),
  text("long type value", `{"type":"${"webauthn.get".padEnd(300, "x")}","challenge":"${C}"}`, false),
  text("raw control char", `{${ok},"v":"a\u0001b"}`, false),
  text("raw tab in string", `{${ok},"v":"a\tb"}`, false),
  text("raw unicode", `{${ok},"v":"héllo ✓ 😀"}`, true),
  text("escaped nul", `{${ok},"v":"\\u0000"}`, true),
  text("escaped nul in key", `{${ok},"\\u0000":1}`, true),
  text("lone high surrogate", `{${ok},"v":"\\ud800"}`, false),
  text("lone low surrogate", `{${ok},"v":"\\udc00"}`, false),
  text("surrogate pair", `{${ok},"v":"\\ud83d\\ude00"}`, true),
  text("high surrogate then non-escape", `{${ok},"v":"\\ud83dx"}`, false),
  text("uppercase hex escape", `{${ok},"v":"\\u004A\\u004a"}`, true),
  text("bad escape", `{${ok},"v":"\\x41"}`, false),
  text("short unicode escape", `{${ok},"v":"\\u12"}`, false),
  text("number 1e5", `{${ok},"n":1e5}`, true),
  text("number 1E+5", `{${ok},"n":1E+5}`, true),
  text("number -0.5e-3", `{${ok},"n":-0.5e-3}`, true),
  text("number leading zero", `{${ok},"n":01}`, false),
  text("number trailing dot", `{${ok},"n":1.}`, false),
  text("number leading dot", `{${ok},"n":.5}`, false),
  text("number minus only", `{${ok},"n":-}`, false),
  text("number plus", `{${ok},"n":+1}`, false),
  text("literal true", `{${ok},"n":true}`, true),
  text("literal tru", `{${ok},"n":tru}`, false),
  text("literal nulll", `{${ok},"n":nulll}`, false),
  text("literal True", `{${ok},"n":True}`, false),
  text("trailing comma", `{${ok},}`, false),
  text("trailing comma nested", `{${ok},"a":[1,]}`, false),
  text("missing colon", `{${ok},"a" 1}`, false),
  text("unquoted key", `{${ok},a:1}`, false),
  text("single quotes", `{${ok},'a':1}`, false),
  text("empty key", `{${ok},"":1}`, true),
  text("empty nested object and array", `{${ok},"a":{},"b":[]}`, true),
  text("nested duplicate keys allowed", `{${ok},"a":{"x":1,"x":2}}`, true),
  text("unterminated string", `{${ok},"v":"abc`, false),
  text("unterminated object", `{${ok}`, false),
  bytes("invalid utf-8", Buffer.concat([Buffer.from(`{${ok},"v":"`), Buffer.from([0xff, 0xfe]), Buffer.from(`"}`)]), false),
  bytes("overlong utf-8", Buffer.concat([Buffer.from(`{${ok},"v":"`), Buffer.from([0xc0, 0xaf]), Buffer.from(`"}`)]), false),
  bytes("utf-8 encoded surrogate", Buffer.concat([Buffer.from(`{${ok},"v":"`), Buffer.from([0xed, 0xa0, 0x80]), Buffer.from(`"}`)]), false),
  bytes("nul byte raw", Buffer.concat([Buffer.from(`{${ok},"v":"`), Buffer.from([0x00]), Buffer.from(`"}`)]), false),
];

test("no case records a divergence between the TypeScript and Rust rules", () => {
  assert.deepEqual(cases.filter(({ expectedTs }) => expectedTs !== undefined).map(({ name }) => name), []);
});

test("the TypeScript clientDataJSON rules give the expected verdict for every case", () => {
  const failures = cases.filter(({ clientData, expected, expectedTs }) => clientDataMatches(Buffer.from(clientData, "base64"), C) !== (expectedTs ?? expected)).map(({ name }) => name);
  assert.deepEqual(failures, []);
});

test("writes the cases for the Rust verifier's parity test", () => {
  writeFileSync(new URL("./fixtures/audit-fable51-clientdata-cases.json", import.meta.url), JSON.stringify({ msg: MSG, challenge: C, cases }, null, 1) + "\n");
});

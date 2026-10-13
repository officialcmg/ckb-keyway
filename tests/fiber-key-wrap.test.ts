import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { createFiberKeyRecipient } from "../src/sdk/browser/fiber-key-wrap.ts";

const pkpId = `0x${"ab".repeat(20)}`;
const deviceIdHash = "cd".repeat(32);

async function action(name: string, decrypted?: string) {
  const source = await readFile(new URL(`../lit-actions/${name}.js`, import.meta.url), "utf8");
  const calls: Array<{ op: string; args: Record<string, string> }> = [];
  const Lit = { Actions: {
    Decrypt: async (args: Record<string, string>) => { calls.push({ op: "Decrypt", args }); return decrypted; },
    Encrypt: async (args: Record<string, string>) => { calls.push({ op: "Encrypt", args }); return `sealed:${args.message.length}`; },
  } };
  const main = new Function("Lit", `${source}\nreturn main;`)(Lit) as (params: Record<string, unknown>) => Promise<Record<string, string>>;
  return { main, calls };
}

test("Lit re-encrypts the Fiber key to the browser's one-time key, and only that browser can open it", async () => {
  const fiberKey = crypto.getRandomValues(new Uint8Array(32));
  const { main, calls } = await action("wrap-fiber-key", Buffer.from(fiberKey).toString("base64"));
  const recipient = await createFiberKeyRecipient();
  const bundle = await main({ pkpId, ciphertext: "stored-ciphertext", recipientPublicKey: recipient.publicKey, deviceIdHash });
  assert.deepEqual(Object.keys(bundle).sort(), ["ct", "epk", "iv", "v"]);
  assert.equal(JSON.stringify(bundle).includes(Buffer.from(fiberKey).toString("base64")), false, "no plaintext in the output");
  assert.deepEqual(await recipient.unwrap(bundle, { pkpId, deviceIdHash }), fiberKey);
  assert.deepEqual(calls, [{ op: "Decrypt", args: { pkpId, ciphertext: "stored-ciphertext" } }]);

  // Bound to the wallet, the device and the recipient: anything else fails to open.
  await assert.rejects(() => recipient.unwrap(bundle, { pkpId, deviceIdHash: "ef".repeat(32) }));
  await assert.rejects(() => recipient.unwrap(bundle, { pkpId: `0x${"12".repeat(20)}`, deviceIdHash }));
  const other = await createFiberKeyRecipient();
  await assert.rejects(() => other.unwrap(bundle, { pkpId, deviceIdHash }));
});

test("the wrap Action checks every input before it decrypts anything", async () => {
  const { main, calls } = await action("wrap-fiber-key", "x");
  const recipient = await createFiberKeyRecipient();
  for (const params of [
    { pkpId: "nope", ciphertext: "c", recipientPublicKey: recipient.publicKey, deviceIdHash },
    { pkpId, ciphertext: "c", recipientPublicKey: "A".repeat(87), deviceIdHash },
    { pkpId, ciphertext: "c", recipientPublicKey: recipient.publicKey, deviceIdHash: "short" },
  ]) await assert.rejects(() => main(params));
  assert.equal(calls.length, 0);
});

test("the generate Action makes the key inside Lit and returns only ciphertext", async () => {
  const { main, calls } = await action("generate-fiber-key");
  const result = await main({ pkpId });
  assert.deepEqual(Object.keys(result), ["ciphertext"]);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].op, "Encrypt");
  assert.match(calls[0].args.message, /^[A-Za-z0-9+/]{43}=$/);
});

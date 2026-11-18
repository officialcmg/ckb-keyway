import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import test from "node:test";
import { addPkpToGroup, createPkp, findGroupId } from "../src/server/chipotle.ts";

const BASE = "https://api.chipotle.litprotocol.com/core/v1";
// What the API server's provisioning key is used for. The key Lit issued for it is scoped to the same: it can
// create wallets and add them to the "CKB Keyway" group, and can't register Actions (see research/lit-policy).
const ALLOWED = ["/create_wallet", "/list_groups", "/add_pkp_to_group"];

test("the provisioning key is sent only to create a wallet, list groups and add a wallet to a group", async (t) => {
  const key = "test-provisioning-key";
  const seen: string[] = [];
  const original = globalThis.fetch;
  t.after(() => { globalThis.fetch = original; });
  globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit) => {
    const url = new URL(String(input));
    assert.equal(new Headers(init?.headers).get("X-Api-Key"), key);
    assert.equal(url.origin + url.pathname.slice(0, "/core/v1".length), BASE);
    seen.push(url.pathname.slice("/core/v1".length));
    const body = url.pathname.endsWith("/create_wallet") ? { wallet_address: `0x${"ab".repeat(20)}` }
      : url.pathname.endsWith("/list_groups") ? [{ name: "CKB Keyway", id: "1" }] : {};
    return Response.json(body);
  }) as typeof fetch;
  await createPkp(key);
  await addPkpToGroup(key, await findGroupId(key, "CKB Keyway"), `0x${"ab".repeat(20)}`);
  assert.deepEqual(seen, ALLOWED);
});

test("no other server code reads the provisioning key or calls another Lit management endpoint", () => {
  const files = (dir: string): string[] => readdirSync(dir, { withFileTypes: true }).flatMap((entry) =>
    entry.isDirectory() ? files(join(dir, entry.name)) : /\.(ts|tsx|mjs|js)$/.test(entry.name) ? [join(dir, entry.name)] : []);
  const sources = [...files("src"), ...files("managed-host").filter((file) => !file.includes("node_modules"))];
  // Only wallet setup reads the key, and it hands it to nothing but the three calls above.
  const readers = sources.filter((file) => readFileSync(file, "utf8").includes("LIT_PROVISIONING_API_KEY"));
  assert.deepEqual(readers, [join("src", "server", "bootstrap.ts")]);
  const bootstrap = readFileSync(readers[0], "utf8");
  const uses = bootstrap.split("\n").filter((line) => /provisioningApiKey|LIT_PROVISIONING_API_KEY/.test(line)).map((line) => line.trim());
  assert.deepEqual(uses, [
    'return createPkp(requiredEnv("LIT_PROVISIONING_API_KEY"));',
    'const provisioningApiKey = requiredEnv("LIT_PROVISIONING_API_KEY");',
    'await addPkpToGroup(provisioningApiKey, await findGroupId(provisioningApiKey, "CKB Keyway"), litPkpId);',
  ]);
  // The management client itself knows no other endpoint, so nothing can start using more of what a key allows
  // without this test changing.
  const chipotle = readFileSync(join("src", "server", "chipotle.ts"), "utf8");
  const paths = [...chipotle.matchAll(/"(\/[a-z_]+)(?:\?[^"]*)?"/g)].map((match) => match[1]);
  assert.deepEqual(paths, ALLOWED);
});

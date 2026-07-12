import { readFile } from "node:fs/promises";
import path from "node:path";

export type LitActionName = "sign-ckb-digest" | "encrypt-fiber-key" | "decrypt-fiber-key";

const cache = new Map<LitActionName, Promise<string>>();

export function loadLitAction(name: LitActionName): Promise<string> {
  const existing = cache.get(name);
  if (existing) return existing;
  const source = readFile(path.join(process.cwd(), "lit-actions", `${name}.js`), "utf8");
  cache.set(name, source);
  return source;
}

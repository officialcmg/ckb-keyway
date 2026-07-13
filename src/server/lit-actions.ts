import { readFile } from "node:fs/promises";

export type LitActionName = "sign-ckb-digest" | "encrypt-fiber-key" | "decrypt-fiber-key";

const cache = new Map<LitActionName, Promise<string>>();

export function loadLitAction(name: LitActionName): Promise<string> {
  const existing = cache.get(name);
  if (existing) return existing;
  const source = readFile(new URL(`../../lit-actions/${name}.js`, import.meta.url), "utf8");
  cache.set(name, source);
  return source;
}

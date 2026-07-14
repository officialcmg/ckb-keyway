import { cp, mkdir, readFile, rm, writeFile } from "node:fs/promises";

const root = new URL("../", import.meta.url);
const output = new URL("../dist/package/", import.meta.url);
const repositoryPackage = JSON.parse(await readFile(new URL("package.json", root), "utf8"));
const publicPackage = JSON.parse(await readFile(new URL("package.sdk.json", root), "utf8"));

await rm(output, { recursive: true, force: true });
await mkdir(new URL("dist/", output), { recursive: true });
await Promise.all([
  cp(new URL("dist/react/", root), new URL("dist/react/", output), { recursive: true }),
  cp(new URL("README.md", root), new URL("README.md", output)),
  cp(new URL("LICENSE", root), new URL("LICENSE", output)),
  writeFile(
    new URL("package.json", output),
    `${JSON.stringify({ ...publicPackage, version: repositoryPackage.version }, null, 2)}\n`,
  ),
]);

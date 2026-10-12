import { createHash } from "node:crypto";

const BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/**
 * The IPFS CIDv0 that Lit derives for Action source code: a single-chunk UnixFS file in a dag-pb node,
 * hashed with sha2-256 and encoded in base58btc. Sources up to 256 KiB fit in one chunk.
 */
export function litActionCid(code: string): string {
  const content = new TextEncoder().encode(code);
  if (content.length > 256 * 1024) throw new Error("Lit Action source exceeds one IPFS chunk");
  const unixfs = concat([0x08, 0x02], field(2, content), [0x18], varint(content.length));
  const node = field(1, unixfs);
  const digest = createHash("sha256").update(node).digest();
  return base58(concat([0x12, 0x20], digest));
}

function field(tag: number, bytes: Uint8Array): Uint8Array {
  return concat([(tag << 3) | 2], varint(bytes.length), bytes);
}

function varint(value: number): number[] {
  const bytes: number[] = [];
  while (value >= 0x80) {
    bytes.push((value & 0x7f) | 0x80);
    value >>>= 7;
  }
  bytes.push(value);
  return bytes;
}

function concat(...parts: Array<ArrayLike<number>>): Uint8Array {
  const out = new Uint8Array(parts.reduce((total, part) => total + part.length, 0));
  let offset = 0;
  for (const part of parts) { out.set(part, offset); offset += part.length; }
  return out;
}

function base58(bytes: Uint8Array): string {
  let value = BigInt(`0x${Buffer.from(bytes).toString("hex")}`);
  let out = "";
  while (value > 0n) { out = BASE58[Number(value % 58n)] + out; value /= 58n; }
  for (const byte of bytes) { if (byte !== 0) break; out = `1${out}`; }
  return out;
}

import { lookup } from "node:dns/promises";
import { isIP } from "node:net";

/**
 * Hosted nodes dial peers from inside KeyWay's network, so an app could otherwise point them at internal
 * services. Only public addresses are allowed: private, loopback, link-local and shared ranges, and internal
 * host names, are refused, including host names that resolve to them.
 */
export async function assertPublicPeerAddress(multiaddr: string, resolve: (host: string) => Promise<string[]> = resolveAll): Promise<void> {
  const [, kind, host] = multiaddr.split("/");
  if (!host) throw new Error("Peer address is invalid");
  if (kind === "ip4" || kind === "ip6") {
    if (isPrivateIp(host)) throw new Error("Peer addresses must be public");
    return;
  }
  const name = host.toLowerCase();
  if (name === "localhost" || /\.(internal|local|localhost|lan|home|corp)$/.test(name) || !name.includes(".")) {
    throw new Error("Peer addresses must be public");
  }
  const addresses = await resolve(name).catch(() => { throw new Error("Peer host name doesn't resolve"); });
  if (addresses.length === 0 || addresses.some(isPrivateIp)) throw new Error("Peer addresses must be public");
}

/**
 * Checks a peer address and returns the one a hosted node should dial: a host name becomes the IP that was
 * checked, so the node can't resolve it again to a different, internal one.
 */
export async function pinPublicPeerAddress(multiaddr: string, resolve: (host: string) => Promise<string[]> = resolveAll): Promise<string> {
  const [, kind, , ...rest] = multiaddr.split("/");
  const named = kind !== "ip4" && kind !== "ip6";
  // A secure WebSocket needs the host name for its certificate, so it can't be pinned to an IP.
  if (named && /\/(wss|tls)(\/|$)/.test(multiaddr)) {
    throw new Error("A hosted node can't dial a secure WebSocket peer by host name; pass the peer's TCP address");
  }
  let answers: string[] = [];
  await assertPublicPeerAddress(multiaddr, async (host) => (answers = await resolve(host)));
  if (!named) return multiaddr;
  const ip = answers.find((address) => kind === "dns4" ? isIP(address) === 4 : kind === "dns6" ? isIP(address) === 6 : true);
  if (!ip) throw new Error("Peer host name doesn't resolve");
  return ["", isIP(ip) === 6 ? "ip6" : "ip4", ip, ...rest].join("/");
}

async function resolveAll(host: string): Promise<string[]> {
  return (await lookup(host, { all: true })).map(({ address }) => address);
}

export function isPrivateIp(address: string): boolean {
  const version = isIP(address);
  if (version === 4) {
    const [a, b] = address.split(".").map(Number);
    return a === 0 || a === 10 || a === 127 || (a === 100 && b >= 64 && b <= 127) || (a === 169 && b === 254)
      || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || a >= 224;
  }
  if (version === 6) {
    // Compared as bytes: one address has many spellings (::ffff:7f00:1 is 127.0.0.1, 0::1 is ::1).
    const b = ipv6Bytes(address);
    const zero = (from: number, to: number) => b.slice(from, to).every((byte) => byte === 0);
    const ip4 = (at: number) => b.slice(at, at + 4).join(".");
    if (zero(0, 10) && b[10] === 0xff && b[11] === 0xff) return isPrivateIp(ip4(12)); // IPv4-mapped
    if (zero(0, 12)) return true; // unspecified, loopback and IPv4-compatible
    if (b[0] === 0x00 && b[1] === 0x64 && b[2] === 0xff && b[3] === 0x9b) return zero(4, 12) ? isPrivateIp(ip4(12)) : true; // NAT64
    if (b[0] === 0x20 && b[1] === 0x02) return isPrivateIp(ip4(2)); // 6to4
    if (b[0] === 0x20 && b[1] === 0x01 && (zero(2, 4) || (b[2] === 0x0d && b[3] === 0xb8))) return true; // Teredo, documentation
    if (b[0] === 0x01 && zero(1, 8)) return true; // discard
    return (b[0] & 0xfe) === 0xfc || (b[0] === 0xfe && b[1] >= 0x80) || b[0] === 0xff; // unique local, link and site local, multicast
  }
  return true;
}

/** The 16 bytes of an address isIP() accepted as IPv6. */
function ipv6Bytes(address: string): number[] {
  let text = address.toLowerCase().split("%")[0];
  let ip4: number[] = [];
  const dotted = /(\d+\.\d+\.\d+\.\d+)$/.exec(text);
  if (dotted) {
    ip4 = dotted[1].split(".").map(Number);
    text = `${text.slice(0, -dotted[1].length)}0:0`;
  }
  const [head, tail] = text.includes("::") ? text.split("::") : [text, undefined];
  const left = head ? head.split(":") : [];
  const right = tail ? tail.split(":") : [];
  const groups = [...left, ...Array(8 - left.length - right.length).fill("0"), ...right].map((group) => parseInt(group, 16));
  const bytes = groups.flatMap((group) => [group >> 8, group & 0xff]);
  if (ip4.length) bytes.splice(12, 4, ...ip4);
  return bytes;
}

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
    const lower = address.toLowerCase();
    if (lower === "::" || lower === "::1") return true;
    const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/.exec(lower);
    if (mapped) return isPrivateIp(mapped[1]);
    return /^(fc|fd|fe8|fe9|fea|feb|ff)/.test(lower);
  }
  return true;
}

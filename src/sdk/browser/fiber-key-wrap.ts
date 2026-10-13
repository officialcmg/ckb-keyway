/**
 * The browser's half of the Fiber key wrap. The browser makes a one-time P-256 key that can't be exported
 * and sends only its public half; Lit decrypts the Fiber key inside its secure enclave and re-encrypts it to
 * that key (lit-actions/wrap-fiber-key.js). KeyWay's server relays ciphertext it can't open.
 */
const VERSION = "ckb-keyway/fiber-key-wrap/v1";

export type WrappedFiberKey = { v: 1; epk: string; iv: string; ct: string };

export async function createFiberKeyRecipient() {
  const keyPair = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"]);
  const publicKeyBytes = new Uint8Array(await crypto.subtle.exportKey("raw", keyPair.publicKey));
  const publicKey = toBase64Url(publicKeyBytes);

  /** Opens the bundle Lit returned, which must be bound to this wallet, this device and this one-time key. */
  async function unwrap(bundle: unknown, binding: { pkpId: string; deviceIdHash: string }): Promise<Uint8Array> {
    if (!isWrapped(bundle)) throw new Error("KeyWay returned an invalid Fiber key bundle");
    const epkBytes = fromBase64Url(bundle.epk);
    if (epkBytes.length !== 65 || epkBytes[0] !== 4) throw new Error("KeyWay returned an invalid Fiber key bundle");
    const epk = await crypto.subtle.importKey("raw", epkBytes, { name: "ECDH", namedCurve: "P-256" }, false, []);
    const shared = new Uint8Array(await crypto.subtle.deriveBits({ name: "ECDH", public: epk }, keyPair.privateKey, 256));
    const salt = new Uint8Array(epkBytes.length + publicKeyBytes.length);
    salt.set(epkBytes);
    salt.set(publicKeyBytes, epkBytes.length);
    const hkdf = await crypto.subtle.importKey("raw", shared, "HKDF", false, ["deriveKey"]);
    shared.fill(0);
    const aes = await crypto.subtle.deriveKey(
      { name: "HKDF", hash: "SHA-256", salt, info: new TextEncoder().encode(VERSION) },
      hkdf,
      { name: "AES-GCM", length: 256 },
      false,
      ["decrypt"],
    );
    const additionalData = new TextEncoder().encode(`${VERSION}|${binding.pkpId.toLowerCase()}|${binding.deviceIdHash}|${publicKey}|${bundle.epk}`);
    const key = new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: fromBase64Url(bundle.iv), additionalData }, aes, fromBase64Url(bundle.ct)));
    if (key.length !== 32) {
      key.fill(0);
      throw new Error("KeyWay returned an invalid Fiber key");
    }
    return key;
  }

  return { publicKey, unwrap };
}

function isWrapped(value: unknown): value is WrappedFiberKey {
  if (!value || typeof value !== "object") return false;
  const { v, epk, iv, ct } = value as Record<string, unknown>;
  return v === 1 && [epk, iv, ct].every((part) => typeof part === "string" && /^[A-Za-z0-9_-]+$/.test(part));
}

function toBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function fromBase64Url(value: string): Uint8Array<ArrayBuffer> {
  const base64 = value.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(value.length / 4) * 4, "=");
  const binary = atob(base64);
  const bytes = new Uint8Array(new ArrayBuffer(binary.length));
  for (let index = 0; index < binary.length; index++) bytes[index] = binary.charCodeAt(index);
  return bytes;
}

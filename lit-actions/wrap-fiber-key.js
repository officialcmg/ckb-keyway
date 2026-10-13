// js_params: { pkpId, ciphertext, recipientPublicKey, deviceIdHash }
// Decrypts the user's Fiber key inside Lit and re-encrypts it to a one-time key the browser made, so the
// server relaying this only ever sees ciphertext. ECDH P-256, HKDF-SHA256 and AES-256-GCM; the browser
// rebuilds the same associated data to open it.
const VERSION = "ckb-keyway/fiber-key-wrap/v1";

function fromBase64Url(value) {
  const base64 = value.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(value.length / 4) * 4, "=");
  return Uint8Array.from(atob(base64), (char) => char.charCodeAt(0));
}

function toBase64Url(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function main({ pkpId, ciphertext, recipientPublicKey, deviceIdHash }) {
  if (typeof pkpId !== "string" || !/^0x[0-9a-fA-F]{40}$/.test(pkpId)) throw new Error("pkpId must be a 20-byte EVM address");
  if (typeof ciphertext !== "string" || ciphertext.length === 0) throw new Error("ciphertext is required");
  if (typeof deviceIdHash !== "string" || !/^[0-9a-f]{64}$/.test(deviceIdHash)) throw new Error("deviceIdHash must be 32 bytes of hex");
  if (typeof recipientPublicKey !== "string" || !/^[A-Za-z0-9_-]{87}$/.test(recipientPublicKey)) throw new Error("recipientPublicKey must be a raw P-256 key");
  const recipientBytes = fromBase64Url(recipientPublicKey);
  if (recipientBytes.length !== 65 || recipientBytes[0] !== 4) throw new Error("recipientPublicKey must be a raw P-256 key");

  // Every check happens before the key is decrypted; importing the key rejects points that aren't on the curve.
  const recipient = await crypto.subtle.importKey("raw", recipientBytes, { name: "ECDH", namedCurve: "P-256" }, false, []);
  const ephemeral = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"]);
  const epkBytes = new Uint8Array(await crypto.subtle.exportKey("raw", ephemeral.publicKey));
  const shared = new Uint8Array(await crypto.subtle.deriveBits({ name: "ECDH", public: recipient }, ephemeral.privateKey, 256));
  const salt = new Uint8Array(epkBytes.length + recipientBytes.length);
  salt.set(epkBytes);
  salt.set(recipientBytes, epkBytes.length);
  const hkdf = await crypto.subtle.importKey("raw", shared, "HKDF", false, ["deriveKey"]);
  const aes = await crypto.subtle.deriveKey({ name: "HKDF", hash: "SHA-256", salt, info: new TextEncoder().encode(VERSION) }, hkdf, { name: "AES-GCM", length: 256 }, false, ["encrypt"]);
  shared.fill(0);

  const fiberKey = await Lit.Actions.Decrypt({ pkpId, ciphertext });
  if (!/^[A-Za-z0-9+/]{43}=$/.test(fiberKey)) throw new Error("decrypted Fiber key is invalid");
  const keyBytes = Uint8Array.from(atob(fiberKey), (char) => char.charCodeAt(0));
  try {
    const epk = toBase64Url(epkBytes);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const additionalData = new TextEncoder().encode(`${VERSION}|${pkpId.toLowerCase()}|${deviceIdHash}|${recipientPublicKey}|${epk}`);
    const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData }, aes, keyBytes));
    return { v: 1, epk, iv: toBase64Url(iv), ct: toBase64Url(ct) };
  } finally {
    keyBytes.fill(0);
  }
}

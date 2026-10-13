// js_params: { pkpId }
// Creates the user's Fiber node key inside Lit and returns only its ciphertext, so no server ever holds it.
async function main({ pkpId }) {
  if (typeof pkpId !== "string" || !/^0x[0-9a-fA-F]{40}$/.test(pkpId)) {
    throw new Error("pkpId must be a 20-byte EVM address");
  }
  const key = crypto.getRandomValues(new Uint8Array(32));
  try {
    let binary = "";
    for (const byte of key) binary += String.fromCharCode(byte);
    return { ciphertext: await Lit.Actions.Encrypt({ pkpId, message: btoa(binary) }) };
  } finally {
    key.fill(0);
  }
}

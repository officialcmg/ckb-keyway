// js_params: { pkpId, ciphertext }
async function main({ pkpId, ciphertext }) {
  if (typeof pkpId !== "string" || !/^0x[0-9a-fA-F]{40}$/.test(pkpId)) {
    throw new Error("pkpId must be a 20-byte EVM address");
  }

  if (typeof ciphertext !== "string" || ciphertext.length === 0) {
    throw new Error("ciphertext is required");
  }

  const fiberKey = await Lit.Actions.Decrypt({ pkpId, ciphertext });
  if (!/^[A-Za-z0-9+/]{43}=$/.test(fiberKey)) {
    throw new Error("decrypted Fiber key is invalid");
  }

  return { fiberKey };
}

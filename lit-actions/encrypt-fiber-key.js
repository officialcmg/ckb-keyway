// js_params: { pkpId, fiberKey }
async function main({ pkpId, fiberKey }) {
  if (typeof pkpId !== "string" || !/^0x[0-9a-fA-F]{40}$/.test(pkpId)) {
    throw new Error("pkpId must be a 20-byte EVM address");
  }

  if (typeof fiberKey !== "string" || !/^[A-Za-z0-9+/]{43}=$/.test(fiberKey)) {
    throw new Error("fiberKey must be a base64-encoded 32-byte key");
  }

  return {
    ciphertext: await Lit.Actions.Encrypt({ pkpId, message: fiberKey }),
  };
}

// js_params: { pkpId, digest }
async function main({ pkpId, digest }) {
  if (typeof pkpId !== "string" || pkpId.length === 0) {
    throw new Error("pkpId is required");
  }

  if (typeof digest !== "string" || !/^0x[0-9a-fA-F]{64}$/.test(digest)) {
    throw new Error("digest must be a 0x-prefixed 32-byte hex string");
  }

  const privateKey = await Lit.Actions.getPrivateKey({ pkpId });
  const signature = new ethers.utils.SigningKey(privateKey).signDigest(digest);

  return {
    r: signature.r,
    s: signature.s,
    recoveryParam: signature.recoveryParam,
  };
}

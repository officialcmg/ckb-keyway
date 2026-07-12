import { loadLitAction } from "@/src/server/lit-actions";
import { decryptFiberKey } from "@/src/server/lit";
import { authenticateUser } from "@/src/server/stytch";
import { readWallet } from "@/src/server/user-wallet";
import { requireLease } from "@/src/server/device-lease";

export async function POST(request: Request) {
  let fiberKey: Uint8Array | undefined;
  try {
    const user = await authenticateUser(request.headers.get("authorization"));
    const body: unknown = await request.json();
    const { deviceIdHash, leaseId } = body && typeof body === "object"
      ? body as { deviceIdHash?: unknown; leaseId?: unknown }
      : {};
    if (typeof deviceIdHash !== "string") throw new Error("Device ID hash is required");
    if (typeof leaseId !== "string") throw new Error("Device lease is required");

    const wallet = readWallet(user);
    if (!wallet || wallet.status !== "ready") throw new Error("KeyWay wallet is not provisioned");
    if (wallet.primaryDeviceIdHash !== deviceIdHash) throw new Error("Fiber wallet is bound to another device");
    requireLease(user, deviceIdHash, leaseId);

    const apiKey = requiredEnv("LIT_USAGE_API_KEY");
    fiberKey = await decryptFiberKey(wallet.encryptedFiberKey, wallet.litPkpId, {
      apiKey,
      actionCid: requiredEnv("LIT_DECRYPT_ACTION_CID"),
      actionCode: await loadLitAction("decrypt-fiber-key"),
    });
    const responseBytes = fiberKey.slice();
    return new Response(responseBytes, {
      headers: {
        "Cache-Control": "no-store",
        "Content-Type": "application/octet-stream",
        "Content-Length": "32",
      },
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : "Fiber credential recovery failed";
    const unauthorized = /session/i.test(message);
    return Response.json({ error: message }, {
      status: unauthorized ? 401 : 400,
      headers: { "Cache-Control": "no-store" },
    });
  } finally {
    fiberKey?.fill(0);
  }
}

function requiredEnv(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`Missing server configuration: ${name}`);
  return value;
}

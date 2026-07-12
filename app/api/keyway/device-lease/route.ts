import { acquireLease, heartbeatLease, releaseLease } from "@/src/server/device-lease";
import { authenticateUser } from "@/src/server/stytch";
import { readWallet } from "@/src/server/user-wallet";

export async function POST(request: Request) {
  try {
    const user = await authenticateUser(request.headers.get("authorization"));
    const body: unknown = await request.json();
    if (!body || typeof body !== "object") throw new Error("Invalid lease request");
    const { operation, deviceIdHash, leaseId } = body as Record<string, unknown>;
    if (typeof operation !== "string" || typeof deviceIdHash !== "string") {
      throw new Error("Lease operation and device ID hash are required");
    }

    const wallet = readWallet(user);
    if (!wallet || wallet.status !== "ready") throw new Error("KeyWay wallet is not provisioned");
    if (wallet.primaryDeviceIdHash !== deviceIdHash) throw new Error("Fiber wallet is bound to another device");

    if (operation === "acquire") return Response.json(publicLease(await acquireLease(user, deviceIdHash)));
    if (typeof leaseId !== "string") throw new Error("Lease ID is required");
    if (operation === "heartbeat") return Response.json(publicLease(await heartbeatLease(user, deviceIdHash, leaseId)));
    if (operation === "release") {
      await releaseLease(user, deviceIdHash, leaseId);
      return new Response(null, { status: 204 });
    }
    throw new Error("Unsupported lease operation");
  } catch (error) {
    const message = error instanceof Error ? error.message : "Device lease failed";
    const unauthorized = /session|bearer/i.test(message);
    return Response.json({ error: message }, { status: unauthorized ? 401 : 400 });
  }
}

function publicLease(lease: { leaseId: string; expiresAt: string }) {
  return { leaseId: lease.leaseId, expiresAt: lease.expiresAt };
}

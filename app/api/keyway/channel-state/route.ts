import { authenticateUser } from "@/src/server/stytch";
import { markChannelOpened } from "@/src/server/user-wallet";

export async function POST(request: Request) {
  try {
    const user = await authenticateUser(request.headers.get("authorization"));
    const body: unknown = await request.json();
    const deviceIdHash = body && typeof body === "object"
      ? (body as { deviceIdHash?: unknown }).deviceIdHash
      : undefined;
    if (typeof deviceIdHash !== "string") throw new Error("Device ID hash is required");
    await markChannelOpened(user, deviceIdHash);
    return new Response(null, { status: 204 });
  } catch (error) {
    const message = error instanceof Error ? error.message : "Channel-state update failed";
    const unauthorized = /session|bearer/i.test(message);
    return Response.json({ error: message }, { status: unauthorized ? 401 : 400 });
  }
}

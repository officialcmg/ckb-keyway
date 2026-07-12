import { bootstrap } from "@/src/server/bootstrap";
import { authenticateUser } from "@/src/server/stytch";

export async function POST(request: Request) {
  try {
    const user = await authenticateUser(request.headers.get("authorization"));
    const body: unknown = await request.json();
    if (!body || typeof body !== "object") throw new Error("Invalid bootstrap request");
    const { deviceIdHash, fiberKey } = body as { deviceIdHash?: unknown; fiberKey?: unknown };
    if (typeof deviceIdHash !== "string") throw new Error("Device ID hash is required");
    if (fiberKey !== undefined && typeof fiberKey !== "string") throw new Error("Fiber key is invalid");
    return Response.json(await bootstrap(user, deviceIdHash, fiberKey));
  } catch (error) {
    const message = error instanceof Error ? error.message : "Bootstrap failed";
    const unauthorized = /session/i.test(message);
    return Response.json({ error: message }, { status: unauthorized ? 401 : 400 });
  }
}

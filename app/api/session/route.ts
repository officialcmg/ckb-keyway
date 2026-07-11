import { authenticateBearer } from "@/src/server/stytch";

export async function GET(request: Request) {
  try {
    return Response.json({ userId: await authenticateBearer(request.headers.get("authorization")) });
  } catch {
    return Response.json({ error: "Invalid or expired session" }, { status: 401 });
  }
}

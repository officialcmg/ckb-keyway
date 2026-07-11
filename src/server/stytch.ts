import * as stytch from "stytch";

let client: stytch.Client | undefined;

function getClient() {
  const project_id = process.env.STYTCH_PROJECT_ID;
  const secret = process.env.STYTCH_SECRET;
  if (!project_id || !secret) throw new Error("Stytch server configuration is incomplete");
  return client ??= new stytch.Client({ project_id, secret, env: stytch.envs.test });
}

export async function authenticateBearer(authorization: string | null): Promise<string> {
  if (!authorization?.startsWith("Bearer ")) throw new Error("Missing bearer session");
  const session_jwt = authorization.slice(7);
  if (!session_jwt) throw new Error("Missing bearer session");
  const response = await getClient().sessions.authenticate({ session_jwt });
  return response.user.user_id;
}

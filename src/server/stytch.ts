import * as stytch from "stytch";

let client: stytch.Client | undefined;

function getClient() {
  const project_id = process.env.STYTCH_PROJECT_ID;
  const secret = process.env.STYTCH_SECRET;
  const environment = process.env.STYTCH_ENVIRONMENT ?? "test";
  if (!project_id || !secret) throw new Error("Stytch server configuration is incomplete");
  if (environment !== "test" && environment !== "live") throw new Error("STYTCH_ENVIRONMENT must be test or live");
  return client ??= new stytch.Client({ project_id, secret, env: stytch.envs[environment] });
}

export async function sendEmailCode(email: string): Promise<string> {
  const response = await getClient().otps.email.loginOrCreate({
    email: email.trim().toLowerCase(),
    expiration_minutes: 10,
  });
  return response.email_id;
}

export async function verifyEmailCode(methodId: string, code: string) {
  const response = await getClient().otps.authenticate({
    method_id: methodId,
    code,
    session_duration_minutes: 60,
  });
  return {
    sessionToken: response.session_token,
    user: publicUser(response.user),
  };
}

export async function authenticateBearer(authorization: string | null): Promise<string> {
  return (await authenticateUser(authorization)).user_id;
}

export async function authenticateUser(authorization: string | null) {
  const response = await getClient().sessions.authenticate(sessionArguments(authorization));
  return response.user;
}

export async function revokeSession(authorization: string | null): Promise<void> {
  try {
    const { session } = await getClient().sessions.authenticate(sessionArguments(authorization));
    await getClient().sessions.revoke({ session_id: session.session_id });
  } catch (error) {
    if (String(error).includes("session_not_found")) return;
    throw error;
  }
}

function sessionArguments(authorization: string | null): { session_token: string } | { session_jwt: string } {
  if (!authorization?.startsWith("Bearer ")) throw new Error("Missing bearer session");
  const credential = authorization.slice(7);
  if (!credential) throw new Error("Missing bearer session");
  return credential.split(".").length === 3 ? { session_jwt: credential } : { session_token: credential };
}

export function publicUser(user: stytch.User) {
  return { id: user.user_id };
}

export async function updateTrustedMetadata(userId: string, trustedMetadata: Record<string, unknown>) {
  return (await getClient().users.update({ user_id: userId, trusted_metadata: trustedMetadata })).user;
}

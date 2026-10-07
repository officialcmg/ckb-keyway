import type { BetterAuthOptions } from "better-auth";
import { bearer, emailOTP } from "better-auth/plugins";
import type { Pool } from "pg";

export function authSchemaOptions(pool: Pool): BetterAuthOptions {
  return {
    database: pool,
    secret: process.env.BETTER_AUTH_SECRET,
    baseURL: process.env.BETTER_AUTH_URL,
    basePath: "/internal-auth",
    user: { modelName: "keyway_auth_users" },
    account: { modelName: "keyway_auth_accounts" },
    verification: { modelName: "keyway_auth_verifications" },
    session: {
      modelName: "keyway_auth_sessions",
      expiresIn: 7 * 24 * 60 * 60,
      updateAge: 24 * 60 * 60,
      cookieCache: { enabled: false },
      additionalFields: { scopeId: { type: "string", required: true, input: false } },
    },
    plugins: [
      bearer({ requireSignature: true }),
      emailOTP({ otpLength: 6, expiresIn: 600, allowedAttempts: 5, storeOTP: "hashed", resendStrategy: "rotate",
        sendVerificationOTP: async () => { throw new Error("Email delivery is not configured"); },
      }),
    ],
    advanced: { database: { generateId: "uuid" } },
    telemetry: { enabled: false },
  };
}

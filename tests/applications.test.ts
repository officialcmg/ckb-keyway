import assert from "node:assert/strict";
import test from "node:test";
import type { User } from "stytch";
import {
  addApplicationOrigin,
  applicationAllowsOrigin,
  createApplication,
  listApplications,
  prepareOtpSend,
  recordOtpResult,
  removeApplicationOrigin,
  updateApplication,
  verifyOtpApplication,
} from "../src/server/applications.ts";
import { database } from "../src/server/database.ts";

process.env.KEYWAY_RATE_LIMIT_SECRET ??= "test-rate-limit-secret-that-is-long-enough";

test("keeps application settings scoped to their owner", { skip: !process.env.DATABASE_URL }, async () => {
  const owner = { user_id: `app-owner-${crypto.randomUUID()}` } as User;
  const stranger = { user_id: `app-stranger-${crypto.randomUUID()}` } as User;
  const created = await createApplication(owner, { name: "Example Pay" });
  assert.match(created.appId, /^keyway_/);
  assert.equal((await listApplications(stranger)).length, 0);

  const withOrigin = await addApplicationOrigin(owner, {
    appId: created.appId,
    origin: "https://example.com",
    environment: "production",
  });
  assert.deepEqual(withOrigin.origins, [{ origin: "https://example.com", environment: "production" }]);
  assert.equal(await applicationAllowsOrigin(created.appId, "https://example.com"), true);
  assert.equal(await applicationAllowsOrigin(created.appId, "https://attacker.example"), false);
  await assert.rejects(updateApplication(stranger, { appId: created.appId, name: "Stolen" }), /not found/i);

  await updateApplication(owner, { appId: created.appId, disabled: true });
  assert.equal(await applicationAllowsOrigin(created.appId, "https://example.com"), false);
  await updateApplication(owner, { appId: created.appId, disabled: false });
  await removeApplicationOrigin(owner, { appId: created.appId, origin: "https://example.com" });
  assert.equal(await applicationAllowsOrigin(created.appId, "https://example.com"), false);
});

test("records OTP usage and enforces each application's request limit", { skip: !process.env.DATABASE_URL }, async () => {
  const owner = { user_id: `rate-owner-${crypto.randomUUID()}` } as User;
  const application = await createApplication(owner, { name: "Rate Limited", otpLimitPerMinute: 1 });
  const request = {
    appId: application.appId,
    email: `${crypto.randomUUID()}@example.com`,
    ipAddress: `test-${crypto.randomUUID()}`,
  };
  const context = await prepareOtpSend(request);
  await recordOtpResult(context, "sent", `method-${crypto.randomUUID()}`);
  await assert.rejects(prepareOtpSend(request), /too many/i);

  const [updated] = await listApplications(owner);
  assert.equal(updated.usage.sent24h, 1);
  assert.equal(updated.usage.rateLimited24h, 1);
});

test("refreshes a reused Stytch email method for the latest OTP send", { skip: !process.env.DATABASE_URL }, async () => {
  const owner = { user_id: `otp-owner-${crypto.randomUUID()}` } as User;
  const first = await createApplication(owner, { name: "First App" });
  const second = await createApplication(owner, { name: "Second App" });
  const methodId = `method-${crypto.randomUUID()}`;
  const firstContext = await prepareOtpSend({
    appId: first.appId,
    email: `${crypto.randomUUID()}@example.com`,
    ipAddress: `test-${crypto.randomUUID()}`,
  });
  await recordOtpResult(firstContext, "sent", methodId);
  const sql = await database();
  await sql`update keyway_otp_methods set created_at = now() - interval '1 hour' where method_id = ${methodId}`;

  const secondContext = await prepareOtpSend({
    appId: second.appId,
    email: `${crypto.randomUUID()}@example.com`,
    ipAddress: `test-${crypto.randomUUID()}`,
  });
  await recordOtpResult(secondContext, "sent", methodId);

  assert.deepEqual(await verifyOtpApplication(methodId, second.appId), {
    appId: second.appId,
    emailHash: secondContext.emailHash,
    ipHash: secondContext.ipHash,
  });
});

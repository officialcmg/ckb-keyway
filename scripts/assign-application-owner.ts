import postgres from "postgres";

const [appId, userId] = process.argv.slice(2);
if (!/^keyway_[A-Za-z0-9_-]{24}$/.test(appId ?? "") || !/^[0-9a-f-]{36}$/.test(userId ?? "")) throw new Error("Usage: assign-application-owner.ts <registered-app-id> <new-dashboard-KeyWay-user-id>");
const sql = postgres(process.env.DATABASE_URL!, { max: 1 });
try {
  const [user] = await sql`select 1 from keyway_users where id = ${userId} and scope_id = 'dashboard'`;
  if (!user) throw new Error("Owner must be a verified dashboard account");
  const rows = await sql`update keyway_applications set owner_user_id = ${userId}, updated_at = now() where app_id = ${appId} returning app_id`;
  if (!rows.length) throw new Error("Application does not exist");
  console.log(JSON.stringify({ assigned: true, appId }));
} finally { await sql.end(); }

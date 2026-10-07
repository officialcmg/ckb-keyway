import postgres from "postgres";
import { Pool } from "pg";
import { getMigrations } from "better-auth/db/migration";
import { authSchemaOptions } from "../src/server/auth-options.ts";
import { migrateDatabase } from "../src/server/database.ts";

const url = process.env.DATABASE_URL;
if (!url) throw new Error("DATABASE_URL is required");
const sql = postgres(url, { max: 1 });
const pool = new Pool({ connectionString: url, max: 1 });
try {
  if (!process.argv.includes("--print")) await migrateDatabase(sql);
  const migration = await getMigrations(authSchemaOptions(pool));
  if (migration.unsafeChanges.length || migration.schemaProblems.length) throw new Error("Authentication schema needs manual review");
  if (process.argv.includes("--print")) console.log(await migration.compileMigrations());
  else if (migration.toBeCreated.length || migration.toBeAdded.length || migration.toBeAddedIndexes.length) {
    throw new Error("Versioned authentication migrations do not match Better Auth's schema");
  }
} finally {
  await sql.end();
  await pool.end();
}

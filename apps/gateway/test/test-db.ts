import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { createClient, type Client } from "@libsql/client";
import { drizzle } from "drizzle-orm/libsql";
import * as schema from "../src/db/schema.js";

/**
 * Creates a fresh in-memory SQLite database with all 20 tables from ./drizzle/*.sql
 */
export async function createFullTestDb(): Promise<{
  client: Client;
  db: ReturnType<typeof drizzle<typeof schema>>;
}> {
  const client = createClient({ url: ":memory:" });
  const drizzleDir = join(process.cwd(), "drizzle");
  const sqlFiles = readdirSync(drizzleDir)
    .filter((f) => f.endsWith(".sql"))
    .sort();

  for (const file of sqlFiles) {
    const rawSql = readFileSync(join(drizzleDir, file), "utf-8");
    const statements = rawSql
      .split("--> statement-breakpoint")
      .map((s) => s.trim())
      .filter(Boolean);
    for (const stmt of statements) {
      await client.execute(stmt);
    }
  }

  return { client, db: drizzle(client, { schema }) };
}
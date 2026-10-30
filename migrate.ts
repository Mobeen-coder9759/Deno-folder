// Applies migration.sql (additive + idempotent). Runs in Heroku's release phase before every deploy goes live.
import { pool } from "./_shared/db.ts";

try {
  const sql = await Deno.readTextFile(new URL("./migration.sql", import.meta.url));
  await pool.query(sql);
  console.info("migration applied");
} catch (e) {
  console.error("migration failed:", e instanceof Error ? e.message : e);
  Deno.exitCode = 1;
} finally {
  await pool.end();
}

import pg from "npm:pg@8.11.3";

// DATE -> "YYYY-MM-DD". Without this node-postgres builds a JS Date at the server's local midnight and
// the date of birth can shift by a day once it is serialised to JSON (depends on the server time zone).
pg.types.setTypeParser(1082, (v: string) => v);
// numeric -> number (clinic settings)
pg.types.setTypeParser(1700, (v: string) => Number(v));
// timestamp WITHOUT time zone (app_users.created_at) is stored in UTC by Postgres: read it as UTC.
pg.types.setTypeParser(1114, (v: string) => new Date(v.replace(" ", "T") + "Z"));

export const pool = new pg.Pool({
  connectionString: Deno.env.get("DATABASE_URL"),
  // Heroku Postgres requires SSL (self-signed chain). Set DB_SSL=off ONLY for a local dev database.
  ssl: Deno.env.get("DB_SSL") === "off" ? false : { rejectUnauthorized: false },
  // Heroku Essential-0 allows 20 connections in total (n8n flows use some). Raise with PG_POOL_MAX if needed.
  max: Math.max(1, Number(Deno.env.get("PG_POOL_MAX")) || 4),
  idleTimeoutMillis: 10_000,
  connectionTimeoutMillis: 10_000,
  statement_timeout: 5_000, // kill runaway queries
  application_name: "fresh-start-api",
});

// An idle connection dropping must never crash the process.
pool.on("error", (err: Error) => console.error("pg pool error:", err.message));

export const query = (text: string, params: unknown[] = []) => pool.query(text, params);

/** Default clinic time zone. Each clinic can override it in Settings (see clinicTimeZone). */
export const TZ = Deno.env.get("CLINIC_TZ") ?? "Asia/Karachi";

/** The clinic's own time zone, or the server default when it has not saved one. */
export async function clinicTimeZone(clinicId: number): Promise<string> {
  const { rows } = await query("SELECT timezone FROM clinic_settings WHERE clinic_id = $1", [clinicId]);
  return rows[0]?.timezone ?? TZ;
}

/**
 * Tenant-scoped WHERE builder. `clinic_id = $1` is ALWAYS the first clause.
 * User values only ever enter through `?` placeholders -> bound parameters.
 */
export class Where {
  readonly params: unknown[] = [];
  private clauses: string[] = [];
  constructor(clinicId: number) {
    this.params.push(clinicId);
    this.clauses.push("clinic_id = $1");
  }
  add(sql: string, ...vals: unknown[]) {
    let i = 0;
    this.clauses.push(sql.replace(/\?/g, () => { this.params.push(vals[i++]); return `$${this.params.length}`; }));
  }
  get sql() { return this.clauses.join(" AND "); }
}

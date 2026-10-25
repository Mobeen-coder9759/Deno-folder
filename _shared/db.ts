import pg from "npm:pg@8.11.3";

export const pool = new pg.Pool({
  connectionString: Deno.env.get("DATABASE_URL"),
  // Heroku Postgres requires SSL (self-signed chain). Set DB_SSL=off ONLY for a local dev database.
  ssl: Deno.env.get("DB_SSL") === "off" ? false : { rejectUnauthorized: false },
  max: 2,
  idleTimeoutMillis: 10_000,
  statement_timeout: 5_000,           // kill runaway queries
  application_name: "fresh-start-api",
});

export const query = (text: string, params: unknown[] = []) => pool.query(text, params);

export const TZ = Deno.env.get("CLINIC_TZ") ?? "Asia/Karachi";

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

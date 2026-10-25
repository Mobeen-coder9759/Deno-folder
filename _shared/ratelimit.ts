import { query } from "./db.ts";
import { HttpError } from "./http.ts";

// Fixed-window counter, atomic upsert. Worst case is ~2x burst at a window boundary.
export async function rateLimit(key: string, limit: number, windowSec: number) {
  const { rows } = await query(
    `INSERT INTO rate_limits (key, window_start, count)
     VALUES ($1, to_timestamp(floor(extract(epoch FROM now()) / $2::int) * $2::int), 1)
     ON CONFLICT (key, window_start) DO UPDATE SET count = rate_limits.count + 1
     RETURNING count,
       extract(epoch FROM (window_start + ($2::int * interval '1 second') - now()))::int AS retry`,
    [key.slice(0, 200), windowSec],
  );
  if (Math.random() < 0.01) { // opportunistic cleanup
    query("DELETE FROM rate_limits WHERE window_start < now() - interval '1 day'").catch(() => {});
  }
  if (rows[0].count > limit) {
    throw new HttpError(429, "Too many requests", { "Retry-After": String(Math.max(rows[0].retry, 1)) });
  }
}

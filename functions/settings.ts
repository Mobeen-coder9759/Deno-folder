import { handler, json, readJson, audit, HttpError } from "../_shared/http.ts";
import { query } from "../_shared/db.ts";
import { authorize } from "../_shared/auth.ts";
import { settingsUpdateBody } from "../_shared/validate.ts";

// Column names are constants; request fields are mapped to them, never interpolated.
const COLUMNS = {
  appointment_value: "appointment_value",
  hourly_cost: "hourly_cost",
  minutes_per_booking: "minutes_per_booking",
  timezone: "timezone",
} as const;
const SELECT = "appointment_value::float8 AS appointment_value, hourly_cost::float8 AS hourly_cost, minutes_per_booking, timezone";

export default handler(async (req) => {
  // Every role that can see the dashboard needs these numbers; only admins may change them.
  const s = await authorize(req, {
    roles: req.method === "GET" ? ["admin", "staff", "hr"] : ["admin"],
    bucket: "settings",
    limit: 60,
  });

  // GET /settings
  if (req.method === "GET") {
    const { rows } = await query(`SELECT ${SELECT} FROM clinics WHERE id = $1`, [s.clinic_id]);
    if (!rows[0]) throw new HttpError(404, "Not found");
    return json({ data: rows[0] });
  }

  // PATCH /settings { appointment_value?, hourly_cost?, minutes_per_booking?, timezone? }
  if (req.method === "PATCH") {
    const b = settingsUpdateBody.parse(await readJson(req)) as Record<string, unknown>;
    const entries = Object.entries(COLUMNS).filter(([k]) => k in b);
    const sets = entries.map(([, col], i) => `${col} = $${i + 1}`);
    const vals = entries.map(([k]) => b[k]);
    vals.push(s.clinic_id);
    const { rows } = await query(
      `UPDATE clinics SET ${sets.join(", ")} WHERE id = $${vals.length} RETURNING ${SELECT}`,
      vals,
    );
    if (!rows[0]) throw new HttpError(404, "Not found");
    audit("settings_updated", s, { fields: entries.map(([k]) => k) });
    return json({ data: rows[0] });
  }

  throw new HttpError(405, "Method not allowed");
});

import { handler, json, readJson, audit, HttpError } from "../_shared/http.ts";
import { query, TZ } from "../_shared/db.ts";
import { authorize } from "../_shared/auth.ts";
import { settingsBody } from "../_shared/validate.ts";

const DEFAULTS = { appointment_value: 180, hourly_cost: 22, minutes_per_booking: 6 };

type Settings = { appointment_value: number; hourly_cost: number; minutes_per_booking: number; timezone: string };

async function load(clinicId: number): Promise<Settings> {
  const { rows } = await query(
    "SELECT appointment_value, hourly_cost, minutes_per_booking, timezone FROM clinic_settings WHERE clinic_id = $1",
    [clinicId],
  );
  return rows[0] ?? { ...DEFAULTS, timezone: TZ };
}

export default handler(async (req) => {
  // GET /settings (every role: the dashboard savings cards need it)
  if (req.method === "GET") {
    const s = await authorize(req, { roles: ["admin", "staff", "hr"] });
    return json({ data: await load(s.clinic_id) });
  }

  // PUT /settings (admin): partial update, stored per clinic
  if (req.method === "PUT") {
    const s = await authorize(req, { roles: ["admin"], bucket: "settings", limit: 30 });
    const patch = settingsBody.parse(await readJson(req));
    if (patch.timezone !== undefined) {
      const known = await query("SELECT 1 FROM pg_timezone_names WHERE name = $1", [patch.timezone]);
      if (!known.rowCount) {
        throw new HttpError(400, "Validation failed", {}, [{ field: "timezone", message: "Unknown time zone" }]);
      }
    }
    const next: Settings = { ...(await load(s.clinic_id)), ...patch };
    const { rows } = await query(
      `INSERT INTO clinic_settings (clinic_id, appointment_value, hourly_cost, minutes_per_booking, timezone)
       VALUES ($1, $2, $3, $4, $5)
       ON CONFLICT (clinic_id) DO UPDATE SET
         appointment_value = EXCLUDED.appointment_value,
         hourly_cost = EXCLUDED.hourly_cost,
         minutes_per_booking = EXCLUDED.minutes_per_booking,
         timezone = EXCLUDED.timezone,
         updated_at = now()
       RETURNING appointment_value, hourly_cost, minutes_per_booking, timezone`,
      [s.clinic_id, next.appointment_value, next.hourly_cost, next.minutes_per_booking, next.timezone],
    );
    audit("settings_updated", s, { fields: Object.keys(patch) });
    return json({ data: rows[0] });
  }

  throw new HttpError(405, "Method not allowed");
});

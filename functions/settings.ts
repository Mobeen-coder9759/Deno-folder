import { handler, json, readJson, audit, HttpError } from "../_shared/http.ts";
import { query, TZ } from "../_shared/db.ts";
import { authorize } from "../_shared/auth.ts";
import { settingsBody } from "../_shared/validate.ts";

const DEFAULTS = { appointment_value: 180, hourly_cost: 22, minutes_per_booking: 6 };

type Settings = { appointment_value: number; hourly_cost: number; minutes_per_booking: number; timezone: string };

async function load(clinicId: number): Promise<Settings> {
  const { rows } = await query(
    "SELECT appointment_value::float8, hourly_cost::float8, minutes_per_booking::float8, timezone FROM clinic_settings WHERE clinic_id = $1",
    [clinicId],
  );
  return rows[0] ?? { ...DEFAULTS, timezone: TZ };
}

export default handler(async (req) => {
  // GET /settings (every role: the dashboard savings cards need it)
  if (req.method === "GET") {
    const s = await authorize(req, { roles: ["admin", "staff", "hr"], bucket: "settings-read", limit: 120 });
    return json({ data: await load(s.clinic_id) });
  }

  // PUT /settings (admin): partial update, stored per clinic
  if (req.method === "PUT") {
    const s = await authorize(req, { roles: ["admin"], bucket: "settings", limit: 30 });
    const patch = settingsBody.parse(await readJson(req));
    
    if (!Object.keys(patch).length) throw new HttpError(400, "Nothing to update");

    if (patch.timezone !== undefined) {
      const known = await query("SELECT 1 FROM pg_timezone_names WHERE name = $1", [patch.timezone]);
      if (!known.rowCount) {
        throw new HttpError(400, "Unknown time zone");
      }
    }

    const { rows } = await query(
      `INSERT INTO clinic_settings (clinic_id, appointment_value, hourly_cost, minutes_per_booking, timezone)
       VALUES ($1, COALESCE($2::numeric, $7::numeric), COALESCE($3::numeric, $8::numeric),
               COALESCE($4::numeric, $9::numeric), COALESCE($5::text, $6::text))
       ON CONFLICT (clinic_id) DO UPDATE SET
         appointment_value   = COALESCE($2::numeric, clinic_settings.appointment_value),
         hourly_cost         = COALESCE($3::numeric, clinic_settings.hourly_cost),
         minutes_per_booking = COALESCE($4::numeric, clinic_settings.minutes_per_booking),
         timezone            = COALESCE($5::text,    clinic_settings.timezone),
         updated_at = now()
       RETURNING appointment_value::float8, hourly_cost::float8, minutes_per_booking::float8, timezone`,
      [
        s.clinic_id, 
        patch.appointment_value ?? null, 
        patch.hourly_cost ?? null, 
        patch.minutes_per_booking ?? null, 
        patch.timezone ?? null,
        TZ, 
        DEFAULTS.appointment_value, 
        DEFAULTS.hourly_cost, 
        DEFAULTS.minutes_per_booking
      ],
    );
    
    audit("settings_updated", s, { fields: Object.keys(patch) });
    return json({ data: rows[0] });
  }

  throw new HttpError(405, "Method not allowed");
});

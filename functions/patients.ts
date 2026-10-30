import { handler, json, readJson, queryParams, audit, HttpError } from "../_shared/http.ts";
import { query, Where } from "../_shared/db.ts";
import { authorize } from "../_shared/auth.ts";
import { patientsQuery, patientUpdate, patientKeyQuery } from "../_shared/validate.ts";

const ROLES = ["admin", "staff"];
const SORT = { asc: "ASC", desc: "DESC" } as const; // user input is mapped, never interpolated
// request field -> column (constants)
const UPDATABLE = { new_name: "name", new_phone: "phone", email: "email", dob: "dob", insurance: "insurance" } as const;
const escLike = (s: string) => s.replace(/[\\%_]/g, "\\$&");

export default handler(async (req) => {
  // Deleting a patient wipes their appointment history, so that's admin-only
  const s = await authorize(req, { roles: req.method === "DELETE" ? ["admin"] : ROLES });

  // GET /patients?sort=asc|desc&search=
  if (req.method === "GET") {
    const q = patientsQuery.parse(queryParams(req));
    const w = new Where(s.clinic_id);
    if (q.search) w.add("name ILIKE ? ESCAPE '\\'", `%${escLike(q.search)}%`);
    const params = [...w.params, q.limit, q.offset];
    const { rows } = await query(
      `SELECT name, phone,
         (array_agg(email     ORDER BY updated_at DESC) FILTER (WHERE email     IS NOT NULL))[1] AS email,
         (array_agg(dob       ORDER BY updated_at DESC) FILTER (WHERE dob       IS NOT NULL))[1] AS dob,
         (array_agg(insurance ORDER BY updated_at DESC) FILTER (WHERE insurance IS NOT NULL))[1] AS insurance,
         COUNT(*)::int AS total_appointments,
         MAX(booking_time) AS last_appointment
       FROM appointments WHERE ${w.sql}
       GROUP BY name, phone
       ORDER BY lower(name) ${SORT[q.sort]}, phone
       LIMIT $${params.length - 1} OFFSET $${params.length}`,
      params,
    );
    return json({ data: rows });
  }

  // PATCH /patients { name, phone, new_name?, new_phone?, email?, dob?, insurance? }
  if (req.method === "PATCH") {
    const b = patientUpdate.parse(await readJson(req)) as Record<string, unknown>;
    const entries = Object.entries(UPDATABLE).filter(([k]) => k in b);
    const sets = entries.map(([, col], i) => `${col} = $${i + 1}`);
    const vals = entries.map(([k]) => b[k]);
    const params = [...vals, s.clinic_id, b.name, b.phone];
    const n = params.length;
    const { rowCount } = await query(
      `UPDATE appointments SET ${sets.join(", ")}, updated_at = now()
       WHERE clinic_id = $${n - 2} AND name = $${n - 1} AND phone IS NOT DISTINCT FROM $${n}::varchar`,
      params,
    );
    if (!rowCount) throw new HttpError(404, "Not found");
    audit("patient_updated", s, { rows: rowCount });
    return json({ updated: rowCount });
  }

  // DELETE /patients?name=&phone=
  if (req.method === "DELETE") {
    const q = patientKeyQuery.parse(queryParams(req));
    const { rowCount } = await query(
      `DELETE FROM appointments
       WHERE clinic_id = $1 AND name = $2 AND phone IS NOT DISTINCT FROM $3::varchar`,
      [s.clinic_id, q.name, q.phone ?? null],
    );
    if (!rowCount) throw new HttpError(404, "Not found");
    audit("patient_deleted", s, { rows: rowCount });
    return json({ deleted: rowCount });
  }

  throw new HttpError(405, "Method not allowed");
});

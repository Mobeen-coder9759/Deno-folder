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
  // Deleting a patient wipes their appointment history, so that's admin-only.
  // Rate-limited authorize bucket added
  const s = await authorize(req, { 
    roles: req.method === "DELETE" ? ["admin"] : ROLES, 
    bucket: "patients", 
    limit: 60 
  });

  // GET /patients?sort=asc|desc&search=
  if (req.method === "GET") {
    const q = patientsQuery.parse(queryParams(req));
    const w = new Where(s.clinic_id);
    
    // Normalizing searches to trim and lowercase prevents duplicate-drift issues 
    if (q.search) w.add("lower(trim(name)) ILIKE ? ESCAPE '\\'", `%${escLike(q.search.toLowerCase().trim())}%`);
    
    const params = [...w.params, q.limit, q.offset];
    const { rows } = await query(
      `SELECT 
         (array_agg(name     ORDER BY updated_at DESC))[1] AS name, 
         phone,
         (array_agg(email     ORDER BY updated_at DESC) FILTER (WHERE email     IS NOT NULL))[1] AS email,
         (array_agg(dob       ORDER BY updated_at DESC) FILTER (WHERE dob       IS NOT NULL))[1] AS dob,
         (array_agg(insurance ORDER BY updated_at DESC) FILTER (WHERE insurance IS NOT NULL))[1] AS insurance,
         COUNT(*)::int AS total_appointments,
         MAX(booking_time) AS last_appointment
       FROM appointments WHERE ${w.sql}
       GROUP BY lower(trim(name)), phone
       ORDER BY lower(trim(name)) ${SORT[q.sort]}, (array_agg(name ORDER BY updated_at DESC))[1], phone
       LIMIT $${params.length - 1} OFFSET $${params.length}`,
      params,
    );
    return json({ data: rows });
  }

  // PATCH /patients { name, phone, new_name?, new_phone?, email?, dob?, insurance? }
  if (req.method === "PATCH") {
    const b = patientUpdate.parse(await readJson(req)) as Record<string, unknown>;
    const entries = Object.entries(UPDATABLE).filter(([k]) => k in b);
    
    // Bug fix: Empty payload safeguard
    if (!entries.length) throw new HttpError(400, "Nothing to update");
    
    const sets = entries.map(([, col], i) => `${col} = $${i + 1}`);
    const vals = entries.map(([k]) => b[k]);
    
    // Bug fix: undefined phone is now an explicit null
    const params = [...vals, s.clinic_id, b.name, b.phone ?? null];
    const n = params.length;
    
    // Update uses normalized name matching and returns mapped IDs for thick logging
    const { rows } = await query(
      `UPDATE appointments SET ${sets.join(", ")}, updated_at = now()
       WHERE clinic_id = $${n - 2} 
         AND lower(trim(name)) = lower(trim($${n - 1}::varchar)) 
         AND phone IS NOT DISTINCT FROM $${n}::varchar
       RETURNING id`,
      params,
    );
    if (!rows.length) throw new HttpError(404, "Not found");
    
    // Thicker audit log: records IDs instead of just the rowCount
    audit("patient_updated", s, { ids: rows.map(r => r.id) });
    return json({ updated: rows.length });
  }

  // DELETE /patients?name=&phone=
  if (req.method === "DELETE") {
    const q = patientKeyQuery.parse(queryParams(req));
    
    // Delete uses normalized name matching and returns mapped IDs
    const { rows } = await query(
      `DELETE FROM appointments
       WHERE clinic_id = $1 
         AND lower(trim(name)) = lower(trim($2::varchar)) 
         AND phone IS NOT DISTINCT FROM $3::varchar
       RETURNING id`,
      [s.clinic_id, q.name, q.phone ?? null],
    );
    if (!rows.length) throw new HttpError(404, "Not found");
    
    // Thicker audit log
    audit("patient_deleted", s, { ids: rows.map(r => r.id) });
    return json({ deleted: rows.length });
  }

  throw new HttpError(405, "Method not allowed");
});

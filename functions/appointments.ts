import { handler, json, readJson, subpath, queryParams, audit, HttpError } from "../_shared/http.ts";
import { query, Where, clinicTimeZone } from "../_shared/db.ts";
import { authorize } from "../_shared/auth.ts";
import { appointmentCreate, appointmentUpdate, appointmentsQuery, idParam } from "../_shared/validate.ts";

const ROLES = ["admin", "staff"];            // read + write
const READ_ROLES = ["admin", "staff", "hr"]; // hr: read-only, and never receives contact/insurance data
// Column names come from these constants, never from request data
const WRITABLE = ["name", "phone", "email", "dob", "insurance", "reason", "booking_type", "booking_time", "old_time", "cancel_time"] as const;
const STATUS = "CASE WHEN cancel_time IS NOT NULL THEN 'cancelled' ELSE 'scheduled' END AS status";
const SELECT = `id, name, phone, email, dob, insurance, reason, booking_type, booking_time, old_time, cancel_time, created_at, updated_at, ${STATUS}`;
const SELECT_HR = `id, name, NULL AS phone, NULL AS email, NULL::date AS dob, NULL AS insurance, reason, booking_type, booking_time, old_time, cancel_time, created_at, updated_at, ${STATUS}`;
const escLike = (s: string) => s.replace(/[\\%_]/g, "\\$&"); // user-supplied % and _ are literals

const pick = (b: Record<string, unknown>) => {
  const cols = WRITABLE.filter((c) => c in b);
  return { cols, vals: cols.map((c) => b[c]) };
};

export default handler(async (req) => {
  const s = await authorize(req, { roles: req.method === "GET" ? READ_ROLES : ROLES });
  const [idRaw] = subpath(req, "appointments");

  // GET /appointments?date=&reason=&search=&limit=&offset=
  if (req.method === "GET" && !idRaw) {
    const q = appointmentsQuery.parse(queryParams(req));
    const w = new Where(s.clinic_id);
    if (q.date) w.add("(booking_time AT TIME ZONE ?::text)::date = ?::date", await clinicTimeZone(s.clinic_id), q.date);
    if (q.reason) w.add("reason ILIKE ? ESCAPE '\\'", `%${escLike(q.reason)}%`);
    if (q.search) w.add("name ILIKE ? ESCAPE '\\'", `%${escLike(q.search)}%`);
    const params = [...w.params, q.limit, q.offset];
    const { rows } = await query(
      `SELECT ${s.role === "hr" ? SELECT_HR : SELECT} FROM appointments WHERE ${w.sql}
       ORDER BY booking_time ASC NULLS LAST, id ASC
       LIMIT $${params.length - 1} OFFSET $${params.length}`,
      params,
    );
    return json({ data: rows });
  }

  // POST /appointments
  if (req.method === "POST" && !idRaw) {
    const { cols, vals } = pick(appointmentCreate.parse(await readJson(req)));
    const placeholders = cols.map((_, i) => `$${i + 3}`).join(", ");
    const { rows } = await query(
      `INSERT INTO appointments (clinic_id, calendar_event_id, ${cols.join(", ")})
       VALUES ($1, $2, ${placeholders}) RETURNING ${SELECT}`,
      [s.clinic_id, `crm-${crypto.randomUUID()}`, ...vals],
    );
    audit("appointment_created", s, { id: rows[0].id });
    return json({ data: rows[0] }, 201);
  }

  // PATCH /appointments/:id
  if (req.method === "PATCH" && idRaw) {
    const id = idParam.parse(idRaw);
    const { cols, vals } = pick(appointmentUpdate.parse(await readJson(req)));
    const sets = cols.map((c, i) => `${c} = $${i + 1}`);
    const params = [...vals, id, s.clinic_id];
    const { rows } = await query(
      `UPDATE appointments SET ${sets.join(", ")}, updated_at = now()
       WHERE id = $${params.length - 1} AND clinic_id = $${params.length} RETURNING ${SELECT}`,
      params,
    );
    if (!rows[0]) throw new HttpError(404, "Not found"); // other clinic's id looks identical to a missing id
    audit("appointment_updated", s, { id });
    return json({ data: rows[0] });
  }

  // DELETE /appointments/:id
  if (req.method === "DELETE" && idRaw) {
    const id = idParam.parse(idRaw);
    const { rowCount } = await query("DELETE FROM appointments WHERE id = $1 AND clinic_id = $2", [id, s.clinic_id]);
    if (!rowCount) throw new HttpError(404, "Not found");
    audit("appointment_deleted", s, { id });
    return json({ ok: true });
  }

  throw new HttpError(405, "Method not allowed");
});

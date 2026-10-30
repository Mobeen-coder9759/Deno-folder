import { handler, json, queryParams, HttpError } from "../_shared/http.ts";
import { query, clinicTimeZone } from "../_shared/db.ts";
import { authorize } from "../_shared/auth.ts";
import { analyticsQuery } from "../_shared/validate.ts";

export default handler(async (req) => {
  if (req.method !== "GET") throw new HttpError(405, "Method not allowed");
  // hr can open the dashboard, and these are aggregate counts only (no patient data)
  const s = await authorize(req, { roles: ["admin", "staff", "hr"], bucket: "analytics", limit: 30 });
  const { days } = analyticsQuery.parse(queryParams(req));
  const TZ = await clinicTimeZone(s.clinic_id);

  // Cancelled appointments (cancel_time set) are excluded. Swap booking_time -> created_at
  // below if "bookings" should mean "when it was booked" instead of "when it's scheduled".
  const [reasons, bookings] = await Promise.all([
    query(
      `SELECT initcap(lower(COALESCE(NULLIF(trim(reason), ''), 'Unspecified'))) AS reason, COUNT(*)::int AS count
       FROM appointments
       WHERE clinic_id = $1 AND cancel_time IS NULL AND booking_time IS NOT NULL
         AND (booking_time AT TIME ZONE $2::text)::date
             BETWEEN (now() AT TIME ZONE $2::text)::date - ($3::int - 1) AND (now() AT TIME ZONE $2::text)::date
       GROUP BY 1 ORDER BY count DESC, reason LIMIT 10`,
      [s.clinic_id, TZ, days],
    ),
    query(
      `SELECT to_char(d, 'YYYY-MM-DD') AS date, COUNT(a.id)::int AS count
       FROM generate_series(
              ((now() AT TIME ZONE $2::text)::date - ($3::int - 1))::timestamp,
              (now() AT TIME ZONE $2::text)::date::timestamp,
              interval '1 day') AS d
       LEFT JOIN appointments a
         ON a.clinic_id = $1 AND a.cancel_time IS NULL
        AND (a.booking_time AT TIME ZONE $2::text)::date = d::date
       GROUP BY d ORDER BY d`,
      [s.clinic_id, TZ, days],
    ),
  ]);

  return json({ reasons: reasons.rows, bookings: bookings.rows });
});

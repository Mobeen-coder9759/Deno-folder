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

  // Cancelled appointments (cancel_time set) are excluded. 
  // If "bookings" should mean "when the agent booked it" instead of "when the visit is scheduled",
  // swap `booking_time` for `created_at` in both queries below.
  const [reasons, bookings] = await Promise.all([
    query(
      `WITH ranked AS (
         SELECT 
           initcap(lower(COALESCE(NULLIF(trim(reason), ''), 'Unspecified'))) AS reason, 
           COUNT(*)::int AS count
         FROM appointments
         WHERE clinic_id = $1 
           AND cancel_time IS NULL 
           -- Index-friendly range filter using the existing active_bookings index
           AND booking_time >= ((now() AT TIME ZONE $2::text)::date - ($3::int - 1))::timestamp AT TIME ZONE $2::text
           AND booking_time <  ((now() AT TIME ZONE $2::text)::date + 1)::timestamp AT TIME ZONE $2::text
         GROUP BY 1
       ),
       numbered AS (
         SELECT reason, count, ROW_NUMBER() OVER (ORDER BY count DESC, reason) as rn
         FROM ranked
       )
       SELECT 
         CASE WHEN rn <= 10 THEN reason ELSE 'Other' END AS reason,
         SUM(count)::int AS count
       FROM numbered
       GROUP BY 
         CASE WHEN rn <= 10 THEN reason ELSE 'Other' END, 
         CASE WHEN rn <= 10 THEN rn ELSE 11 END
       ORDER BY CASE WHEN rn <= 10 THEN rn ELSE 11 END`,
      [s.clinic_id, TZ, days],
    ),
    query(
      `WITH dates AS (
         SELECT d::date AS date
         FROM generate_series(
           (now() AT TIME ZONE $2::text)::date - ($3::int - 1),
           (now() AT TIME ZONE $2::text)::date,
           interval '1 day'
         ) d
       ),
       counts AS (
         SELECT 
           (booking_time AT TIME ZONE $2::text)::date AS date, 
           COUNT(*)::int AS count
         FROM appointments
         WHERE clinic_id = $1 
           AND cancel_time IS NULL
           -- Index-friendly range filter limits the rows before the group-by cast happens
           AND booking_time >= ((now() AT TIME ZONE $2::text)::date - ($3::int - 1))::timestamp AT TIME ZONE $2::text
           AND booking_time <  ((now() AT TIME ZONE $2::text)::date + 1)::timestamp AT TIME ZONE $2::text
         GROUP BY 1
       )
       SELECT 
         to_char(dates.date, 'YYYY-MM-DD') AS date, 
         COALESCE(counts.count, 0)::int AS count
       FROM dates
       LEFT JOIN counts ON dates.date = counts.date
       ORDER BY dates.date`,
      [s.clinic_id, TZ, days],
    ),
  ]);

  return json({ reasons: reasons.rows, bookings: bookings.rows });
});

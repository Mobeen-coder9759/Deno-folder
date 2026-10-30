-- Fresh Start API: additive, idempotent schema changes.
-- Applied automatically on every Heroku deploy (release phase: `deno run ... migrate.ts`).
-- Safe to run any number of times. It never changes or deletes existing rows.
-- Data fixes and NOT NULL live in manual-steps.sql.

-- Rate limiting store
CREATE TABLE IF NOT EXISTS rate_limits (
  key          text        NOT NULL,
  window_start timestamptz NOT NULL,
  count        int         NOT NULL DEFAULT 1,
  PRIMARY KEY (key, window_start)
);

-- Per-clinic settings behind the Settings page (savings calculator inputs + time zone)
CREATE TABLE IF NOT EXISTS clinic_settings (
  clinic_id           integer       PRIMARY KEY REFERENCES clinics (id) ON DELETE CASCADE,
  appointment_value   numeric(12,2) NOT NULL DEFAULT 180,
  hourly_cost         numeric(12,2) NOT NULL DEFAULT 22,
  minutes_per_booking numeric(8,2)  NOT NULL DEFAULT 6,
  timezone            text          NOT NULL,
  updated_at          timestamptz   NOT NULL DEFAULT now()
);

-- Performance
CREATE INDEX IF NOT EXISTS appointments_clinic_booking_idx ON appointments (clinic_id, booking_time);
CREATE INDEX IF NOT EXISTS appointments_clinic_name_idx    ON appointments (clinic_id, lower(name));

-- Usernames are case-insensitive in the API. If case-collisions already exist this index is skipped
-- (with a NOTICE) instead of failing the deploy: fix the duplicates, then re-run.
DO $$
BEGIN
  CREATE UNIQUE INDEX IF NOT EXISTS app_users_username_ci_key ON app_users (lower(username));
EXCEPTION WHEN unique_violation THEN
  RAISE NOTICE 'app_users_username_ci_key skipped: usernames that differ only by case exist';
END
$$;

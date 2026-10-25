-- Rate limiting store
CREATE TABLE IF NOT EXISTS rate_limits (
  key          text        NOT NULL,
  window_start timestamptz NOT NULL,
  count        int         NOT NULL DEFAULT 1,
  PRIMARY KEY (key, window_start)
);

-- Performance
CREATE INDEX IF NOT EXISTS appointments_clinic_booking_idx ON appointments (clinic_id, booking_time);
CREATE INDEX IF NOT EXISTS appointments_clinic_name_idx    ON appointments (clinic_id, lower(name));

-- Usernames are case-insensitive in the API (fails if you already have case-collisions: fix those first)
CREATE UNIQUE INDEX IF NOT EXISTS app_users_username_ci_key ON app_users (lower(username));

-- Find orphans (rows with no clinic are invisible to every query)
SELECT count(*) FROM appointments WHERE clinic_id IS NULL;
SELECT count(*) FROM app_users    WHERE clinic_id IS NULL;

-- Assign orphans to the right clinic (replace 1 with the real clinics.id)
-- UPDATE appointments SET clinic_id = 1 WHERE clinic_id IS NULL;
-- UPDATE app_users    SET clinic_id = 1 WHERE clinic_id IS NULL;

-- DO THIS LAST: only after your n8n / voice-agent INSERTs include clinic_id.
-- Once applied, any insert without clinic_id will fail.
-- ALTER TABLE appointments ALTER COLUMN clinic_id SET NOT NULL;
-- ALTER TABLE app_users    ALTER COLUMN clinic_id SET NOT NULL;

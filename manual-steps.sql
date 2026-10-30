-- Run these BY HAND (psql / heroku pg:psql), in this order. They depend on your data,
-- so they are never run automatically.

-- 1. Rows with no clinic are invisible to the API, and a user without a clinic cannot sign in.
SELECT count(*) AS appointments_without_clinic FROM appointments WHERE clinic_id IS NULL;
SELECT count(*) AS users_without_clinic        FROM app_users    WHERE clinic_id IS NULL;

-- 2. Assign them to the right clinic (replace 1 with the real clinics.id):
-- UPDATE appointments SET clinic_id = 1 WHERE clinic_id IS NULL;
-- UPDATE app_users    SET clinic_id = 1 WHERE clinic_id IS NULL;

-- 3. DO THIS LAST, only after your n8n / voice-agent INSERTs include clinic_id.
--    Once applied, any insert without clinic_id fails.
-- ALTER TABLE appointments ALTER COLUMN clinic_id SET NOT NULL;
-- ALTER TABLE app_users    ALTER COLUMN clinic_id SET NOT NULL;

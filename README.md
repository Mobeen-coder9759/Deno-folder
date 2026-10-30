# Fresh Start API (Deno on Heroku)

One Deno app serving `/auth`, `/appointments`, `/patients`, `/analytics`, `/settings`, `/health` against Heroku Postgres.
Every query is scoped to the `clinic_id` of the **database-verified** session. `clinic_id` and `role` are never read from a request body or query string.

## Endpoints

| Method | Path | Roles | Notes |
| --- | --- | --- | --- |
| POST | `/auth/login` | public | `{ username, password }` -> `{ token, user }` |
| POST | `/auth/register` | public + `REGISTRATION_KEY` | new clinic + its first admin. **Disabled unless `REGISTRATION_KEY` is set** |
| GET | `/auth/me` | any | the signed-in user as the database sees them now |
| GET / POST | `/auth/users` | admin | list / add users of **your** clinic |
| PATCH | `/auth/users/:id` | admin | `{ role?, is_active?, name? }`; you can't change your own role/status |
| GET / POST | `/appointments` | read: admin, staff, hr · write: admin, staff | **hr gets names/times/reasons only** (phone, email, dob, insurance are null) |
| PATCH / DELETE | `/appointments/:id` | admin, staff | another clinic's id is a 404 |
| GET / PATCH / DELETE | `/patients` | admin, staff (delete: admin) | patients = (name, phone) groups of appointments |
| GET | `/analytics?days=30` | admin, staff, hr | `{ reasons, bookings }` for the dashboard charts |
| GET / PUT | `/settings` | read: all · write: admin | per-clinic savings inputs + time zone |
| GET | `/health` | public | `{ "ok": true }` |

## Deploy (Heroku)
1. Set config vars (see `.env.example`): `DATABASE_URL` (add-on sets it), `JWT_SECRET`, `ALLOWED_ORIGINS`, optionally `REGISTRATION_KEY`, `CLINIC_TZ`.
   Without `ALLOWED_ORIGINS` every browser call gets 403. Use exact origins: your Lovable preview URL and your published URL.
2. Push this folder to Heroku. The `release:` line in the `Procfile` runs `migration.sql` on every deploy (additive and idempotent: creates the `clinic_settings` table if missing, never edits rows).
   If your buildpack can't run release-phase commands, remove that line and run `deno task migrate` once instead.
3. Check `https://<your-app>.herokuapp.com/health` returns `{"ok":true}`.
4. Frontend: `VITE_API_BASE_URL` (or the default in `src/lib/api.ts`) must be this app's URL.

### Before anyone can sign in
- The user row needs `is_active = true`, a bcrypt `password_hash` and a non-null `clinic_id`.
- Appointments need a `clinic_id` too (rows without one are invisible). See `manual-steps.sql`.
- Make your n8n / voice-agent INSERTs include `clinic_id`, **then** run the `SET NOT NULL` lines in `manual-steps.sql`.

## Run locally
    cp .env.example .env   # fill in; add DB_SSL=off only for a local non-SSL database
    deno task start

## Tests (needs Postgres + python3 with `bcrypt` + deno)
`tests/schema.sql` mirrors your real schema. Create a scratch database `fs` (role `app`, password `app`), apply `tests/schema.sql` and `migration.sql`, then start the server **the way the Procfile does** with:
`DATABASE_URL=postgres://app:app@localhost:5432/fs DB_SSL=off JWT_SECRET=test-secret-test-secret-test-secret-123456 ALLOWED_ORIGINS=http://localhost:8080 REGISTRATION_KEY=invite123 TZ=America/Los_Angeles`
(a non-UTC `TZ` proves dates of birth don't shift), log to `/tmp/server.log`, then `python3 tests/test_api.py` (162 checks).

## Notes
- Heroku caps DB connections (Essential-0: 20). Each instance opens up to `PG_POOL_MAX` (default 4).
- Client IP for rate limits is the address Heroku appended to `X-Forwarded-For` (counted from the right). Anything a client sends to its left, and `CF-Connecting-IP`, is ignored. Behind extra proxies raise `TRUST_PROXY_HOPS`.
- The per-username login limit is the main brute-force defense; a successful sign-in resets that user's counter.

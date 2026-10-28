# Fresh Start API (Deno)

One Deno app serving /auth, /appointments, /patients, /analytics, /settings, /health against your Heroku Postgres.

| Route | Methods | Roles |
|---|---|---|
| `/auth/login`, `/auth/register` | POST | public (register can be invite-only) |
| `/auth/users` | GET (list clinic users), POST (add user) | admin |
| `/auth/users/:id` | PATCH `{ role?, is_active? }` | admin (not on yourself) |
| `/appointments`, `/appointments/:id` | GET / POST / PATCH / DELETE | admin, staff (hr: GET only, no contact data) |
| `/patients` | GET / PATCH, DELETE (admin only) | admin, staff |
| `/analytics` | GET | admin, staff, hr |
| `/settings` | GET, PATCH `{ appointment_value?, hourly_cost?, minutes_per_booking?, timezone? }` | GET: all roles, PATCH: admin |

Every query is scoped by the `clinic_id` of the verified session, never by anything in the request.

## Deploy
1. Run `migration.sql` on Heroku Postgres (safe to re-run; it also adds the per-clinic settings columns). Leave the commented-out SET NOT NULL lines for last.
2. Put this folder in a GitHub repo and create a Deno Deploy project from it, entrypoint `main.ts`
   (or `deployctl deploy --project=<name> main.ts`). Check Deno Deploy's docs for the current flow.
3. Set env vars in Deno Deploy (see `.env.example`): DATABASE_URL, JWT_SECRET, ALLOWED_ORIGINS, REGISTRATION_KEY, CLINIC_TZ.
4. Check `https://<your-app>/health` returns {"ok":true}.
5. Put `lovable/src/lib/api.ts` in the Lovable project with your deployed URL as the base.

## Run locally
    cp .env.example .env   # fill in, add DB_SSL=off only for a local non-SSL database
    deno task start

## Tests (needs Postgres + python3 with `bcrypt`)
`tests/schema.sql` mirrors your real schema. Apply it plus `migration.sql` to a scratch DB, start the server with
DB_SSL=off, JWT_SECRET=test-secret-test-secret-test-secret-123456, ALLOWED_ORIGINS=http://localhost:8080,
REGISTRATION_KEY=invite123, then `python3 tests/test_api.py` (147 checks). The suite passes with the server running under `TZ=UTC`, `Asia/Karachi` and `America/Los_Angeles`.

## Notes
- Heroku caps DB connections (Essential-0 allows 20). Each instance opens up to 2, so watch the count as traffic grows.
- Per-IP rate limits use the LAST `X-Forwarded-For` entry, which is the address Heroku's router appends. Entries before it are client-supplied and ignored. If you move behind a different proxy, revisit `clientIp()` in `_shared/http.ts`.
- The per-username login limit is still the main brute-force defense.
- `DATE` columns (e.g. `dob`) are returned as plain `YYYY-MM-DD` strings (`_shared/db.ts`), so they never shift a day with the server's timezone.

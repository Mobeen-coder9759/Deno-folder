# Fresh Start API (Deno)

One Deno app serving /auth, /appointments, /patients, /analytics, /health against your Heroku Postgres.

## Deploy
1. Run `migration.sql` on Heroku Postgres (leave the commented-out SET NOT NULL lines for last).
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
REGISTRATION_KEY=invite123, then `python3 tests/test_api.py` (101 checks).

## Notes
- Heroku caps DB connections (Essential-0 allows 20). Each instance opens up to 2, so watch the count as traffic grows.
- The per-username login limit is the real brute-force defense; IP headers can be spoofed by clients.

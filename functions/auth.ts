import bcrypt from "npm:bcryptjs@2.4.3";
import { handler, json, readJson, subpath, clientIp, audit, HttpError } from "../_shared/http.ts";
import { pool, query } from "../_shared/db.ts";
import { signToken, authorize } from "../_shared/auth.ts";
import { rateLimit } from "../_shared/ratelimit.ts";
import { registerBody, loginBody, createUserBody, userStatusBody, idParam } from "../_shared/validate.ts";

const COST = 10;
const DUMMY_HASH = bcrypt.hashSync("not-a-real-password", COST); // equalizes timing for unknown usernames
const LOGIN_WINDOW = 15 * 60;
const PUBLIC_USER = "id, clinic_id, role, username, name"; // constant: never select password_hash for responses

async function safeEqual(a: string, b: string) {
  const enc = new TextEncoder();
  const [ha, hb] = await Promise.all([
    crypto.subtle.digest("SHA-256", enc.encode(a)),
    crypto.subtle.digest("SHA-256", enc.encode(b)),
  ]);
  const x = new Uint8Array(ha), y = new Uint8Array(hb);
  let diff = 0;
  for (let i = 0; i < x.length; i++) diff |= x[i] ^ y[i];
  return diff === 0;
}

export default handler(async (req) => {
  const [a, b] = subpath(req, "auth"); // /auth/login | /auth/register | /auth/users | /auth/users/:id

  // POST /auth/register -> creates a NEW clinic + its first admin. Never accepts a clinic_id.
  if (a === "register" && req.method === "POST") {
    await rateLimit(`register:ip:${clientIp(req)}`, 5, 3600);
    const body = registerBody.parse(await readJson(req));

    const regKey = Deno.env.get("REGISTRATION_KEY");
    if (regKey && !(body.registration_key && await safeEqual(body.registration_key, regKey))) {
      throw new HttpError(403, "Registration is invite-only");
    }

    const hash = await bcrypt.hash(body.password, COST);
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const dup = await client.query("SELECT 1 FROM app_users WHERE lower(username) = $1", [body.username]);
      if (dup.rowCount) throw new HttpError(409, "Username already taken");
      const clinic = await client.query("INSERT INTO clinics (name) VALUES ($1) RETURNING id", [body.clinic_name]);
      const { rows } = await client.query(
        `INSERT INTO app_users (username, password_hash, name, role, clinic_id)
         VALUES ($1, $2, $3, 'admin', $4) RETURNING ${PUBLIC_USER}`,
        [body.username, hash, body.name, clinic.rows[0].id],
      );
      await client.query("COMMIT");
      const u = rows[0];
      return json({ token: await signToken(u), user: u }, 201);
    } catch (e) {
      await client.query("ROLLBACK");
      throw e;
    } finally {
      client.release();
    }
  }

  // POST /auth/login
  if (a === "login" && req.method === "POST") {
    await rateLimit(`login:ip:${clientIp(req)}`, 30, LOGIN_WINDOW);
    const body = loginBody.parse(await readJson(req));
    // Per-username limit is the real brute-force defense (IP headers can be spoofed)
    await rateLimit(`login:user:${body.username}`, 8, LOGIN_WINDOW);

    const { rows } = await query(
      `SELECT ${PUBLIC_USER}, password_hash, is_active FROM app_users WHERE lower(username) = $1`,
      [body.username],
    );
    const u = rows[0];
    const ok = await bcrypt.compare(body.password, u?.password_hash ?? DUMMY_HASH); // always runs
    if (!u || !ok || u.is_active !== true || u.clinic_id == null) {
      throw new HttpError(401, "Invalid username or password"); // identical for every failure mode
    }
    const { password_hash: _h, is_active: _a, ...user } = u;
    return json({ token: await signToken(user), user });
  }

  // POST /auth/users (admin adds staff to THEIR clinic)
  if (a === "users" && !b && req.method === "POST") {
    const s = await authorize(req, { roles: ["admin"], bucket: "users", limit: 20 });
    const body = createUserBody.parse(await readJson(req));
    const dup = await query("SELECT 1 FROM app_users WHERE lower(username) = $1", [body.username]);
    if (dup.rowCount) throw new HttpError(409, "Username already taken");
    const hash = await bcrypt.hash(body.password, COST);
    const { rows } = await query(
      `INSERT INTO app_users (username, password_hash, name, role, clinic_id)
       VALUES ($1, $2, $3, $4, $5) RETURNING ${PUBLIC_USER}`,
      [body.username, hash, body.name, body.role, s.clinic_id], // clinic from verified session
    );
    audit("user_created", s, { target: rows[0].id, role: body.role });
    return json({ user: rows[0] }, 201);
  }

  // PATCH /auth/users/:id  { is_active } (deactivation takes effect immediately)
  if (a === "users" && b && req.method === "PATCH") {
    const s = await authorize(req, { roles: ["admin"], bucket: "users", limit: 20 });
    const id = idParam.parse(b);
    if (id === s.id) throw new HttpError(400, "You can't change your own status");
    const body = userStatusBody.parse(await readJson(req));
    const { rows } = await query(
      `UPDATE app_users SET is_active = $1 WHERE id = $2 AND clinic_id = $3 RETURNING ${PUBLIC_USER}, is_active`,
      [body.is_active, id, s.clinic_id],
    );
    if (!rows[0]) throw new HttpError(404, "Not found");
    audit("user_status", s, { target: id, is_active: body.is_active });
    return json({ user: rows[0] });
  }

  throw new HttpError(404, "Not found");
});

import bcrypt from "npm:bcryptjs@2.4.3";
import { handler, json, readJson, subpath, clientIp, audit, HttpError } from "../_shared/http.ts";
import { pool, query } from "../_shared/db.ts";
import { signToken, authorize } from "../_shared/auth.ts";
import { rateLimit, clearRateLimit } from "../_shared/ratelimit.ts";
import {
  registerBody, loginBody, createUserBody, updateUserBody, idParam,
  forgotPasswordBody, resetPasswordBody,
} from "../_shared/validate.ts";

const COST = 10;
const DUMMY_HASH = bcrypt.hashSync("not-a-real-password", COST); // equalizes timing for unknown usernames
const LOGIN_WINDOW = 15 * 60;
const PUBLIC_USER = "id, clinic_id, role, username, name"; // constant: never select password_hash for responses
const MANAGED_USER = `${PUBLIC_USER}, is_active, created_at`; // what the admin's user list shows

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

/** SHA-256 hex of raw token — stored in DB, never the raw value */
async function hashToken(raw: string): Promise<string> {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(raw));
  return Array.from(new Uint8Array(buf)).map((b) => b.toString(16).padStart(2, "0")).join("");
}

/** Send a password-reset email via Resend. Falls back to console.log when RESEND_API_KEY is absent. */
async function sendResetEmail(to: string, resetUrl: string): Promise<void> {
  const key = Deno.env.get("RESEND_API_KEY");
  if (!key) {
    console.log(`[dev] Password-reset link for ${to}: ${resetUrl}`);
    return;
  }
  const from = Deno.env.get("RESEND_FROM") ?? "noreply@brightpath.app";
  const res = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: { "Authorization": `Bearer ${key}`, "Content-Type": "application/json" },
    body: JSON.stringify({
      from,
      to: [to],
      subject: "Reset your Dental Dashboard password",
      html: `<p>Hi,</p>
<p>Click the link below to reset your password. It expires in 60 minutes.</p>
<p><a href="${resetUrl}">${resetUrl}</a></p>
<p>If you didn't request this, you can safely ignore this email.</p>`,
    }),
  });
  if (!res.ok) {
    const body = await res.text().catch(() => "");
    console.error(`Resend error ${res.status}: ${body}`);
  }
}

export default handler(async (req) => {
  const [a, b] = subpath(req, "auth"); // /auth/login | /auth/register | /auth/users | /auth/users/:id

  // POST /auth/register -> creates a NEW clinic + its first admin. Never accepts a clinic_id.
  if (a === "register" && req.method === "POST") {
    await rateLimit(`register:ip:${clientIp(req)}`, 5, 3600);
    const body = registerBody.parse(await readJson(req));

    // Public sign-up would let anyone on the internet open clinics: it stays OFF until REGISTRATION_KEY is set.
    const regKey = Deno.env.get("REGISTRATION_KEY");
    if (!regKey) throw new HttpError(403, "Registration is disabled");
    if (!(body.registration_key && await safeEqual(body.registration_key, regKey))) {
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
    const userKey = `login:user:${body.username}`;
    await rateLimit(userKey, 8, LOGIN_WINDOW);

    const { rows } = await query(
      `SELECT ${PUBLIC_USER}, password_hash, is_active FROM app_users WHERE lower(username) = $1`,
      [body.username],
    );
    const u = rows[0];
    const ok = await bcrypt.compare(body.password, u?.password_hash ?? DUMMY_HASH); // always runs
    if (!u || !ok || u.is_active !== true || u.clinic_id == null) {
      throw new HttpError(401, "Invalid username or password"); // identical for every failure mode
    }
    await clearRateLimit(userKey); // a successful sign-in must not count towards the lockout
    const { password_hash: _h, is_active: _a, ...user } = u;
    return json({ token: await signToken(user), user });
  }

  // GET /auth/me -> the signed-in user as the database sees them right now (role changes show up here)
  if (a === "me" && !b && req.method === "GET") {
    const s = await authorize(req, { bucket: "me", limit: 60 });
    const { rows } = await query(`SELECT ${PUBLIC_USER} FROM app_users WHERE id = $1 AND clinic_id = $2`, [s.id, s.clinic_id]);
    if (!rows[0]) throw new HttpError(401, "Unauthorized");
    return json({ user: rows[0] });
  }

  // POST /auth/forgot-password { email }
  // Always returns 200 so the caller can't tell whether the account exists.
  if (a === "forgot-password" && req.method === "POST") {
    await rateLimit(`forgot:ip:${clientIp(req)}`, 5, 3600);
    const body = forgotPasswordBody.parse(await readJson(req));

    const { rows } = await query(
      `SELECT id, email FROM app_users WHERE lower(email) = $1 AND is_active = true LIMIT 1`,
      [body.email],
    );
    const user = rows[0] as { id: number; email: string } | undefined;

    if (user) {
      // Invalidate any previous unused tokens for this user
      await query(
        `UPDATE password_reset_tokens SET used = true WHERE user_id = $1 AND used = false`,
        [user.id],
      );

      // Generate a cryptographically random 48-byte token (URL-safe base64 = 64 chars)
      const raw = btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(48))))
        .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
      const hash = await hashToken(raw);
      const expiresAt = new Date(Date.now() + 60 * 60 * 1000).toISOString(); // 60 min

      await query(
        `INSERT INTO password_reset_tokens (user_id, token_hash, expires_at) VALUES ($1, $2, $3)`,
        [user.id, hash, expiresAt],
      );

      const appUrl = Deno.env.get("APP_URL") ?? "https://brightpath-customer-compass.lovable.app";
      const resetUrl = `${appUrl}/reset-password?token=${raw}`;
      await sendResetEmail(user.email, resetUrl);
    }

    // Always the same response — never reveal whether the account exists
    return json({ ok: true, message: "If that account exists, a reset link has been sent." });
  }

  // POST /auth/reset-password { token, password }
  if (a === "reset-password" && req.method === "POST") {
    await rateLimit(`reset:ip:${clientIp(req)}`, 10, 3600);
    const body = resetPasswordBody.parse(await readJson(req));
    const hash = await hashToken(body.token);

    const { rows } = await query(
      `SELECT prt.id AS token_id, prt.user_id, prt.expires_at, prt.used
         FROM password_reset_tokens prt
        WHERE prt.token_hash = $1
        LIMIT 1`,
      [hash],
    );
    const row = rows[0] as { token_id: number; user_id: number; expires_at: string; used: boolean } | undefined;

    if (!row || row.used || new Date(row.expires_at) <= new Date()) {
      throw new HttpError(400, "Reset link is invalid or has expired.");
    }

    const newHash = await bcrypt.hash(body.password, COST);
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      await client.query(
        `UPDATE app_users SET password_hash = $1 WHERE id = $2`,
        [newHash, row.user_id],
      );
      await client.query(
        `UPDATE password_reset_tokens SET used = true WHERE id = $1`,
        [row.token_id],
      );
      await client.query("COMMIT");
    } catch (e) {
      await client.query("ROLLBACK");
      throw e;
    } finally {
      client.release();
    }

    return json({ ok: true, message: "Password updated. You can now sign in." });
  }

  // GET /auth/users (admin): every user of THEIR clinic
  if (a === "users" && !b && req.method === "GET") {
    const s = await authorize(req, { roles: ["admin"], bucket: "users", limit: 60 });
    const { rows } = await query(`SELECT ${MANAGED_USER} FROM app_users WHERE clinic_id = $1 ORDER BY id`, [s.clinic_id]);
    return json({ data: rows });
  }

  // POST /auth/users (admin adds staff to THEIR clinic)
  if (a === "users" && !b && req.method === "POST") {
    const s = await authorize(req, { roles: ["admin"], bucket: "users", limit: 60 });
    const body = createUserBody.parse(await readJson(req));
    const dup = await query("SELECT 1 FROM app_users WHERE lower(username) = $1", [body.username]);
    if (dup.rowCount) throw new HttpError(409, "Username already taken");
    const hash = await bcrypt.hash(body.password, COST);
    const { rows } = await query(
      `INSERT INTO app_users (username, password_hash, name, role, clinic_id)
       VALUES ($1, $2, $3, $4, $5) RETURNING ${MANAGED_USER}`,
      [body.username, hash, body.name, body.role, s.clinic_id], // clinic from verified session
    );
    audit("user_created", s, { target: rows[0].id, role: body.role });
    return json({ user: rows[0] }, 201);
  }

  // PATCH /auth/users/:id  { is_active?, role?, name? } (takes effect on the user's very next request)
  if (a === "users" && b && req.method === "PATCH") {
    const s = await authorize(req, { roles: ["admin"], bucket: "users", limit: 60 });
    const id = idParam.parse(b);
    const body = updateUserBody.parse(await readJson(req));
    if (id === s.id && (body.is_active !== undefined || body.role !== undefined)) {
      throw new HttpError(400, "You can't change your own role or status");
    }
    const fields = (["name", "role", "is_active"] as const).filter((k) => body[k] !== undefined);
    const sets = fields.map((col, i) => `${col} = $${i + 1}`); // column names are constants
    const params: unknown[] = [...fields.map((k) => body[k]), id, s.clinic_id];
    const { rows } = await query(
      `UPDATE app_users SET ${sets.join(", ")}
       WHERE id = $${params.length - 1} AND clinic_id = $${params.length} RETURNING ${MANAGED_USER}`,
      params,
    );
    if (!rows[0]) throw new HttpError(404, "Not found"); // another clinic's id looks identical to a missing id
    audit("user_updated", s, { target: id, fields });
    return json({ user: rows[0] });
  }

  throw new HttpError(404, "Not found");
});

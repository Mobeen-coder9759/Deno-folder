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
const MANAGED_USER = `${PUBLIC_USER}, email, is_active, created_at`; // what the admin's user list shows
const RESET_INVALID = "Reset link is invalid or has expired.";

const norm = (s: string) => s.trim().toLowerCase();

/** Postgres unique-violation (23505), for both node-pg and deno-postgres error shapes. */
function isUniqueViolation(e: unknown): boolean {
  const x = e as { code?: string; fields?: { code?: string } } | null;
  return x?.code === "23505" || x?.fields?.code === "23505";
}

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
  const from = Deno.env.get("RESEND_FROM");
  if (!from) {
    // No silent fallback to an unverified sender: Resend would reject it and nobody would notice.
    console.error("RESEND_FROM is not set; reset email was NOT sent");
    return;
  }
  const res = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: { "Authorization": `Bearer ${key}`, "Content-Type": "application/json" },
    signal: AbortSignal.timeout(10_000), // a hung provider must not hang the request
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

/** Creates a fresh reset token (invalidating older ones, atomically) and emails the link. */
async function issueResetLink(user: { id: number; email: string }): Promise<void> {
  // 48 random bytes, URL-safe base64
  const raw = btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(48))))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  const tokenHash = await hashToken(raw);
  const expiresAt = new Date(Date.now() + 60 * 60 * 1000).toISOString(); // 60 min

  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await client.query(
      `UPDATE password_reset_tokens SET used = true WHERE user_id = $1 AND used = false`,
      [user.id],
    );
    await client.query(
      `INSERT INTO password_reset_tokens (user_id, token_hash, expires_at) VALUES ($1, $2, $3)`,
      [user.id, tokenHash, expiresAt],
    );
    await client.query("COMMIT");
  } catch (e) {
    await client.query("ROLLBACK");
    throw e;
  } finally {
    client.release();
  }

  const appUrl = (Deno.env.get("APP_URL") ?? "https://brightpath-customer-compass.lovable.app").replace(/\/+$/, "");
  await sendResetEmail(user.email, `${appUrl}/reset-password?token=${raw}`);
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
      // Login accepts username OR email, so a username must not equal anyone's email either.
      const dup = await client.query(
        "SELECT 1 FROM app_users WHERE lower(username) = $1 OR lower(email) = $1",
        [norm(body.username)],
      );
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
      // two simultaneous sign-ups with the same name: the unique index catches it, answer 409 not 500
      if (isUniqueViolation(e)) throw new HttpError(409, "Username already taken");
      throw e;
    } finally {
      client.release();
    }
  }

  // POST /auth/login  { username }  <- accepts a username OR an email in that one field
  if (a === "login" && req.method === "POST") {
    await rateLimit(`login:ip:${clientIp(req)}`, 30, LOGIN_WINDOW);
    const body = loginBody.parse(await readJson(req));
    const ident = norm(body.username);
    // Per-identifier limit is the real brute-force defense (IP headers can be spoofed)
    const userKey = `login:user:${ident}`;
    await rateLimit(userKey, 8, LOGIN_WINDOW);

    const { rows } = await query(
      `SELECT ${PUBLIC_USER}, password_hash, is_active FROM app_users
        WHERE lower(username) = $1 OR lower(email) = $1
        ORDER BY (lower(username) = $1) DESC
        LIMIT 1`,
      [ident],
    );
    const u = rows[0];
    // The same account reached via its username AND via its email shares ONE lockout counter,
    // otherwise an attacker would get 8 guesses per identifier instead of 8 total.
    const acctKey = u ? `login:acct:${u.id}` : null;
    if (acctKey) await rateLimit(acctKey, 8, LOGIN_WINDOW);

    const ok = await bcrypt.compare(body.password, u?.password_hash ?? DUMMY_HASH); // always runs
    if (!u || !ok || u.is_active !== true || u.clinic_id == null) {
      throw new HttpError(401, "Invalid username or password"); // identical for every failure mode
    }
    await clearRateLimit(userKey); // a successful sign-in must not count towards the lockout
    if (acctKey) await clearRateLimit(acctKey);
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
    const email = norm(body.email);
    await rateLimit(`forgot:email:${email}`, 3, 3600); // stops someone flooding one inbox from many IPs

    const { rows } = await query(
      `SELECT id, email FROM app_users WHERE lower(email) = $1 AND is_active = true LIMIT 1`,
      [email],
    );
    const user = rows[0] as { id: number; email: string } | undefined;

    if (user) {
      // Fire-and-forget: the DB writes + email call would otherwise make "account exists"
      // measurably slower than "account doesn't exist". Errors are logged, never shown to the caller.
      issueResetLink(user).catch((e) => console.error("forgot-password failed:", e));
    }

    // Always the same response — never reveal whether the account exists
    return json({ ok: true, message: "If that account exists, a reset link has been sent." });
  }

  // POST /auth/reset-password { token, password }
  if (a === "reset-password" && req.method === "POST") {
    await rateLimit(`reset:ip:${clientIp(req)}`, 10, 3600);
    const body = resetPasswordBody.parse(await readJson(req));
    const tokenHash = await hashToken(body.token);
    const now = new Date().toISOString();

    // Cheap pre-check so junk tokens don't make us run bcrypt
    const pre = await query(
      `SELECT 1 FROM password_reset_tokens WHERE token_hash = $1 AND used = false AND expires_at > $2 LIMIT 1`,
      [tokenHash, now],
    );
    if (!pre.rows[0]) throw new HttpError(400, RESET_INVALID);

    const newHash = await bcrypt.hash(body.password, COST);
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      // Atomic claim: if two requests race with the same link, exactly one gets a row back
      const claim = await client.query(
        `UPDATE password_reset_tokens SET used = true
          WHERE token_hash = $1 AND used = false AND expires_at > $2
          RETURNING user_id`,
        [tokenHash, now],
      );
      if (!claim.rows[0]) throw new HttpError(400, RESET_INVALID);
      const userId = claim.rows[0].user_id as number;

      const upd = await client.query(
        `UPDATE app_users SET password_hash = $1 WHERE id = $2 AND is_active = true RETURNING id`,
        [newHash, userId],
      );
      if (!upd.rows[0]) throw new HttpError(400, RESET_INVALID); // account was deactivated after the link was sent

      // Any other outstanding links for this user die with this reset
      await client.query(
        `UPDATE password_reset_tokens SET used = true WHERE user_id = $1 AND used = false`,
        [userId],
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

  // POST /auth/users (admin adds staff to THEIR clinic)  { username, password, name, role, email? }
  if (a === "users" && !b && req.method === "POST") {
    const s = await authorize(req, { roles: ["admin"], bucket: "users", limit: 60 });
    const body = createUserBody.parse(await readJson(req));
    // email is read loosely so this compiles before/after you add it to createUserBody in validate.ts
    const rawEmail = (body as { email?: string | null }).email;
    const email = rawEmail ? norm(rawEmail) : null;
    const username = norm(body.username);

    // username and email share one namespace because login accepts either
    const dup = await query(
      `SELECT 1 FROM app_users
        WHERE lower(username) = $1 OR lower(email) = $1
           OR ($2::text IS NOT NULL AND (lower(username) = $2 OR lower(email) = $2))
        LIMIT 1`,
      [username, email],
    );
    if (dup.rowCount) throw new HttpError(409, "Username or email already in use");

    const hash = await bcrypt.hash(body.password, COST);
    try {
      const { rows } = await query(
        `INSERT INTO app_users (username, password_hash, name, role, clinic_id, email)
         VALUES ($1, $2, $3, $4, $5, $6) RETURNING ${MANAGED_USER}`,
        [body.username, hash, body.name, body.role, s.clinic_id, email], // clinic from verified session
      );
      audit("user_created", s, { target: rows[0].id, role: body.role });
      return json({ user: rows[0] }, 201);
    } catch (e) {
      if (isUniqueViolation(e)) throw new HttpError(409, "Username or email already in use");
      throw e;
    }
  }

  // PATCH /auth/users/:id  { is_active?, role?, name?, email? } (takes effect on the user's very next request)
  if (a === "users" && b && req.method === "PATCH") {
    const s = await authorize(req, { roles: ["admin"], bucket: "users", limit: 60 });
    const id = idParam.parse(b);
    const body = updateUserBody.parse(await readJson(req));
    const patch = body as { name?: string; role?: string; is_active?: boolean; email?: string | null };
    if (id === s.id && (patch.is_active !== undefined || patch.role !== undefined)) {
      throw new HttpError(400, "You can't change your own role or status");
    }

    // Column names below are constants, values are always bound parameters
    const entries: [string, unknown][] = [];
    if (patch.name !== undefined) entries.push(["name", patch.name]);
    if (patch.role !== undefined) entries.push(["role", patch.role]);
    if (patch.is_active !== undefined) entries.push(["is_active", patch.is_active]);
    if (patch.email !== undefined) entries.push(["email", patch.email ? norm(patch.email) : null]);
    if (!entries.length) throw new HttpError(400, "Nothing to update"); // an empty SET list is invalid SQL (used to be a 500)

    const newEmail = patch.email ? norm(patch.email) : null;
    if (newEmail) {
      const taken = await query(
        `SELECT 1 FROM app_users WHERE id <> $2 AND (lower(email) = $1 OR lower(username) = $1) LIMIT 1`,
        [newEmail, id],
      );
      if (taken.rowCount) throw new HttpError(409, "Email already in use");
    }

    const sets = entries.map(([col], i) => `${col} = $${i + 1}`);
    const params: unknown[] = [...entries.map(([, v]) => v), id, s.clinic_id];
    try {
      const { rows } = await query(
        `UPDATE app_users SET ${sets.join(", ")}
         WHERE id = $${params.length - 1} AND clinic_id = $${params.length} RETURNING ${MANAGED_USER}`,
        params,
      );
      if (!rows[0]) throw new HttpError(404, "Not found"); // another clinic's id looks identical to a missing id
      audit("user_updated", s, { target: id, fields: entries.map(([col]) => col) });
      return json({ user: rows[0] });
    } catch (e) {
      if (isUniqueViolation(e)) throw new HttpError(409, "Email already in use");
      throw e;
    }
  }

  throw new HttpError(404, "Not found");
});

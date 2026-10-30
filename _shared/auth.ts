import { SignJWT, jwtVerify } from "npm:jose@5.2.4";
import { HttpError } from "./http.ts";
import { query } from "./db.ts";
import { rateLimit } from "./ratelimit.ts";

const ISSUER = "fresh-start-api";
const AUDIENCE = "fresh-start-app";
const TTL = Deno.env.get("JWT_TTL") ?? "8h";

function key(): Uint8Array {
  const s = Deno.env.get("JWT_SECRET") ?? "";
  if (s.length < 32) throw new Error("JWT_SECRET missing or too short"); // fail closed (-> 500)
  return new TextEncoder().encode(s);
}

export type Session = { id: number; clinic_id: number; role: string };

export const signToken = (s: Session) =>
  new SignJWT({ id: s.id, clinic_id: s.clinic_id, role: s.role })
    .setProtectedHeader({ alg: "HS256", typ: "JWT" })
    .setIssuer(ISSUER).setAudience(AUDIENCE).setSubject(String(s.id))
    .setIssuedAt().setExpirationTime(TTL)
    .sign(key());

/**
 * 1. Verify signature (HS256 only), issuer, audience, expiry
 * 2. Rate-limit per user
 * 3. Re-check the user in the DB (active? same clinic?) and use the DB's role + clinic_id as truth,
 *    so deactivating a user or changing their role takes effect immediately.
 */
export async function authorize(
  req: Request,
  opts: { roles?: string[]; bucket?: string; limit?: number } = {},
): Promise<Session> {
  const m = /^Bearer ([\w-]+\.[\w-]+\.[\w-]+)$/.exec(req.headers.get("Authorization") ?? "");
  if (!m) throw new HttpError(401, "Unauthorized");

  const secret = key();
  let claims;
  try {
    ({ payload: claims } = await jwtVerify(m[1], secret, {
      algorithms: ["HS256"], issuer: ISSUER, audience: AUDIENCE,
    }));
  } catch {
    throw new HttpError(401, "Unauthorized");
  }

  const id = Number(claims.id);
  if (!Number.isInteger(id)) throw new HttpError(401, "Unauthorized");

  await rateLimit(`${opts.bucket ?? "api"}:u${id}`, opts.limit ?? 120, 60);

  const { rows } = await query(
    "SELECT id, clinic_id, role FROM app_users WHERE id = $1 AND is_active IS TRUE AND clinic_id IS NOT NULL",
    [id],
  );
  const u = rows[0];
  if (!u || u.clinic_id !== Number(claims.clinic_id)) throw new HttpError(401, "Unauthorized");

  const session: Session = { id: u.id, clinic_id: u.clinic_id, role: u.role };
  if (opts.roles && !opts.roles.includes(session.role)) throw new HttpError(403, "Forbidden");
  return session;
}

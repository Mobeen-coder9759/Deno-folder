import { ZodError } from "npm:zod@3.23.8";

export class HttpError extends Error {
  constructor(
    public status: number,
    message: string,
    public headers: Record<string, string> = {},
    public details?: unknown,
  ) { super(message); }
}

// ---------- CORS: strict allowlist, no wildcard fallback ----------
const ORIGIN_PATTERNS = (Deno.env.get("ALLOWED_ORIGINS") ?? "")
  .split(",").map((s) => s.trim()).filter(Boolean)
  .map((o) => new RegExp(
    "^" + o.replace(/[.+?^${}()|[\]\\]/g, "\\$&").replace(/\*/g, "[a-z0-9-]+") + "$", "i"));

const allowedOrigin = (origin: string | null) =>
  origin && ORIGIN_PATTERNS.some((re) => re.test(origin)) ? origin : null;

function finalize(res: Response, origin: string | null, preflight = false): Response {
  const h = res.headers;
  h.set("Cache-Control", "no-store");            // patient data must never be cached
  h.set("X-Content-Type-Options", "nosniff");
  if (origin) {
    h.set("Access-Control-Allow-Origin", origin);
    h.append("Vary", "Origin");
    if (preflight) {
      h.set("Access-Control-Allow-Headers", "authorization, content-type");
      h.set("Access-Control-Allow-Methods", "GET, POST, PATCH, DELETE, OPTIONS");
      h.set("Access-Control-Max-Age", "86400");
    }
  }
  return res;
}

export const json = (data: unknown, status = 200) =>
  new Response(JSON.stringify(data), { status, headers: { "Content-Type": "application/json" } });

function errorResponse(e: any): Response {
  if (e instanceof HttpError) {
    const r = json({ error: e.message, details: e.details }, e.status);
    for (const [k, v] of Object.entries(e.headers)) r.headers.set(k, v);
    return r;
  }
  if (e instanceof ZodError) {
    return json({
      error: "Validation failed",
      details: e.issues.map((i) => ({ field: i.path.join("."), message: i.message })),
    }, 400);
  }
  if (e?.code === "23505") return json({ error: "Already exists" }, 409);
  if (String(e?.code ?? "").startsWith("22")) return json({ error: "Invalid input" }, 400);
  console.error("unhandled", e?.code ?? "", e?.message); // detail stays in server logs only
  return json({ error: "Internal server error" }, 500);
}

export function handler(fn: (req: Request) => Promise<Response>) {
  return async (req: Request): Promise<Response> => {
    const originHeader = req.headers.get("Origin");
    const origin = allowedOrigin(originHeader);
    // Browser request from an origin that isn't allowlisted: refuse before doing any work.
    // (No Origin header = server-to-server / n8n, which still has to pass auth.)
    if (originHeader && !origin) return finalize(json({ error: "Origin not allowed" }, 403), null);
    if (req.method === "OPTIONS") return finalize(new Response(null, { status: 204 }), origin, true);
    try {
      return finalize(await fn(req), origin);
    } catch (e) {
      return finalize(errorResponse(e), origin);
    }
  };
}

// ---------- Input helpers ----------
const MAX_BODY = 10_000; // bytes of JSON; nothing here needs more

export async function readJson(req: Request): Promise<unknown> {
  if (!(req.headers.get("content-type") ?? "").toLowerCase().startsWith("application/json")) {
    throw new HttpError(415, "Content-Type must be application/json");
  }
  if (Number(req.headers.get("content-length") ?? 0) > MAX_BODY) throw new HttpError(413, "Body too large");
  const text = await req.text();
  if (text.length > MAX_BODY) throw new HttpError(413, "Body too large");
  try { return JSON.parse(text); } catch { throw new HttpError(400, "Invalid JSON"); }
}

// "/appointments/12" -> ["12"]
export function subpath(req: Request, fn: string): string[] {
  const parts = new URL(req.url).pathname.split("/").filter(Boolean);
  const i = parts.indexOf(fn);
  return i === -1 ? [] : parts.slice(i + 1);
}

export const queryParams = (req: Request) => Object.fromEntries(new URL(req.url).searchParams);

// Heroku's router APPENDS the real client address to the END of X-Forwarded-For; every entry before it is whatever
// the client sent. So we use the last entry (never the first) and ignore cf-connecting-ip, which a client can set
// freely when we're not behind Cloudflare. Used only for rate limiting, never for authorization.
export function clientIp(req: Request): string {
  const parts = (req.headers.get("x-forwarded-for") ?? "").split(",").map((p) => p.trim()).filter(Boolean);
  return (parts[parts.length - 1] ?? "unknown").slice(0, 64);
}

export const audit = (
  event: string,
  s: { id: number; clinic_id: number },
  extra: Record<string, unknown> = {},
) => console.info(JSON.stringify({ audit: event, user: s.id, clinic: s.clinic_id, ...extra, at: new Date().toISOString() }));

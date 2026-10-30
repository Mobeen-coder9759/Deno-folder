// Single entrypoint for Deno Deploy or Heroku (or `deno run -A --env-file=.env main.ts` locally).
import { handler, json, HttpError } from "./_shared/http.ts";
import auth from "./functions/auth.ts";
import appointments from "./functions/appointments.ts";
import patients from "./functions/patients.ts";
import analytics from "./functions/analytics.ts";
import settings from "./functions/settings.ts";

const routes = new Map<string, (req: Request) => Promise<Response>>([
  ["auth", auth],
  ["appointments", appointments],
  ["patients", patients],
  ["analytics", analytics],
  ["settings", settings],
]);

// /health + unknown paths (still gets CORS/security headers + clean JSON errors)
const fallback = handler(async (req) => {
  if (new URL(req.url).pathname === "/health") return json({ ok: true });
  throw new HttpError(404, "Not found");
});

// Get the port from Heroku's environment variables, or fallback to 8000 for local testing
const port = Number(Deno.env.get("PORT")) || 8000;

// Start the server on the exact port Heroku requires
Deno.serve({ port }, (req) => {
  const first = new URL(req.url).pathname.split("/").filter(Boolean)[0] ?? "";
  return (routes.get(first) ?? fallback)(req);
});

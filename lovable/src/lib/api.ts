// Set VITE_API_BASE_URL, or replace the fallback below with your deployed API URL (no trailing slash).
const BASE = (
  (import.meta.env.VITE_API_BASE_URL as string | undefined) ?? "https://YOUR-APP.deno.dev"
).replace(/\/+$/, "");

const TOKEN_KEY = "fs_token";
export const tokenStore = {
  get: () => localStorage.getItem(TOKEN_KEY),
  set: (t: string) => localStorage.setItem(TOKEN_KEY, t),
  clear: () => localStorage.removeItem(TOKEN_KEY),
};

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
    public details?: { field: string; message: string }[],
    public retryAfter?: number, // seconds, set on 429
  ) { super(message); }
}

async function request<T>(
  path: string,
  opts: { method?: string; body?: unknown; auth?: boolean } = {},
): Promise<T> {
  const headers: Record<string, string> = {};
  if (opts.body !== undefined) headers["Content-Type"] = "application/json";
  const token = tokenStore.get();
  if (opts.auth !== false && token) headers.Authorization = `Bearer ${token}`;

  const res = await fetch(`${BASE}${path}`, {
    method: opts.method ?? "GET",
    headers,
    body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
  });
  const data = await res.json().catch(() => null);

  if (!res.ok) {
    if (res.status === 401 && opts.auth !== false) {
      tokenStore.clear();
      window.dispatchEvent(new Event("auth:logout"));
    }
    throw new ApiError(
      res.status,
      data?.error ?? res.statusText,
      data?.details,
      Number(res.headers.get("Retry-After")) || undefined,
    );
  }
  return data as T;
}

const qs = (p: Record<string, string | number | undefined | null>) => {
  const q = new URLSearchParams();
  Object.entries(p).forEach(([k, v]) => v != null && v !== "" && q.set(k, String(v)));
  const s = q.toString();
  return s ? `?${s}` : "";
};

// ---- Types ----
export type User = { id: number; clinic_id: number; role: "admin" | "staff" | "hr"; username: string; name: string };
export type Appointment = {
  id: number; name: string; phone: string | null; email: string | null; dob: string | null;
  insurance: string | null; reason: string | null; booking_type: string | null;
  booking_time: string | null; old_time: string | null; cancel_time: string | null;
  created_at: string; updated_at: string; status: "scheduled" | "cancelled";
};
export type AppointmentInput = { name: string; booking_time: string } &
  Partial<Pick<Appointment, "phone" | "email" | "dob" | "insurance" | "reason" | "booking_type" | "old_time" | "cancel_time">>;
export type PatientRow = {
  name: string; phone: string | null; email: string | null; dob: string | null;
  insurance: string | null; total_appointments: number; last_appointment: string | null;
};
export type Analytics = {
  reasons: { reason: string; count: number }[];
  bookings: { date: string; count: number }[];
};

// ---- Auth ----
export const authApi = {
  async login(username: string, password: string) {
    const r = await request<{ token: string; user: User }>("/auth/login", { method: "POST", body: { username, password }, auth: false });
    tokenStore.set(r.token);
    return r.user;
  },
  async register(p: { username: string; password: string; name: string; clinic_name: string; registration_key?: string }) {
    const r = await request<{ token: string; user: User }>("/auth/register", { method: "POST", body: p, auth: false });
    tokenStore.set(r.token);
    return r.user;
  },
  addUser: (p: { username: string; password: string; name: string; role: User["role"] }) =>
    request<{ user: User }>("/auth/users", { method: "POST", body: p }),
  setUserActive: (id: number, is_active: boolean) =>
    request<{ user: User }>(`/auth/users/${id}`, { method: "PATCH", body: { is_active } }),
  logout() { tokenStore.clear(); window.dispatchEvent(new Event("auth:logout")); },
};

// ---- Appointments ----
export const appointmentsApi = {
  list: (f: { date?: string; reason?: string; search?: string; limit?: number; offset?: number } = {}) =>
    request<{ data: Appointment[] }>(`/appointments${qs(f)}`).then((r) => r.data),
  create: (b: AppointmentInput) =>
    request<{ data: Appointment }>("/appointments", { method: "POST", body: b }).then((r) => r.data),
  update: (id: number, b: Partial<AppointmentInput>) =>
    request<{ data: Appointment }>(`/appointments/${id}`, { method: "PATCH", body: b }).then((r) => r.data),
  cancel: (id: number) =>
    request<{ data: Appointment }>(`/appointments/${id}`, { method: "PATCH", body: { cancel_time: new Date().toISOString() } }).then((r) => r.data),
  remove: (id: number) => request<{ ok: true }>(`/appointments/${id}`, { method: "DELETE" }),
};

// ---- Patients ----
export const patientsApi = {
  list: (f: { sort?: "asc" | "desc"; search?: string; limit?: number; offset?: number } = {}) =>
    request<{ data: PatientRow[] }>(`/patients${qs(f)}`).then((r) => r.data),
  update: (p: { name: string; phone: string | null; new_name?: string; new_phone?: string | null; email?: string | null; dob?: string | null; insurance?: string | null }) =>
    request<{ updated: number }>("/patients", { method: "PATCH", body: p }),
  remove: (name: string, phone: string | null) =>
    request<{ deleted: number }>(`/patients${qs({ name, phone })}`, { method: "DELETE" }),
};

// ---- Analytics ----
export const analyticsApi = {
  get: (days = 30) => request<Analytics>(`/analytics${qs({ days })}`),
};

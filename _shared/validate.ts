import { z } from "npm:zod@3.23.8";

const noControl = (s: string) => !/[\u0000-\u001f\u007f]/.test(s); // Postgres also rejects NUL bytes
const text = (max: number) => z.string().trim().min(1).max(max).refine(noControl, "Invalid characters");
const optText = (max: number) =>
  z.string().trim().max(max).refine(noControl, "Invalid characters").transform((v) => v || null).nullable();

// 6-30 characters: digits, spaces, ( ) . - and an optional leading +, with at least 6 digits
// (one regex on purpose, so a bad value produces exactly one error message). Matches varchar(30).
const PHONE_RE = /^\+?(?=(?:[^0-9]*[0-9]){6})[0-9 ().-]{6,30}$/;
const phone = z.union([
  z.literal("").transform(() => null),
  z.string().trim().max(30).regex(PHONE_RE, "Invalid phone number"),
]).nullable();

const email = z.union([
  z.literal("").transform(() => null),
  z.string().trim().toLowerCase().max(255).email(),
]).nullable();

const dateOnly = z.string().regex(/^\d{4}-\d{2}-\d{2}$/, "Use YYYY-MM-DD")
  .refine((s) => !Number.isNaN(Date.parse(s)) && new Date(s).toISOString().startsWith(s), "Invalid date");

const dob = dateOnly
  .refine((s) => s >= "1900-01-01" && s <= new Date().toISOString().slice(0, 10), "Invalid date of birth")
  .nullable();

const datetime = z.string().datetime({ offset: true });
const bookingType = z.string().trim().regex(/^[A-Za-z0-9 _-]{1,50}$/, "Invalid booking_type").nullable();

export const idParam = z.string().regex(/^\d{1,9}$/, "Invalid id").transform(Number).refine((n) => n > 0, "Invalid id");

// ---------- Appointments ----------
const apptFields = {
  name: text(150),
  booking_time: datetime,
  phone, email, dob,
  insurance: optText(150),
  reason: optText(1000),
  booking_type: bookingType,
  old_time: datetime.nullable(),
  cancel_time: datetime.nullable(),
};
export const appointmentCreate = z.object(apptFields).partial({
  phone: true, email: true, dob: true, insurance: true, reason: true,
  booking_type: true, old_time: true, cancel_time: true,
}).strict();
export const appointmentUpdate = z.object(apptFields).partial().strict()
  .refine((o) => Object.keys(o).length > 0, "Nothing to update");

const search = z.string().trim().max(100).refine(noControl, "Invalid characters");
export const appointmentsQuery = z.object({
  date: dateOnly.optional(),
  reason: search.optional(),
  search: search.optional(),
  limit: z.coerce.number().int().min(1).max(1000).default(200),
  offset: z.coerce.number().int().min(0).max(100000).default(0),
}).strict();

// ---------- Patients ----------
export const patientsQuery = z.object({
  sort: z.enum(["asc", "desc"]).default("asc"),
  search: search.optional(),
  limit: z.coerce.number().int().min(1).max(500).default(200),
  offset: z.coerce.number().int().min(0).max(100000).default(0),
}).strict();

export const patientUpdate = z.object({
  name: text(150),
  phone,                               // required key (nullable) -> identifies the patient explicitly
  new_name: text(150).optional(),
  new_phone: phone.optional(),
  email: email.optional(),
  dob: dob.optional(),
  insurance: optText(150).optional(),
}).strict().refine(
  (o) => ["new_name", "new_phone", "email", "dob", "insurance"].some((k) => k in o),
  "Nothing to update",
);
export const patientKeyQuery = z.object({ name: text(150), phone: phone.optional() }).strict();

// ---------- Analytics ----------
export const analyticsQuery = z.object({ days: z.coerce.number().int().min(1).max(365).default(30) }).strict();

// ---------- Auth ----------
const username = z.string().trim().toLowerCase().regex(/^[a-z0-9._-]{3,50}$/, "3-50 chars: letters, digits, . _ -");
const newPassword = z.string().min(10, "Min 10 characters").max(128)
  .refine((s) => new TextEncoder().encode(s).length <= 72, "Max 72 bytes (bcrypt limit)");

export const registerBody = z.object({
  username, password: newPassword, name: text(100), clinic_name: text(150),
  registration_key: z.string().max(200).optional(),
}).strict();
export const loginBody = z.object({
  username: z.string().trim().toLowerCase().min(1).max(50), // no format rule: don't lock out legacy usernames
  password: z.string().min(1).max(128),
}).strict();
export const createUserBody = z.object({
  username, password: newPassword, name: text(100), role: z.enum(["admin", "staff", "hr"]),
}).strict();
export const updateUserBody = z.object({
  is_active: z.boolean(), role: z.enum(["admin", "staff", "hr"]), name: text(100),
}).partial().strict().refine((o) => Object.keys(o).length > 0, "Nothing to update");

// ---------- Settings ----------
const money = z.number().finite().min(0).max(1_000_000);
export const settingsBody = z.object({
  appointment_value: money,
  hourly_cost: money,
  minutes_per_booking: z.number().finite().min(0).max(1440),
  timezone: z.string().trim().max(64).regex(/^[A-Za-z][A-Za-z0-9_+\-/]*$/, "Invalid time zone"),
}).partial().strict().refine((o) => Object.keys(o).length > 0, "Nothing to update");

export type Role = "admin" | "staff" | "hr";

/** Appointment as the UI uses it (the API's `status` is derived client-side by getStatus). */
export type Appointment = {
  id: number;
  name: string;
  phone: string | null;
  email: string | null;
  dob: string | null;
  insurance: string | null;
  reason: string | null;
  booking_type: string | null;
  booking_time: string | null;
  old_time: string | null;
  cancel_time: string | null;
  created_at: string;
  updated_at: string;
};

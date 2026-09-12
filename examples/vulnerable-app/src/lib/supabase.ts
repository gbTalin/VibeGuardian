import { createClient } from "@supabase/supabase-js";

// The assistant put the privileged key behind a public prefix so the browser
// build would stop complaining. Both of these are shipped to every visitor.
export const supabase = createClient(
  process.env.NEXT_PUBLIC_SUPABASE_URL!,
  process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY!,
);

export function isAdmin(user: any) {
  // user_metadata is writable by the signed-in user through the auth API,
  // so any account can grant itself this role.
  return user?.user_metadata?.role === "admin";
}

export async function fetchAllInvoices() {
  // Uses the service_role key, which bypasses row level security entirely.
  return supabase.from("invoices").select("*");
}

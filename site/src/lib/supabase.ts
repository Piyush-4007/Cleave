import { createClient, type SupabaseClient } from "@supabase/supabase-js";

/*
  Supabase client. Auth is optional at build/dev time: with no env vars the site still runs
  and the download falls back to the public releases page (no gate) until Supabase is wired.
  Set VITE_SUPABASE_URL and VITE_SUPABASE_ANON_KEY (both public/safe) in .env.local.
*/
const url = import.meta.env.VITE_SUPABASE_URL as string | undefined;
const anon = import.meta.env.VITE_SUPABASE_ANON_KEY as string | undefined;

export const supabase: SupabaseClient | null =
  url && anon
    ? createClient(url, anon, {
        auth: {
          // PKCE returns a ?code we exchange for a session. We do that exchange MANUALLY
          // in AuthProvider (detectSessionInUrl: false) so the exchange is deterministic
          // and its errors are visible — the built-in auto-detect swallows failures.
          flowType: "pkce",
          detectSessionInUrl: false,
          persistSession: true,
          autoRefreshToken: true,
        },
      })
    : null;

export const authConfigured = !!supabase;

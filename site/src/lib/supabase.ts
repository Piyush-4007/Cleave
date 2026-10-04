import { createClient, type SupabaseClient } from "@supabase/supabase-js";

/*
  Supabase client. Auth is optional at build/dev time: with no env vars the site still runs
  and the download falls back to the public releases page (no gate) until Supabase is wired.
  Set VITE_SUPABASE_URL and VITE_SUPABASE_ANON_KEY (both public/safe) in .env.local.
*/
// Env values pasted into a dashboard (e.g. Vercel) can pick up invisible characters —
// a trailing newline, a non-breaking space, a smart quote. A stray non-ASCII char in the
// anon key makes fetch() throw "String contains non ISO-8859-1 code point" when it builds
// the auth headers, so every authenticated call dies. Scrub to the JWT/URL charset.
const url = (import.meta.env.VITE_SUPABASE_URL as string | undefined)?.trim();
const rawAnon = import.meta.env.VITE_SUPABASE_ANON_KEY as string | undefined;
const anon = rawAnon?.trim().replace(/[^A-Za-z0-9._-]/g, "");
if (rawAnon && anon !== rawAnon.trim()) {
  console.warn("[supabase] anon key had unexpected characters — stripped before use");
}

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

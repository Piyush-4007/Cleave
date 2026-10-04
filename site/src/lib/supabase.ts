import { createClient, type SupabaseClient } from "@supabase/supabase-js";

/*
  Supabase client. Auth is optional at build/dev time: with no env vars the site still runs
  and the download falls back to the public releases page (no gate) until Supabase is wired.
  Set VITE_SUPABASE_URL and VITE_SUPABASE_ANON_KEY (both public/safe) in .env.local.
*/
const url = import.meta.env.VITE_SUPABASE_URL as string | undefined;
const anon = import.meta.env.VITE_SUPABASE_ANON_KEY as string | undefined;

export const supabase: SupabaseClient | null =
  url && anon ? createClient(url, anon) : null;

export const authConfigured = !!supabase;

import { createContext, useContext, useEffect, useState, type ReactNode } from "react";
import type { User } from "@supabase/supabase-js";
import { supabase, authConfigured } from "./supabase";

/*
  Auth state + actions, backed by Supabase. Google + GitHub OAuth and email/password.
  When Supabase isn't configured yet, `configured` is false and the UI degrades gracefully
  (the download just links to the public releases page, no gate).
*/
interface AuthCtx {
  user: User | null;
  loading: boolean;
  configured: boolean;
  signInOAuth: (provider: "google" | "github") => Promise<void>;
  signInEmail: (email: string, password: string) => Promise<void>;
  signUpEmail: (email: string, password: string) => Promise<{ needsConfirm: boolean }>;
  signOut: () => Promise<void>;
}

const Ctx = createContext<AuthCtx | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!supabase) {
      setLoading(false);
      return;
    }
    const sb = supabase;
    const { data: sub } = sb.auth.onAuthStateChange((event, session) => {
      console.log("[auth] event:", event, session?.user?.email ?? "(none)");
      setUser(session?.user ?? null);
    });

    (async () => {
      // Manually finish the OAuth redirect: exchange the ?code= for a session.
      const code = new URLSearchParams(window.location.search).get("code");
      if (code) {
        const { error } = await sb.auth.exchangeCodeForSession(code);
        if (error) console.error("[auth] exchangeCodeForSession failed:", error.message);
        else console.log("[auth] code exchanged → session stored");
        // strip ?code=&state= from the address bar either way
        window.history.replaceState({}, document.title, window.location.pathname);
      }
      const { data, error } = await sb.auth.getSession();
      if (error) console.error("[auth] getSession error:", error.message);
      console.log("[auth] initial session:", data.session?.user?.email ?? "(none)");
      setUser(data.session?.user ?? null);
      setLoading(false);
    })();

    return () => sub.subscription.unsubscribe();
  }, []);

  const signInOAuth = async (provider: "google" | "github") => {
    if (!supabase) throw new Error("Sign-in isn't configured yet.");
    const { error } = await supabase.auth.signInWithOAuth({
      provider,
      options: { redirectTo: window.location.origin },
    });
    if (error) throw error;
  };
  const signInEmail = async (email: string, password: string) => {
    if (!supabase) throw new Error("Sign-in isn't configured yet.");
    const { error } = await supabase.auth.signInWithPassword({ email, password });
    if (error) throw error;
  };
  const signUpEmail = async (email: string, password: string) => {
    if (!supabase) throw new Error("Sign-up isn't configured yet.");
    const { data, error } = await supabase.auth.signUp({ email, password });
    if (error) throw error;
    return { needsConfirm: !data.session }; // true when email confirmation is on
  };
  const signOut = async () => {
    await supabase?.auth.signOut();
  };

  return (
    <Ctx.Provider value={{ user, loading, configured: authConfigured, signInOAuth, signInEmail, signUpEmail, signOut }}>
      {children}
    </Ctx.Provider>
  );
}

// eslint-disable-next-line react-refresh/only-export-components
export function useAuth() {
  const c = useContext(Ctx);
  if (!c) throw new Error("useAuth must be used inside <AuthProvider>");
  return c;
}

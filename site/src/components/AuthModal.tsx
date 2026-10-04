import { useState } from "react";
import { X, Loader2, Mail, ArrowRight } from "lucide-react";
import { cn } from "@/lib/utils";
import { useAuth } from "@/lib/auth";

function GoogleMark() {
  return (
    <svg viewBox="0 0 24 24" className="size-[18px]" aria-hidden>
      <path fill="#4285F4" d="M23.52 12.27c0-.82-.07-1.6-.2-2.36H12v4.47h6.47a5.53 5.53 0 0 1-2.4 3.63v3h3.88c2.27-2.09 3.57-5.17 3.57-8.74z" />
      <path fill="#34A853" d="M12 24c3.24 0 5.96-1.07 7.95-2.9l-3.88-3c-1.08.72-2.45 1.15-4.07 1.15-3.13 0-5.78-2.11-6.73-4.96H1.29v3.1A12 12 0 0 0 12 24z" />
      <path fill="#FBBC05" d="M5.27 14.29a7.2 7.2 0 0 1 0-4.58v-3.1H1.29a12 12 0 0 0 0 10.78l3.98-3.1z" />
      <path fill="#EA4335" d="M12 4.75c1.77 0 3.35.61 4.6 1.8l3.44-3.44A11.97 11.97 0 0 0 12 0 12 12 0 0 0 1.29 6.61l3.98 3.1C6.22 6.86 8.87 4.75 12 4.75z" />
    </svg>
  );
}
function GithubMark() {
  return (
    <svg viewBox="0 0 24 24" className="size-[18px]" aria-hidden fill="currentColor">
      <path d="M12 .5C5.73.5.5 5.74.5 12.02c0 5.1 3.29 9.42 7.86 10.95.58.1.79-.25.79-.56v-2c-3.2.7-3.88-1.54-3.88-1.54-.53-1.34-1.29-1.7-1.29-1.7-1.05-.72.08-.7.08-.7 1.17.08 1.78 1.2 1.78 1.2 1.03 1.78 2.7 1.26 3.36.97.1-.75.4-1.26.73-1.55-2.56-.29-5.26-1.28-5.26-5.7 0-1.26.45-2.29 1.19-3.1-.12-.29-.52-1.46.11-3.05 0 0 .97-.31 3.18 1.18a11 11 0 0 1 5.8 0c2.2-1.5 3.17-1.18 3.17-1.18.63 1.59.23 2.76.11 3.05.74.81 1.19 1.84 1.19 3.1 0 4.43-2.71 5.4-5.28 5.69.41.36.78 1.06.78 2.14v3.17c0 .31.21.67.8.56A10.53 10.53 0 0 0 23.5 12.02C23.5 5.74 18.27.5 12 .5z" />
    </svg>
  );
}

export function AuthModal({ open, onClose }: { open: boolean; onClose: () => void }) {
  const { configured, signInOAuth, signInEmail, signUpEmail } = useAuth();
  const [mode, setMode] = useState<"in" | "up">("in");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState<null | "google" | "github" | "email">(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  if (!open) return null;

  const oauth = async (p: "google" | "github") => {
    setError(null);
    setBusy(p);
    try {
      await signInOAuth(p); // redirects away
    } catch (e) {
      setError(msg(e));
      setBusy(null);
    }
  };
  const email_ = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setNotice(null);
    setBusy("email");
    try {
      if (mode === "in") {
        await signInEmail(email, password);
        onClose();
      } else {
        const { needsConfirm } = await signUpEmail(email, password);
        if (needsConfirm) setNotice("Check your inbox to confirm your email, then sign in.");
        else onClose();
      }
    } catch (e) {
      setError(msg(e));
    } finally {
      setBusy(null);
    }
  };

  const oauthBtn =
    "flex w-full items-center justify-center gap-2.5 rounded-full border border-ink/15 bg-paper px-5 py-3 text-[15px] font-semibold text-ink transition-colors hover:border-ink/40 hover:bg-ink/[0.03] disabled:opacity-60";

  return (
    <div className="fixed inset-0 z-[100] flex items-center justify-center p-4">
      <div className="absolute inset-0 bg-ink/40 backdrop-blur-sm" onClick={onClose} />
      <div className="relative z-10 w-full max-w-[420px] rounded-3xl border border-ink/10 bg-paper p-7 shadow-2xl sm:p-8">
        <button onClick={onClose} className="absolute right-5 top-5 text-mute transition-colors hover:text-ink" aria-label="Close">
          <X className="size-5" />
        </button>

        <div className="font-mono text-xs uppercase tracking-[0.14em] text-mute">
          {mode === "in" ? "Sign in" : "Create account"}
        </div>
        <h2 className="display mt-2 text-[30px] leading-tight">
          {mode === "in" ? "Get Cleave, it's free." : "One account, then download."}
        </h2>
        <p className="mt-2 text-[14.5px] leading-relaxed text-mute">
          Sign in to download the desktop app. Cleave runs entirely on your machine — we never
          see your AWS account or your scans.
        </p>

        {!configured ? (
          <div className="mt-6 rounded-2xl border border-ink/10 bg-ink/[0.03] px-4 py-3 text-[13.5px] text-mute">
            Sign-in isn't switched on yet. For now you can{" "}
            <a href="https://github.com/Piyush-4007/cleave-releases/releases/latest" className="font-semibold text-ink underline">
              download from the releases page
            </a>
            .
          </div>
        ) : (
          <>
            <div className="mt-6 space-y-2.5">
              <button onClick={() => oauth("google")} disabled={busy !== null} className={oauthBtn}>
                {busy === "google" ? <Loader2 className="size-[18px] animate-spin" /> : <GoogleMark />}
                Continue with Google
              </button>
              <button onClick={() => oauth("github")} disabled={busy !== null} className={cn(oauthBtn, "bg-ink text-paper hover:bg-ink-3 hover:border-ink")}>
                {busy === "github" ? <Loader2 className="size-[18px] animate-spin" /> : <GithubMark />}
                Continue with GitHub
              </button>
            </div>

            <div className="my-5 flex items-center gap-3 text-[12px] font-mono uppercase tracking-wider text-mute">
              <span className="h-px flex-1 bg-ink/10" /> or email <span className="h-px flex-1 bg-ink/10" />
            </div>

            <form onSubmit={email_} className="space-y-2.5">
              <input
                type="email" required value={email} onChange={(e) => setEmail(e.target.value)}
                placeholder="you@company.com" autoComplete="email"
                className="w-full rounded-xl border border-ink/15 bg-paper px-4 py-3 text-[15px] text-ink outline-none placeholder:text-mute/70 focus:border-ink"
              />
              <input
                type="password" required minLength={8} value={password} onChange={(e) => setPassword(e.target.value)}
                placeholder={mode === "up" ? "Create a password (8+ chars)" : "Password"}
                autoComplete={mode === "up" ? "new-password" : "current-password"}
                className="w-full rounded-xl border border-ink/15 bg-paper px-4 py-3 text-[15px] text-ink outline-none placeholder:text-mute/70 focus:border-ink"
              />
              <button type="submit" disabled={busy !== null}
                className="flex w-full items-center justify-center gap-2 rounded-full bg-lime px-5 py-3 text-[15px] font-semibold text-ink transition-all hover:brightness-95 active:scale-[0.98] disabled:opacity-60">
                {busy === "email" ? <Loader2 className="size-[18px] animate-spin" /> : <Mail className="size-[18px]" />}
                {mode === "in" ? "Sign in" : "Create account"}
              </button>
            </form>

            <button
              onClick={() => { setMode(mode === "in" ? "up" : "in"); setError(null); setNotice(null); }}
              className="mt-4 flex w-full items-center justify-center gap-1 text-[13.5px] text-mute transition-colors hover:text-ink"
            >
              {mode === "in" ? "New here? Create an account" : "Already have an account? Sign in"}
              <ArrowRight className="size-3.5" />
            </button>
          </>
        )}

        {notice && <div className="mt-4 rounded-xl border border-lime/40 bg-lime/15 px-4 py-2.5 text-[13.5px] text-ink">{notice}</div>}
        {error && <div className="mt-4 rounded-xl border border-red-300 bg-red-50 px-4 py-2.5 text-[13.5px] text-red-700">{error}</div>}
      </div>
    </div>
  );
}

function msg(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

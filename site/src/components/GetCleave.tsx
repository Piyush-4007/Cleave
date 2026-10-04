import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from "react";
import { AuthModal } from "./AuthModal";
import { useAuth } from "@/lib/auth";
import { latestInstallerUrl, triggerDownload } from "@/lib/download";

/*
  The "Get Cleave" flow. getCleave(): if auth is off or the user is signed in, download the
  latest installer straight away; otherwise open the sign-in modal and resume the download
  once they're in. The pending intent lives in sessionStorage so it survives the OAuth
  redirect round-trip.
*/
const PENDING_KEY = "cleave_getcleave_pending";

interface GetCleaveCtx {
  getCleave: () => void;
  openAuth: () => void;
}
const Ctx = createContext<GetCleaveCtx | null>(null);

export function GetCleaveProvider({ children }: { children: ReactNode }) {
  const { user, configured } = useAuth();
  const [open, setOpen] = useState(false);

  const download = useCallback(async () => {
    triggerDownload(await latestInstallerUrl());
  }, []);

  const getCleave = useCallback(() => {
    if (!configured || user) {
      void download();
      return;
    }
    try { sessionStorage.setItem(PENDING_KEY, "1"); } catch { /* private mode */ }
    setOpen(true);
  }, [configured, user, download]);

  const openAuth = useCallback(() => setOpen(true), []);

  // resume a download the user asked for before signing in (incl. after an OAuth redirect)
  useEffect(() => {
    if (!user) return;
    let pending = false;
    try { pending = sessionStorage.getItem(PENDING_KEY) === "1"; } catch { /* ignore */ }
    if (pending) {
      try { sessionStorage.removeItem(PENDING_KEY); } catch { /* ignore */ }
      setOpen(false);
      void download();
    }
  }, [user, download]);

  return (
    <Ctx.Provider value={{ getCleave, openAuth }}>
      {children}
      <AuthModal open={open} onClose={() => {
        try { sessionStorage.removeItem(PENDING_KEY); } catch { /* ignore */ }
        setOpen(false);
      }} />
    </Ctx.Provider>
  );
}

// eslint-disable-next-line react-refresh/only-export-components
export function useGetCleave() {
  const c = useContext(Ctx);
  if (!c) throw new Error("useGetCleave must be used inside <GetCleaveProvider>");
  return c;
}

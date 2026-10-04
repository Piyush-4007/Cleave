/*
  Desktop auto-update. On launch the app asks the GitHub Releases feed whether a newer
  signed build exists; if so, a slim banner offers "Update & restart" (downloadAndInstall
  then relaunch). The Tauri plugins are dynamic-imported so the web build never touches
  them. Silent when there's no update, no endpoint, or we're offline.
*/
import { useEffect, useState } from "react";
import { ArrowClockwise, CircleNotch, Warning, X } from "@phosphor-icons/react";
import { DESKTOP } from "../desktop";

type State =
  | { kind: "idle" }
  | { kind: "available"; version: string; notes?: string; install: () => void }
  | { kind: "downloading" }
  | { kind: "error"; message: string };

export function UpdateBanner() {
  const [state, setState] = useState<State>({ kind: "idle" });
  const [dismissed, setDismissed] = useState(false);

  useEffect(() => {
    if (!DESKTOP) return;
    let cancelled = false;
    (async () => {
      try {
        const { check } = await import("@tauri-apps/plugin-updater");
        const update = await check();
        if (!update || cancelled) return;
        const install = () => {
          setState({ kind: "downloading" });
          (async () => {
            try {
              await update.downloadAndInstall();
              const { relaunch } = await import("@tauri-apps/plugin-process");
              await relaunch();
            } catch (e) {
              setState({ kind: "error", message: String(e instanceof Error ? e.message : e) });
            }
          })();
        };
        setState({ kind: "available", version: update.version, notes: update.body ?? undefined, install });
      } catch {
        /* no endpoint / offline / not packaged — ignore */
      }
    })();
    return () => { cancelled = true; };
  }, []);

  if (state.kind === "idle" || dismissed) return null;

  return (
    <div className="flex items-center gap-3 border-b border-[color:var(--accent)]/40 bg-[color:var(--accent)]/10 px-5 py-2.5 text-[13px]">
      {state.kind === "downloading" ? (
        <><CircleNotch size={15} className="accent animate-spin shrink-0" />
          <span className="text-[color:var(--text)]">Downloading update… the app will restart when it's ready.</span></>
      ) : state.kind === "error" ? (
        <><Warning size={15} className="cut shrink-0" weight="fill" />
          <span className="text-[color:var(--text)]">Update failed: {state.message}. Try again from the website download.</span>
          <button onClick={() => setDismissed(true)} className="ml-auto text-[color:var(--muted)] hover:text-[color:var(--text)]"><X size={14} /></button></>
      ) : (
        <>
          <span className="accent font-medium">Cleave v{state.version} is available.</span>
          <span className="text-[color:var(--muted)]">A newer build with the latest engine + fixes.</span>
          <button onClick={state.install}
            className="ml-auto inline-flex items-center gap-1.5 rounded-md bg-[color:var(--accent)] px-3 py-1.5 text-[12px] font-medium text-[color:var(--accent-ink)]">
            <ArrowClockwise size={13} /> Update &amp; restart
          </button>
          <button onClick={() => setDismissed(true)} className="text-[color:var(--muted)] hover:text-[color:var(--text)]" title="Later"><X size={14} /></button>
        </>
      )}
    </div>
  );
}

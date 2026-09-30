import { useEffect } from "react";
import { NavLink, Outlet, Link, useLocation, useNavigate } from "react-router-dom";
import { ShieldCheck } from "@phosphor-icons/react";
import { Mark } from "../components/Logo";
import { ThemeToggle } from "../components/ThemeToggle";
import { AnalysisProvider, useAnalysis } from "./useAnalysis";
import { getConnection, waitForBackend } from "./api";
import { DESKTOP } from "../desktop";

const TABS = [
  ["Overview", "/dashboard"],
  ["Paths", "/dashboard/paths"],
  ["Findings", "/dashboard/findings"],
  ["Remediation", "/dashboard/remediation"],
  ["History", "/dashboard/history"],
];

function AccountBadge() {
  const { data } = useAnalysis();
  const sc = data?.source !== "mock" ? data?.scan : undefined;
  const label = !data ? "connecting…"
    : !sc ? `acct ${data.account}`
    : `${sc.principal_name ?? "?"} · ${sc.alias || data.account}`;
  return (
    <Link to="/dashboard/connect" className="flex items-center gap-3 no-underline"
      title={sc?.arn ? `${sc.arn} (manage connection)` : "Manage connection"}>
      <span className="mono inline-flex items-center gap-2 text-[12px] text-[color:var(--muted)] hover:text-[color:var(--text)]">
        {sc && <span className="h-1.5 w-1.5 rounded-full bg-[color:var(--accent)]" aria-label="connected" />}
        {label}
      </span>
      <span className="mono inline-flex items-center gap-1.5 rounded border border-[color:var(--line)] px-2 py-1 text-[10px] uppercase tracking-[0.12em] text-[color:var(--accent)]">
        <ShieldCheck size={13} weight="fill" /> read-only
      </span>
    </Link>
  );
}

/** Desktop, first launch: nothing scanned yet, so open on Connect rather than an empty
 *  overview. A saved scan (last_scan) opens straight on its result. */
function DesktopFirstRun() {
  const nav = useNavigate();
  const { pathname } = useLocation();
  useEffect(() => {
    if (!DESKTOP || pathname.endsWith("/connect")) return;
    waitForBackend()
      .then(getConnection)
      .then((c) => {
        if (!c.connected && !c.last_scan) nav("/dashboard/connect", { replace: true });
      })
      .catch(() => { /* ErrorBanner reports it via the analysis load */ });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);
  return null;
}

function ErrorBanner() {
  const { error, reload } = useAnalysis();
  if (!error) return null;
  return (
    <div className="mx-5 mt-5 flex items-center justify-between gap-4 rounded-md border border-[color:var(--line)] bg-[color:var(--panel)] px-4 py-3 text-[13.5px] sm:mx-7">
      <span className="text-[color:var(--text-2)]">{error.replace(/^Error: /, "")}</span>
      <button onClick={reload} className="mono text-[12px] uppercase tracking-[0.12em] text-[color:var(--accent)]">
        Retry
      </button>
    </div>
  );
}

export function DashboardShell() {
  return (
    <AnalysisProvider>
      <div className="min-h-[100dvh]">
        <header className="sticky top-0 z-40 border-b border-[color:var(--line)] bg-[color:var(--bg)]/90 backdrop-blur-md">
          <div className="flex h-[60px] items-center justify-between px-5 sm:px-7">
            <div className="flex items-center gap-8">
              <a href="/" className="flex items-center gap-2 text-[color:var(--text)] no-underline">
                <Mark size={22} accentArrow />
                <span className="display text-[17px]">Cleave</span>
              </a>
              <nav className="hidden items-center gap-1 md:flex">
                {TABS.map(([label, to]) => (
                  <NavLink
                    key={to}
                    to={to}
                    end={to === "/dashboard"}
                    className={({ isActive }) =>
                      `rounded-md px-3 py-1.5 text-[13.5px] transition-colors ${
                        isActive
                          ? "bg-[color:var(--panel)] text-[color:var(--text)]"
                          : "text-[color:var(--muted)] hover:text-[color:var(--text)]"
                      }`
                    }
                  >
                    {label}
                  </NavLink>
                ))}
              </nav>
            </div>
            <div className="flex items-center gap-4">
              <AccountBadge />
              <ThemeToggle />
            </div>
          </div>
          <nav className="flex gap-1 overflow-x-auto border-t border-[color:var(--line)] px-4 py-2 md:hidden">
            {TABS.map(([label, to]) => (
              <NavLink key={to} to={to} end={to === "/dashboard"}
                className={({ isActive }) =>
                  `whitespace-nowrap rounded-md px-3 py-1.5 text-[13px] ${isActive ? "bg-[color:var(--panel)] text-[color:var(--text)]" : "text-[color:var(--muted)]"}`}>
                {label}
              </NavLink>
            ))}
          </nav>
        </header>
        <DesktopFirstRun />
        <ErrorBanner />
        <Outlet />
      </div>
    </AnalysisProvider>
  );
}

import { NavLink, Outlet } from "react-router-dom";
import { ShieldCheck } from "@phosphor-icons/react";
import { Mark } from "../components/Logo";
import { ThemeToggle } from "../components/ThemeToggle";
import { AnalysisProvider, useAnalysis } from "./useAnalysis";

const TABS = [
  ["Overview", "/dashboard"],
  ["Paths", "/dashboard/paths"],
  ["Findings", "/dashboard/findings"],
  ["Remediation", "/dashboard/remediation"],
  ["History", "/dashboard/history"],
];

function AccountBadge() {
  const { data } = useAnalysis();
  return (
    <div className="flex items-center gap-3">
      <span className="mono text-[12px] text-[color:var(--muted)]">
        {data ? `acct ${data.account}` : "connecting…"}
      </span>
      <span className="mono inline-flex items-center gap-1.5 rounded border border-[color:var(--line)] px-2 py-1 text-[10px] uppercase tracking-[0.12em] text-[color:var(--accent)]">
        <ShieldCheck size={13} weight="fill" /> read-only
      </span>
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
        <Outlet />
      </div>
    </AnalysisProvider>
  );
}

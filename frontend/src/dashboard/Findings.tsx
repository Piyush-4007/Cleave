import { useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { CaretDown, CaretRight, MagnifyingGlass, Warning, Wrench } from "@phosphor-icons/react";
import { useAnalysis } from "./useAnalysis";
import type { Finding, Reachability, Severity } from "./api";
import { REACH, ReachTag, SEVERITIES, SeverityGlyph, SeverityPill, sevVar } from "./Severity";

/*
  Findings — the conventional per-resource list (what Nessus or Prowler would give you),
  grouped by check the way Nessus groups by plugin. The Cleave difference is the first
  sort key: findings on a computed attack path come first, whatever their severity.
*/

const REACH_ORDER: Reachability[] = ["on_path", "entry_point", "account", "not_reachable"];

interface Group {
  check: string;
  title: string;
  service: string;
  cis: string | null;
  caveat: string | null;
  remediation: string;
  severity: Severity; // worst in the group
  reach: Reachability; // best (most reachable) in the group
  items: Finding[];
}

function groupByCheck(fs: Finding[]): Group[] {
  const by = new Map<string, Group>();
  for (const f of fs) {
    const g = by.get(f.check);
    if (!g) {
      by.set(f.check, { check: f.check, title: f.title, service: f.service, cis: f.cis,
        caveat: f.caveat ?? null,
        remediation: f.remediation, severity: f.severity, reach: f.reachability, items: [f] });
    } else {
      g.items.push(f);
      if (SEVERITIES.indexOf(f.severity) < SEVERITIES.indexOf(g.severity)) g.severity = f.severity;
      if (REACH_ORDER.indexOf(f.reachability) < REACH_ORDER.indexOf(g.reach)) g.reach = f.reachability;
    }
  }
  return [...by.values()].sort((a, b) =>
    REACH_ORDER.indexOf(a.reach) - REACH_ORDER.indexOf(b.reach) ||
    SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity) ||
    a.items[0].rank - b.items[0].rank);
}

export function Findings() {
  const { data, loading, error } = useAnalysis();
  const nav = useNavigate();
  const [reach, setReach] = useState<Reachability | "all">("all");
  const [sevs, setSevs] = useState<Set<Severity>>(new Set());
  const [service, setService] = useState("all");
  const [q, setQ] = useState("");
  const [open, setOpen] = useState<Set<string>>(new Set());

  const all = data?.findings ?? [];
  const services = useMemo(() => [...new Set(all.map((f) => f.service))].sort(), [all]);
  const shown = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return all.filter((f) =>
      (reach === "all" || f.reachability === reach) &&
      (sevs.size === 0 || sevs.has(f.severity)) &&
      (service === "all" || f.service === service) &&
      (!needle || `${f.title} ${f.resource_name} ${f.evidence} ${f.check}`.toLowerCase().includes(needle)));
  }, [all, reach, sevs, service, q]);
  const groups = useMemo(() => groupByCheck(shown), [shown]);

  if (error) return null;
  if (loading || !data) return <div className="mono p-10 text-[13px] text-[color:var(--muted)]">Loading…</div>;
  const s = data.findings_summary;

  if (!s || s.total === 0) {
    return (
      <div className="mx-auto max-w-[1180px] px-6 py-10 sm:px-8">
        <h1 className="display text-[32px] leading-tight sm:text-[40px]">Findings.</h1>
        <p className="mt-3 max-w-[60ch] text-[15px] text-[color:var(--muted)]">
          {s ? `All ${s.checks_run} checks passed on this scan.` : "Connect an account and scan it to see findings here."}
        </p>
      </div>
    );
  }

  const toggleSev = (v: Severity) => setSevs((cur) => {
    const n = new Set(cur);
    n.has(v) ? n.delete(v) : n.add(v);
    return n;
  });
  const toggleOpen = (c: string) => setOpen((cur) => {
    const n = new Set(cur);
    n.has(c) ? n.delete(c) : n.add(c);
    return n;
  });
  const onPath = s.by_reachability.on_path;

  return (
    <div className="mx-auto max-w-[1180px] px-6 py-10 sm:px-8">
      <div className="mono text-[12px] uppercase tracking-[0.16em] text-[color:var(--dim)]">Findings</div>
      <h1 className="display mt-3 text-[32px] leading-tight sm:text-[42px]">
        {s.total} findings.{" "}
        {onPath > 0
          ? <span className="accent">{onPath} on an attack path.</span>
          : <span className="text-[color:var(--muted)]">None on an attack path.</span>}
      </h1>
      <p className="mt-3 max-w-[70ch] text-[15px] leading-relaxed text-[color:var(--text-2)]">
        {s.checks_failed} of {s.checks_run} checks failed. A flat scanner would stop at severity;
        Cleave ranks what an attacker can actually reach first
        {onPath === 0 ? ", and right now nothing here chains to admin or sensitive data." : "."}
      </p>

      {/* severity tiles — also the severity filter */}
      <div className="mt-8 grid grid-cols-2 gap-px overflow-hidden rounded-lg border border-[color:var(--line)] bg-[color:var(--line)] sm:grid-cols-5">
        {SEVERITIES.map((v) => {
          const on = sevs.has(v);
          return (
            <button key={v} onClick={() => toggleSev(v)} aria-pressed={on}
              className={`relative bg-[color:var(--bg)] px-5 py-4 text-left transition-colors hover:bg-[color:var(--panel)] ${on ? "bg-[color:var(--panel)]" : ""}`}>
              <span className="absolute inset-x-0 top-0 h-[3px]" style={{ background: sevVar(v), opacity: sevs.size && !on ? 0.3 : 1 }} />
              <span className="display block text-[28px] leading-none text-[color:var(--text)]">{s.by_severity[v]}</span>
              <span className="mono mt-2 flex items-center gap-1.5 text-[11px] uppercase tracking-[0.1em] text-[color:var(--muted)]">
                <SeverityGlyph severity={v} /> {v}
              </span>
            </button>
          );
        })}
      </div>

      {/* reachability — the Cleave axis */}
      <div className="mt-6 flex flex-wrap gap-2">
        {(["all", ...REACH_ORDER] as const).map((r) => {
          const n = r === "all" ? s.total : s.by_reachability[r];
          const active = reach === r;
          return (
            <button key={r} onClick={() => setReach(r)} disabled={n === 0 && r !== "all"}
              className={`mono rounded-md border px-3 py-1.5 text-[12px] transition-colors disabled:opacity-35 ${
                active ? "border-[color:var(--accent)] text-[color:var(--text)]" : "border-[color:var(--line)] text-[color:var(--muted)] hover:text-[color:var(--text)]"}`}>
              {r === "all" ? "all" : REACH[r].label.toLowerCase()} <span className="text-[color:var(--dim)]">{n}</span>
            </button>
          );
        })}
      </div>

      <div className="mt-3 flex flex-wrap gap-2">
        <select value={service} onChange={(e) => setService(e.target.value)}
          className="mono rounded-md border border-[color:var(--line)] bg-[color:var(--bg)] px-3 py-1.5 text-[12px] text-[color:var(--text-2)]">
          <option value="all">all services</option>
          {services.map((v) => <option key={v} value={v}>{v}</option>)}
        </select>
        <label className="flex min-w-[220px] flex-1 items-center gap-2 rounded-md border border-[color:var(--line)] px-3 py-1.5">
          <MagnifyingGlass size={13} className="text-[color:var(--dim)]" />
          <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="search findings, resources, evidence"
            className="mono w-full bg-transparent text-[12px] text-[color:var(--text)] outline-none placeholder:text-[color:var(--dim)]" />
        </label>
      </div>

      <div className="mono mt-8 mb-3 text-[11px] uppercase tracking-[0.16em] text-[color:var(--dim)]">
        {groups.length} checks · {shown.length} findings{shown.length !== s.total && ` (filtered from ${s.total})`}
      </div>

      <div className="overflow-hidden rounded-lg border border-[color:var(--line)]">
        {groups.length === 0 && (
          <div className="mono px-5 py-10 text-center text-[12px] text-[color:var(--dim)]">no findings match these filters</div>
        )}
        {groups.map((g) => {
          const isOpen = open.has(g.check);
          return (
            <div key={g.check} className="border-b border-[color:var(--line)] last:border-b-0">
              <button onClick={() => toggleOpen(g.check)} aria-expanded={isOpen}
                className="flex w-full items-center gap-4 px-5 py-3.5 text-left transition-colors hover:bg-[color:var(--panel)]">
                {isOpen ? <CaretDown size={13} className="shrink-0 text-[color:var(--dim)]" /> : <CaretRight size={13} className="shrink-0 text-[color:var(--dim)]" />}
                <SeverityPill severity={g.severity} />
                <span className="min-w-0 flex-1 text-[14px] text-[color:var(--text)]">
                  {g.title}
                  {g.caveat && (
                    <span title={g.caveat}
                      className="ml-2 inline-flex items-center gap-1 align-middle text-[color:var(--sev-medium)]"
                      onClick={(e) => e.stopPropagation()}>
                      <Warning size={14} weight="fill" />
                      <span className="mono text-[10px] uppercase tracking-[0.08em]">limited</span>
                    </span>
                  )}
                </span>
                <span className="mono hidden w-[110px] shrink-0 text-[11px] text-[color:var(--dim)] md:block">{g.service}</span>
                <span className="mono hidden w-[64px] shrink-0 text-[11px] text-[color:var(--dim)] md:block">{g.cis ? `CIS ${g.cis}` : ""}</span>
                <span className="mono w-[40px] shrink-0 text-right text-[12px] text-[color:var(--text-2)]">×{g.items.length}</span>
                <span className="hidden w-[118px] shrink-0 justify-end sm:flex"><ReachTag reach={g.reach} /></span>
              </button>

              {isOpen && (
                <div className="border-t border-[color:var(--line)] bg-[color:var(--panel)]/40 px-5 py-4 sm:pl-12">
                  {g.caveat && (
                    <div className="mb-3 flex gap-3 rounded-md border border-[color:var(--sev-medium)]/40 bg-[color:var(--panel)] px-3 py-2.5 text-[12.5px] text-[color:var(--text-2)]">
                      <Warning size={15} weight="fill" className="mt-0.5 shrink-0" style={{ color: "var(--sev-medium)" }} />
                      <span><b className="text-[color:var(--text)]">What a read-only scan can't see: </b>{g.caveat}</span>
                    </div>
                  )}
                  <div className="flex gap-3 text-[13.5px] text-[color:var(--text-2)]">
                    <Wrench size={15} className="accent mt-0.5 shrink-0" />
                    <span>
                      <b className="text-[color:var(--text)]">Fix: </b>{g.remediation}
                      <span className="mono ml-2 text-[11px] text-[color:var(--dim)]">
                        {g.check}{g.cis && ` · CIS AWS Foundations v3.0.0 §${g.cis}`}
                      </span>
                    </span>
                  </div>
                  <div className="mt-4 overflow-hidden rounded-md border border-[color:var(--line)]">
                    {g.items.map((f) => (
                      <div key={f.id} className="grid gap-x-4 gap-y-1 border-b border-[color:var(--line)] bg-[color:var(--bg)] px-4 py-3 last:border-b-0 sm:grid-cols-[minmax(0,220px)_minmax(0,1fr)_auto]">
                        <div className="min-w-0">
                          <div className="mono truncate text-[12.5px] text-[color:var(--text)]" title={f.resource}>{f.resource_name}</div>
                          <div className="mono text-[11px] text-[color:var(--dim)]">{f.region ?? (f.resource === "account" ? "account-wide" : "global")}</div>
                        </div>
                        <div className="min-w-0 text-[13px] text-[color:var(--text-2)]">
                          {f.evidence}
                          {f.severity !== f.base_severity && f.severity_reason && (
                            <div className="mono mt-1 text-[11px] text-[color:var(--muted)]">
                              severity {f.base_severity} → {f.severity}: {f.severity_reason}
                            </div>
                          )}
                        </div>
                        <div className="flex flex-wrap items-start gap-1.5 sm:justify-end">
                          <ReachTag reach={f.reachability} />
                          {f.paths.map((pid) => (
                            <button key={pid} onClick={() => nav(`/dashboard/paths/${pid}`)}
                              className="mono rounded border border-[color:var(--line)] px-2 py-0.5 text-[10.5px] text-[color:var(--text-2)] hover:border-[color:var(--cut)]">
                              {pid} →
                            </button>
                          ))}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}

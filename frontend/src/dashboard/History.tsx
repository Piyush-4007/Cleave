import { useEffect, useState, type ReactNode } from "react";
import { useNavigate } from "react-router-dom";
import { ArrowRight, Minus, Plus } from "@phosphor-icons/react";
import { getHistory, getHistoryDiff, whoLabel, type HistoryDiff, type ScanRecord } from "./api";
import { SEVERITIES, SeverityGlyph, SeverityPill } from "./Severity";

/*
  Scan history — every scan kept locally (SQLite), newest first, each compared with the
  previous scan of the same account. Selecting a scan shows exactly what appeared and what
  went: the "did my fix actually work?" view.
*/

const when = (iso: string) => new Date(iso).toLocaleString([], { dateStyle: "medium", timeStyle: "short" });

function Delta({ n, kind }: { n: number; kind: "new" | "gone" }) {
  if (!n) return null;
  return (
    <span className={`mono inline-flex items-center gap-0.5 text-[11px] ${kind === "new" ? "text-[color:var(--cut)]" : "text-[color:var(--accent)]"}`}>
      {kind === "new" ? <Plus size={10} /> : <Minus size={10} />}{n}
    </span>
  );
}

export function History() {
  const nav = useNavigate();
  const [scans, setScans] = useState<ScanRecord[] | null>(null);
  const [selected, setSelected] = useState<number | null>(null);
  const [diff, setDiff] = useState<HistoryDiff | null>(null);

  useEffect(() => {
    getHistory().then((h) => {
      setScans(h);
      if (h.length) setSelected(h[0].id);
    });
  }, []);
  useEffect(() => {
    if (selected == null) return;
    setDiff(null);
    getHistoryDiff(selected).then(setDiff).catch(() => setDiff(null));
  }, [selected]);

  if (scans === null) return <div className="mono p-10 text-[13px] text-[color:var(--muted)]">Loading…</div>;

  return (
    <div className="mx-auto max-w-[1180px] px-6 py-10 sm:px-8">
      <div className="mono text-[12px] uppercase tracking-[0.16em] text-[color:var(--dim)]">History</div>
      <h1 className="display mt-3 text-[32px] leading-tight sm:text-[42px]">Scan history.</h1>
      <p className="mt-3 max-w-[64ch] text-[15px] leading-relaxed text-[color:var(--text-2)]">
        Every scan is kept on this machine and compared with the one before it, so you can see
        whether a fix closed a path, and what appeared since.
      </p>

      {scans.length === 0 ? (
        <div className="mono mt-10 grid place-items-center rounded-lg border border-dashed border-[color:var(--line)] py-20 text-[12px] text-[color:var(--dim)]">
          no scans stored yet. Scans made from the Connect screen appear here.
        </div>
      ) : (
        <>
          <div className="mono mt-8 mb-3 text-[11px] uppercase tracking-[0.16em] text-[color:var(--dim)]">
            {scans.length} scan{scans.length === 1 ? "" : "s"}
          </div>
          <div className="overflow-hidden rounded-lg border border-[color:var(--line)]">
            <div className="mono hidden grid-cols-[180px_minmax(0,1fr)_110px_150px_minmax(0,210px)] gap-4 border-b border-[color:var(--line)] bg-[color:var(--panel)] px-5 py-2.5 text-[10.5px] uppercase tracking-[0.1em] text-[color:var(--dim)] md:grid">
              <span>scanned</span><span>as · account</span><span>paths</span><span>findings</span><span>severity</span>
            </div>
            {scans.map((s) => {
              const active = s.id === selected;
              return (
                <button key={s.id} onClick={() => setSelected(s.id)} aria-pressed={active}
                  className={`grid w-full gap-x-4 gap-y-1 border-b border-[color:var(--line)] px-5 py-3.5 text-left transition-colors last:border-b-0 md:grid-cols-[180px_minmax(0,1fr)_110px_150px_minmax(0,210px)] ${
                    active ? "bg-[color:var(--panel)]" : "hover:bg-[color:var(--panel)]/60"}`}>
                  <span className="mono text-[12.5px] text-[color:var(--text)]">
                    {active && <span className="mr-2 inline-block h-1.5 w-1.5 rounded-full bg-[color:var(--accent)] align-middle" />}
                    {when(s.scanned_at)}
                  </span>
                  <span className="min-w-0 truncate text-[13.5px] text-[color:var(--text-2)]">
                    {whoLabel(s) ?? "unknown"} <span className="mono text-[11.5px] text-[color:var(--dim)]">· {s.alias || s.account}</span>
                  </span>
                  <span className="flex items-center gap-2 text-[13.5px] text-[color:var(--text)]">
                    {s.paths_found}
                    {s.delta && <><Delta n={s.delta.paths_new} kind="new" /><Delta n={s.delta.paths_resolved} kind="gone" /></>}
                  </span>
                  <span className="flex items-center gap-2 text-[13.5px] text-[color:var(--text)]">
                    {s.findings_total}
                    {s.on_path > 0 && <span className="mono text-[11px] text-[color:var(--cut)]">{s.on_path} on path</span>}
                    {s.delta && <><Delta n={s.delta.findings_new} kind="new" /><Delta n={s.delta.findings_resolved} kind="gone" /></>}
                  </span>
                  <span className="flex flex-wrap items-center gap-x-3 gap-y-1">
                    {SEVERITIES.filter((v) => (s.by_severity[v] ?? 0) > 0).map((v) => (
                      <span key={v} className="mono inline-flex items-center gap-1 text-[11.5px] text-[color:var(--text-2)]">
                        <SeverityGlyph severity={v} size={10} />{s.by_severity[v]}
                      </span>
                    ))}
                  </span>
                </button>
              );
            })}
          </div>

          {/* what changed in the selected scan */}
          {diff && (
            <div className="mt-10">
              <div className="mono text-[11px] uppercase tracking-[0.16em] text-[color:var(--dim)]">
                {diff.previous ? `changes since ${when(diff.previous.scanned_at)}` : "first scan of this account"}
              </div>
              {!diff.previous ? (
                <p className="mt-3 text-[14px] text-[color:var(--muted)]">
                  Nothing to compare yet. The next scan of {diff.scan.alias || diff.scan.account} will show what changed.
                </p>
              ) : (
                <div className="mt-4 grid gap-4 md:grid-cols-2">
                  {diff.coverage_changed && (
                    <p className="rounded-md border border-[color:var(--line)] bg-[color:var(--panel)] px-4 py-3 text-[13.5px] text-[color:var(--text-2)] md:col-span-2">
                      This scan ran checks the previous one did not. Findings from those checks are
                      listed as <b className="text-[color:var(--text)]">newly checked</b>: they may well
                      have existed before, Cleave just could not see them then.
                    </p>
                  )}
                  <ChangeList title="New findings" tone="new" empty="none"
                    rows={diff.findings.new.filter((f) => !f.newly_checked).map((f) => ({ key: f.key, left: <SeverityPill severity={f.severity} />, text: f.title, sub: f.resource_name }))} />
                  <ChangeList title="Resolved findings" tone="gone" empty="none"
                    rows={diff.findings.resolved.map((f) => ({ key: f.key, left: <SeverityPill severity={f.severity} />, text: f.title, sub: f.resource_name }))} />
                  {diff.findings.new.some((f) => f.newly_checked) && (
                    <div className="md:col-span-2">
                      <ChangeList title="Newly checked (not seen before because the check is new)" tone="neutral" empty="none"
                        rows={diff.findings.new.filter((f) => f.newly_checked).map((f) => ({ key: f.key, left: <SeverityPill severity={f.severity} />, text: f.title, sub: f.resource_name }))} />
                    </div>
                  )}
                  <ChangeList title="New attack paths" tone="new" empty="none"
                    rows={diff.paths.new.map((p) => ({ key: p.key, text: p.title, sub: `score ${p.score?.toFixed(1)}`,
                      onClick: diff.scan.id === scans[0].id ? () => nav(`/dashboard/paths/${p.path_id}`) : undefined }))} />
                  <ChangeList title="Closed attack paths" tone="gone" empty="none"
                    rows={diff.paths.resolved.map((p) => ({ key: p.key, text: p.title, sub: `score ${p.score?.toFixed(1)}` }))} />
                  <p className="mono text-[11.5px] text-[color:var(--dim)] md:col-span-2">
                    unchanged: {diff.findings.unchanged} findings · {diff.paths.unchanged} paths
                  </p>
                </div>
              )}
            </div>
          )}
        </>
      )}
    </div>
  );
}

interface Row { key: string; text: string; sub?: string; left?: ReactNode; onClick?: () => void }

function ChangeList({ title, tone, rows, empty }: { title: string; tone: "new" | "gone" | "neutral"; rows: Row[]; empty: string }) {
  return (
    <div className="overflow-hidden rounded-lg border border-[color:var(--line)]">
      <div className="flex items-center justify-between border-b border-[color:var(--line)] bg-[color:var(--panel)] px-4 py-2.5">
        <span className="text-[13.5px] font-semibold text-[color:var(--text)]">{title}</span>
        <span className={`mono text-[12px] ${rows.length && tone !== "neutral" ? (tone === "new" ? "text-[color:var(--cut)]" : "text-[color:var(--accent)]") : "text-[color:var(--dim)]"}`}>
          {tone === "new" ? "+" : tone === "gone" ? "−" : ""}{rows.length}
        </span>
      </div>
      {rows.length === 0 && <div className="mono px-4 py-4 text-[12px] text-[color:var(--dim)]">{empty}</div>}
      {rows.map((r) => (
        <button key={r.key} onClick={r.onClick} disabled={!r.onClick}
          className="flex w-full items-center gap-3 border-b border-[color:var(--line)] px-4 py-2.5 text-left last:border-b-0 enabled:hover:bg-[color:var(--panel)]">
          {r.left}
          <span className="min-w-0 flex-1">
            <span className="block truncate text-[13px] text-[color:var(--text)]">{r.text}</span>
            {r.sub && <span className="mono block truncate text-[11px] text-[color:var(--dim)]">{r.sub}</span>}
          </span>
          {r.onClick && <ArrowRight size={13} className="shrink-0 text-[color:var(--dim)]" />}
        </button>
      ))}
    </div>
  );
}

import { useState } from "react";
import { CurrencyDollar, Warning, CircleNotch, Lightning, Info } from "@phosphor-icons/react";
import { useAnalysis } from "./useAnalysis";
import { getActualSpend, type ActualSpend } from "./api";

/*
  Cost — two honest halves.
  FREE: "running & billing now" — estimated from the same scan data with bundled list
  prices. No billing permission, no cost to run. It is clearly labelled an estimate.
  OPT-IN: actual month-to-date spend via Cost Explorer, behind a button that states the
  two caveats up front (needs the ce: permission; AWS bills ~$0.01 per request).
*/

const money = (n: number) => `$${n.toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`;

export function Cost() {
  const { data, loading, error } = useAnalysis();
  const [spend, setSpend] = useState<ActualSpend | null>(null);
  const [spendErr, setSpendErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  if (error) return null;
  if (loading || !data) return <div className="mono p-10 text-[13px] text-[color:var(--muted)]">Loading…</div>;
  const c = data.cost;

  const loadActual = async () => {
    setBusy(true);
    setSpendErr(null);
    try {
      setSpend(await getActualSpend());
    } catch (e) {
      setSpendErr(String(e instanceof Error ? e.message : e));
    } finally {
      setBusy(false);
    }
  };

  const maxItem = c && c.items.length ? Math.max(...c.items.map((i) => i.monthly)) : 0;
  const maxSvc = spend && spend.by_service.length ? Math.max(...spend.by_service.map((s) => s.amount)) : 0;

  return (
    <div className="mx-auto max-w-[1180px] px-6 py-10 sm:px-8">
      <div className="mono text-[12px] uppercase tracking-[0.16em] text-[color:var(--dim)]">Cost</div>
      <h1 className="display mt-3 text-[32px] leading-tight sm:text-[42px]">
        {c ? <>About <span className="accent">{money(c.monthly_total)}</span> a month is running right now.</>
           : "No cost data in this scan."}
      </h1>

      {c && (
        <>
          <p className="mt-3 flex items-start gap-2 text-[14px] leading-relaxed text-[color:var(--text-2)]">
            <Info size={16} className="mt-0.5 shrink-0 text-[color:var(--muted)]" />
            <span>Estimated from this scan — {c.basis}. This is what's billable and running, not your invoice;
              for the real figure, load actual spend below.</span>
          </p>

          {/* by-type chips */}
          <div className="mt-6 flex flex-wrap gap-2">
            {Object.entries(c.by_type).sort((a, b) => b[1] - a[1]).map(([t, v]) => (
              <span key={t} className="mono inline-flex items-center gap-2 rounded-md border border-[color:var(--line)] px-3 py-1.5 text-[12px] text-[color:var(--text-2)]">
                {t} <span className="text-[color:var(--text)]">{money(v)}</span>
              </span>
            ))}
          </div>

          {c.items.length === 0 ? (
            <div className="mono mt-8 rounded-lg border border-[color:var(--line)] bg-[color:var(--panel)] px-5 py-8 text-center text-[13px] text-[color:var(--muted)]">
              Nothing billable is running. The account is clean on cost.
            </div>
          ) : (
            <div className="mt-8 overflow-hidden rounded-lg border border-[color:var(--line)]">
              <div className="mono hidden grid-cols-[1fr_130px_120px] gap-4 border-b border-[color:var(--line)] bg-[color:var(--panel)] px-5 py-2.5 text-[10.5px] uppercase tracking-[0.1em] text-[color:var(--dim)] sm:grid">
                <span>resource</span><span>region</span><span className="text-right">est. / month</span>
              </div>
              {c.items.map((i) => (
                <div key={i.resource} className="grid grid-cols-[1fr_auto] gap-x-4 gap-y-1 border-b border-[color:var(--line)] px-5 py-3 last:border-b-0 sm:grid-cols-[1fr_130px_120px]">
                  <div className="min-w-0">
                    <div className="text-[14px] text-[color:var(--text)]">{i.type}</div>
                    <div className="mono truncate text-[11px] text-[color:var(--dim)]" title={i.resource}>
                      {i.name}{i.note && <span className="text-[color:var(--sev-medium)]"> · {i.note}</span>}
                    </div>
                    <div className="mt-1.5 h-1 w-full overflow-hidden rounded bg-[color:var(--line)] sm:hidden">
                      <div className="h-full bg-[color:var(--accent)]" style={{ width: `${(i.monthly / maxItem) * 100}%` }} />
                    </div>
                  </div>
                  <div className="mono hidden items-center text-[12px] text-[color:var(--muted)] sm:flex">{i.region ?? "—"}</div>
                  <div className="flex items-center justify-end gap-3">
                    <div className="hidden h-1.5 w-16 overflow-hidden rounded bg-[color:var(--line)] sm:block">
                      <div className="h-full bg-[color:var(--accent)]" style={{ width: `${(i.monthly / maxItem) * 100}%` }} />
                    </div>
                    <span className="mono text-[13px] text-[color:var(--text)]">{money(i.monthly)}</span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </>
      )}

      {/* ---- opt-in actual spend ---- */}
      <div className="mt-12 rounded-xl border border-[color:var(--line)] bg-[color:var(--panel)] p-6">
        <div className="flex items-center gap-2 text-[15px] font-semibold text-[color:var(--text)]">
          <CurrencyDollar size={18} className="accent" /> Actual spend (Cost Explorer)
        </div>
        {!spend && (
          <>
            <p className="mt-3 flex items-start gap-2 text-[13.5px] leading-relaxed text-[color:var(--text-2)]">
              <Warning size={16} className="mt-0.5 shrink-0" style={{ color: "var(--sev-medium)" }} />
              <span>Your real month-to-date numbers come from AWS Cost Explorer. Two honest caveats:
                it needs the <span className="mono">ce:</span> permission (the read-only role does not include it),
                and AWS bills <b className="text-[color:var(--text)]">~$0.01 per request</b> — so this is the one
                Cleave feature that costs money to run. It never runs as part of a scan.</span>
            </p>
            <button onClick={loadActual} disabled={busy}
              className="mono mt-4 inline-flex items-center gap-2 rounded-md border border-[color:var(--accent)] px-4 py-2 text-[12px] text-[color:var(--text)] disabled:opacity-60">
              {busy ? <CircleNotch size={13} className="animate-spin" /> : <Lightning size={13} />}
              {busy ? "calling Cost Explorer…" : "load actual spend (~$0.01)"}
            </button>
            {spendErr && (
              <p className="mono mt-4 rounded-md border border-[color:var(--cut)]/40 bg-[color:var(--cut)]/8 px-4 py-3 text-[12px] cut">
                {spendErr}
              </p>
            )}
          </>
        )}
        {spend && (
          <>
            <div className="display mt-3 text-[28px] text-[color:var(--text)]">
              {money(spend.month_to_date)} <span className="mono text-[13px] text-[color:var(--muted)]">month to date</span>
            </div>
            <div className="mono text-[11px] text-[color:var(--dim)]">{spend.period.start} → {spend.period.end} · {spend.currency}</div>
            <div className="mt-5 overflow-hidden rounded-lg border border-[color:var(--line)]">
              {spend.by_service.map((s) => (
                <div key={s.service} className="flex items-center gap-4 border-b border-[color:var(--line)] px-4 py-2.5 last:border-b-0">
                  <span className="min-w-0 flex-1 truncate text-[13px] text-[color:var(--text)]">{s.service}</span>
                  <div className="hidden h-1.5 w-24 overflow-hidden rounded bg-[color:var(--line)] sm:block">
                    <div className="h-full bg-[color:var(--accent)]" style={{ width: `${(s.amount / maxSvc) * 100}%` }} />
                  </div>
                  <span className="mono w-20 text-right text-[13px] text-[color:var(--text)]">{money(s.amount)}</span>
                </div>
              ))}
            </div>
          </>
        )}
      </div>
    </div>
  );
}

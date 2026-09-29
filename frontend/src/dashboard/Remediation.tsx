import { useAnalysis } from "./useAnalysis";
import type { CutEdge } from "./api";

export function Remediation() {
  const { data, loading } = useAnalysis();
  if (loading || !data) return <div className="mono p-10 text-[13px] text-[color:var(--muted)]">Loading…</div>;
  const fixes = data.best_single_fix;
  const total = data.minimum_cut.paths_total;

  return (
    <div className="mx-auto max-w-[1180px] px-6 py-10 sm:px-8">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="display text-[32px] leading-tight sm:text-[40px]">Fixes, ranked by paths broken.</h1>
          <p className="mt-3 text-[15px] text-[color:var(--muted)]">
            The minimum cut is {data.minimum_cut.edges.length} changes that break all {total} paths, cost{" "}
            {data.minimum_cut.total_cost}. The best single change breaks {fixes[0]?.paths_cut}.
          </p>
        </div>
        <span className="mono rounded-full border border-[color:var(--line)] px-3 py-1.5 text-[11px] text-[color:var(--dim)]">
          PR generation · Phase 8
        </span>
      </div>

      <div className="mt-10 space-y-3">
        {fixes.map((f, i) => (
          <FixRow key={i} fix={f} rank={i + 1} total={total} featured={i === 0} />
        ))}
      </div>
    </div>
  );
}

function FixRow({ fix, rank, total, featured }: { fix: CutEdge; rank: number; total: number; featured: boolean }) {
  const pct = Math.round((fix.paths_cut / total) * 100);
  const disruption = fix.cost <= 3 ? "low" : fix.cost <= 6 ? "medium" : "high";
  return (
    <div
      className={`rounded-xl border p-5 ${featured ? "border-[color:var(--accent)]/50 bg-[color:var(--panel)]" : "border-[color:var(--line)]"}`}
    >
      <div className="flex flex-wrap items-center gap-x-5 gap-y-3">
        <span className={`mono text-[13px] ${featured ? "accent" : "text-[color:var(--dim)]"}`}>
          {String(rank).padStart(2, "0")}
        </span>
        <div className="min-w-[240px] flex-1">
          <div className="text-[15px] text-[color:var(--text)]">{fix.fix}.</div>
          <div className="mono mt-1 text-[11px] text-[color:var(--dim)]">
            cut {fix.rel} · {fix.frm} → {fix.to}
          </div>
        </div>

        {/* paths broken */}
        <div className="w-[150px]">
          <div className="mono flex items-baseline gap-1 text-[color:var(--text)]">
            <span className="text-[18px]">{fix.paths_cut}</span>
            <span className="text-[12px] text-[color:var(--dim)]">/ {total}</span>
          </div>
          <div className="mt-1.5 h-1 w-full overflow-hidden rounded-full bg-[color:var(--line)]">
            <div className="h-full bg-[color:var(--accent)]" style={{ width: `${pct}%` }} />
          </div>
        </div>

        <span className="mono w-[70px] text-[12px] text-[color:var(--muted)]">{disruption}</span>

        <button
          className={`mono rounded-md px-4 py-2 text-[12px] ${
            featured
              ? "bg-[color:var(--accent)] text-[color:var(--accent-ink)]"
              : "border border-[color:var(--line)] text-[color:var(--text-2)] hover:border-[color:var(--accent)]"
          }`}
        >
          {featured ? "Verify" : "Details"}
        </button>
      </div>
    </div>
  );
}

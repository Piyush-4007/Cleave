import { useNavigate } from "react-router-dom";
import { useAnalysis } from "./useAnalysis";

/* Findings — the conventional flat list, but filterable to "on a live path".
   Deliberately not the landing screen (that is the point of Cleave). */
export function Findings() {
  const { data, loading } = useAnalysis();
  const nav = useNavigate();
  if (loading || !data) return <div className="mono p-10 text-[13px] text-[color:var(--muted)]">Loading…</div>;

  // every hop is a finding; here they all sit on a live path by construction
  const rows = data.paths.flatMap((p) =>
    p.hops.map((h) => ({ path: p.id, score: p.score, rel: h.rel, on: `${h.frm} → ${h.to}`, reason: h.reason })),
  );

  return (
    <div className="mx-auto max-w-[1180px] px-6 py-10 sm:px-8">
      <h1 className="display text-[32px] leading-tight sm:text-[40px]">Findings.</h1>
      <p className="mt-3 text-[15px] text-[color:var(--muted)]">
        Every edge on a live attack path. The flat list your scanner gives you, but only the
        parts an attacker can actually reach.
      </p>
      <div className="mono mt-8 overflow-hidden rounded-lg border border-[color:var(--line)] text-[12px]">
        <div className="grid grid-cols-[70px_1fr_90px] gap-4 border-b border-[color:var(--line)] bg-[color:var(--panel)] px-5 py-3 uppercase tracking-[0.1em] text-[color:var(--dim)]">
          <span>edge</span><span>on</span><span>path</span>
        </div>
        {rows.map((r, i) => (
          <button key={i} onClick={() => nav(`/dashboard/paths/${r.path}`)}
            className="grid w-full grid-cols-[70px_1fr_90px] items-center gap-4 border-b border-[color:var(--line)] px-5 py-3 text-left last:border-b-0 hover:bg-[color:var(--panel)]">
            <span className="text-[color:var(--text)]">{r.rel.toLowerCase().replace(/_/g, " ").split(" ")[0]}</span>
            <span className="truncate text-[color:var(--text-2)]">{r.on}</span>
            <span className="text-[color:var(--dim)]">{r.path}</span>
          </button>
        ))}
      </div>
    </div>
  );
}

/* History — needs scan results persisted (Postgres), which is not wired yet. Honest placeholder. */
export function History() {
  return (
    <div className="mx-auto max-w-[1180px] px-6 py-10 sm:px-8">
      <h1 className="display text-[32px] leading-tight sm:text-[40px]">Scan history.</h1>
      <p className="mt-3 max-w-[52ch] text-[15px] text-[color:var(--muted)]">
        Posture over time lives here once scans are persisted. That storage layer is planned
        for the second semester; today each scan is stateless.
      </p>
      <div className="mono mt-10 grid place-items-center rounded-lg border border-dashed border-[color:var(--line)] py-20 text-[12px] text-[color:var(--dim)]">
        no scans stored yet
      </div>
    </div>
  );
}

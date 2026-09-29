import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { ArrowRight, ArrowClockwise, CircleNotch, Scissors, CheckCircle } from "@phosphor-icons/react";
import { useAnalysis } from "./useAnalysis";
import { connect, type Analysis } from "./api";

const COVERAGE = "IAM, S3, EC2, VPC, Lambda, RDS, Secrets Manager, KMS";

function when(iso: string): string {
  const d = new Date(iso);
  const sameDay = d.toDateString() === new Date().toDateString();
  return sameDay
    ? d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })
    : d.toLocaleString([], { dateStyle: "medium", timeStyle: "short" });
}

/** Zero paths is a real, finished result — say so plainly, with what was scanned. */
function CleanResult({ data }: { data: Analysis }) {
  const nav = useNavigate();
  const { reload } = useAnalysis();
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const scan = data.scan;
  const via = scan?.mode === "role" ? "via read-only role" : scan?.mode === "login" ? "via your AWS login" : null;

  const rescan = async () => {
    if (scan?.mode !== "login") return nav("/dashboard/connect"); // a role needs its ARN again
    setBusy(true);
    setErr(null);
    try {
      await connect("login");
      reload();
    } catch (e) {
      setErr(String(e instanceof Error ? e.message : e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="mx-auto max-w-[720px] px-6 py-16 text-center sm:px-8">
      <div className="mono inline-flex items-center gap-2 text-[12px] uppercase tracking-[0.16em] text-[color:var(--accent)]">
        <CheckCircle size={16} weight="fill" /> scan complete
      </div>
      <h1 className="display mt-4 text-[28px] leading-tight sm:text-[34px]">No attack paths found.</h1>
      <p className="mx-auto mt-3 max-w-[50ch] text-[15px] leading-relaxed text-[color:var(--text-2)]">
        Cleave read {data.summary.resources.toLocaleString()} resources in account{" "}
        <span className="mono">{data.account}</span> and found no route from any entry point or
        identity to admin or to sensitive data.
      </p>
      <div className="mono mx-auto mt-5 flex flex-wrap items-center justify-center gap-x-3 gap-y-1 text-[12px] text-[color:var(--muted)]">
        <span>acct {data.account}</span>
        {via && <><span aria-hidden>·</span><span>{via}</span></>}
        {scan && <><span aria-hidden>·</span><span>scanned {when(scan.scanned_at)}</span></>}
      </div>
      <p className="mono mx-auto mt-2 text-[11.5px] text-[color:var(--dim)]">covered: {COVERAGE}</p>

      <div className="mt-8 flex flex-wrap items-center justify-center gap-3">
        <button onClick={rescan} disabled={busy}
          className="mono inline-flex items-center gap-2 rounded-md border border-[color:var(--accent)] px-4 py-2 text-[12px] text-[color:var(--text)] disabled:opacity-60">
          {busy ? <CircleNotch size={13} className="animate-spin" /> : <ArrowClockwise size={13} />}
          {busy ? "scanning…" : "scan again"}
        </button>
        <button onClick={() => nav("/dashboard/connect")}
          className="mono inline-flex items-center gap-2 rounded-md border border-[color:var(--line)] px-4 py-2 text-[12px] text-[color:var(--text-2)] hover:border-[color:var(--accent)]">
          different account <ArrowRight size={13} />
        </button>
      </div>
      {err && <p className="mt-4 text-[13px] text-[color:var(--text-2)]">{err}</p>}
    </div>
  );
}

export function Overview() {
  const { data, loading, error } = useAnalysis();
  const nav = useNavigate(); // hooks before any early return
  if (error) return null; // the shell's ErrorBanner explains it
  if (loading || !data) return <div className="mono p-10 text-[13px] text-[color:var(--muted)]">Loading…</div>;
  const s = data.summary;

  if (data.paths.length === 0) return <CleanResult data={data} />;

  return (
    <div className="mx-auto max-w-[1180px] px-6 py-10 sm:px-8">
      {/* the contrast headline */}
      <div className="mono text-[12px] uppercase tracking-[0.16em] text-[color:var(--dim)]">Posture</div>
      <h1 className="display mt-3 max-w-[24ch] text-[32px] leading-tight sm:text-[42px]">
        {s.resources.toLocaleString()} resources scanned.{" "}
        <span className="accent">{s.paths_found} live paths</span> to something that matters.
      </h1>

      <div className="mt-8 grid grid-cols-2 gap-px overflow-hidden rounded-lg border border-[color:var(--line)] bg-[color:var(--line)] sm:grid-cols-4">
        <Stat label="attack paths" value={s.paths_found} />
        <Stat label="external entry" value={s.sources_external} />
        <Stat label="to admin" value={s.sinks_admin} />
        <Stat label="to sensitive data" value={s.sinks_sensitive_data} />
      </div>

      {/* best single fix callout */}
      {s.best_single_fix && (
        <div className="mt-6 flex flex-col gap-4 rounded-lg border border-[color:var(--accent)]/40 bg-[color:var(--panel)] p-6 sm:flex-row sm:items-center sm:justify-between">
          <div className="flex items-start gap-4">
            <Scissors size={22} className="accent mt-0.5 shrink-0" />
            <div>
              <div className="mono text-[11px] uppercase tracking-[0.14em] text-[color:var(--dim)]">best single fix</div>
              <div className="mt-1.5 text-[16px] text-[color:var(--text)]">{s.best_single_fix.fix}.</div>
              <div className="mono mt-1 text-[12px] text-[color:var(--muted)]">
                breaks {s.best_single_fix.breaks} of {s.best_single_fix.of} paths · cost {s.best_single_fix.cost}/10
              </div>
            </div>
          </div>
          <button onClick={() => nav("/dashboard/remediation")}
            className="mono inline-flex shrink-0 items-center gap-2 rounded-md border border-[color:var(--line)] px-4 py-2 text-[12px] text-[color:var(--text-2)] hover:border-[color:var(--accent)]">
            remediation <ArrowRight size={13} />
          </button>
        </div>
      )}

      {/* top paths */}
      <div className="mono mt-12 mb-4 text-[11px] uppercase tracking-[0.16em] text-[color:var(--dim)]">
        ranked attack paths
      </div>
      <div className="overflow-hidden rounded-lg border border-[color:var(--line)]">
        {data.paths.map((p) => (
          <button key={p.id} onClick={() => nav(`/dashboard/paths/${p.id}`)}
            className="flex w-full items-center gap-4 border-b border-[color:var(--line)] px-5 py-4 text-left transition-colors last:border-b-0 hover:bg-[color:var(--panel)]">
            <span className="mono w-14 shrink-0 text-[13px] accent">{p.score.toFixed(1)}</span>
            <span className="flex-1 text-[14px] text-[color:var(--text)]">{p.title}</span>
            <span className="mono hidden shrink-0 text-[11px] text-[color:var(--dim)] sm:block">
              {p.source.kind === "EXTERNAL" ? "external" : "assumed"} → {p.sink.kind === "SENSITIVE_DATA" ? "data" : "admin"}
            </span>
            <ArrowRight size={15} className="shrink-0 text-[color:var(--dim)]" />
          </button>
        ))}
      </div>
    </div>
  );
}

function Stat({ label, value }: { label: string; value: number }) {
  return (
    <div className="bg-[color:var(--bg)] p-5">
      <div className="display text-[38px] leading-none">{value}</div>
      <div className="mono mt-2 text-[11px] text-[color:var(--muted)]">{label}</div>
    </div>
  );
}

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

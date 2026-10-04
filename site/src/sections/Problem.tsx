import { Kicker, Reveal, Section, Title } from "@/components/primitives";
import { cn } from "@/lib/utils";

// A believable flat scanner feed: same few check types, endlessly, all looking alike.
const CHECKS = [
  ["HIGH", "S3 bucket allows public read"],
  ["MED", "IAM user without MFA"],
  ["HIGH", "Security group open to 0.0.0.0/0"],
  ["MED", "Access key older than 90 days"],
  ["LOW", "EBS volume not encrypted"],
  ["HIGH", "Policy grants iam:PassRole on *"],
  ["MED", "IMDSv1 enabled on instance"],
  ["LOW", "CloudWatch log retention not set"],
  ["MED", "KMS key rotation disabled"],
  ["HIGH", "Lambda role has wildcard actions"],
];
const RES = ["prod-logs", "team-photos", "acme-backups", "ci-deploy", "web-1", "batch-7", "reports", "etl-job", "analytics", "legacy-api"];

const FEED = Array.from({ length: 48 }, (_, i) => {
  const [sev, title] = CHECKS[(i * 7) % CHECKS.length];
  return { n: 247 - i, sev, title, res: RES[(i * 3) % RES.length] };
});

const PATHS = [
  { rank: 1, score: 0.94, route: ["internet", "acme-backups", "leaked key", "ci-deploy", "AdminRole"], tech: "PassRole → Lambda" },
  { rank: 2, score: 0.81, route: ["web-1", "instance role", "CreatePolicyVersion", "admin"], tech: "Policy rollback" },
  { rank: 3, score: 0.66, route: ["API route (no auth)", "etl-job", "prod-db secret"], tech: "Path to data" },
];

export function Problem() {
  return (
    <Section id="problem">
      <div className="grid gap-10 lg:grid-cols-[1fr_0.8fr] lg:items-end">
        <div>
          <Kicker n="01">The problem</Kicker>
          <Title>
            Same account.
            <br />
            Two very different to-do lists.
          </Title>
        </div>
        <p className="text-lg leading-relaxed text-mute text-pretty">
          Scanners check one resource at a time and hand you everything, sorted by a severity label. The finding that
          gets you breached looks exactly like the 200 that never will. Breaches don't come from one bad setting. They
          come from <span className="text-ink">a chain of them.</span>
        </p>
      </div>

      <div className="mt-16 grid gap-4 lg:grid-cols-2">
        {/* left: the flat list */}
        <Reveal className="relative flex h-[520px] flex-col overflow-hidden rounded-[28px] border border-line bg-paper-2">
          <div className="flex items-center justify-between border-b border-line px-6 py-4">
            <div>
              <div className="font-mono text-xs uppercase tracking-wider text-mute">A typical scanner</div>
              <div className="display mt-1 text-2xl">247 findings</div>
            </div>
            <span className="rounded-full border border-line px-3 py-1 font-mono text-xs text-mute">sorted by severity</span>
          </div>
          <div className="relative flex-1 overflow-hidden">
            <ul className="animate-feed font-mono text-[13px]">
              {[...FEED, ...FEED].map((f, i) => (
                <li key={i} className="flex items-center gap-3 border-b border-line/70 px-6 py-2.5" aria-hidden={i >= FEED.length}>
                  <span className="w-8 shrink-0 text-mute/70">#{f.n}</span>
                  <span
                    className={cn(
                      "w-12 shrink-0 rounded px-1.5 text-center text-[11px] font-semibold",
                      f.sev === "HIGH" ? "bg-[#f3c7a6] text-[#7a2e05]" : f.sev === "MED" ? "bg-[#ece2b0] text-[#5c4a03]" : "bg-line text-mute",
                    )}
                  >
                    {f.sev}
                  </span>
                  <span className="truncate text-ink/80">{f.title}</span>
                  <span className="ml-auto hidden shrink-0 text-mute sm:inline">{f.res}</span>
                </li>
              ))}
            </ul>
            <div aria-hidden className="pointer-events-none absolute inset-x-0 bottom-0 h-32 bg-gradient-to-t from-paper-2 to-transparent" />
          </div>
          <p className="border-t border-line px-6 py-4 text-sm text-mute">Which one first? The list can't tell you.</p>
        </Reveal>

        {/* right: three paths */}
        <Reveal delay={0.1} className="flex flex-col rounded-[28px] bg-ink p-6 text-paper sm:p-8">
          <div className="flex items-center justify-between">
            <div>
              <div className="font-mono text-xs uppercase tracking-wider text-mute-dark">Cleave</div>
              <div className="display mt-1 text-2xl">3 attack paths</div>
            </div>
            <span className="rounded-full bg-lime px-3 py-1 font-mono text-xs font-medium text-ink">ranked by reachability</span>
          </div>

          <ol className="mt-8 flex flex-1 flex-col gap-3">
            {PATHS.map((p) => (
              <li key={p.rank} className="rounded-2xl border border-white/10 bg-ink-2 p-5">
                <div className="flex items-center justify-between font-mono text-xs">
                  <span className="text-mute-dark">
                    #{p.rank} · {p.tech}
                  </span>
                  <span className={p.rank === 1 ? "text-cut" : "text-mute-dark"}>score {p.score.toFixed(2)}</span>
                </div>
                <div className="mt-3 flex flex-wrap items-center gap-x-1.5 gap-y-1 font-mono text-[13px]">
                  {p.route.map((r, i) => (
                    <span key={r} className="flex items-center gap-1.5">
                      <span className={i === p.route.length - 1 ? "text-cut" : "text-paper"}>{r}</span>
                      {i < p.route.length - 1 && <span className="text-lime">→</span>}
                    </span>
                  ))}
                </div>
                <div className="mt-4 h-1 overflow-hidden rounded-full bg-white/10">
                  <div className={cn("h-full rounded-full", p.rank === 1 ? "bg-cut" : "bg-lime")} style={{ width: `${p.score * 100}%` }} />
                </div>
              </li>
            ))}
          </ol>

          <div className="mt-6 flex items-center gap-4 rounded-2xl bg-lime p-5 text-ink">
            <div className="display text-5xl">1</div>
            <p className="text-[15px] font-medium leading-snug">
              change (scope one PassRole) breaks path #1, and 7 more like it.
            </p>
          </div>
        </Reveal>
      </div>

      <p className="mt-6 font-mono text-xs text-mute">
        Real run on a 5-scenario CloudGoat test lab: 58 findings → 9 on a path → 28 paths → 1 change breaks 8. Six changes
        break all 28.
      </p>
    </Section>
  );
}

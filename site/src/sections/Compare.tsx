import { Check } from "lucide-react";
import { Kicker, Reveal, Section, Title, REPO } from "@/components/primitives";
import { cn } from "@/lib/utils";

// Measured on one synthetic account, same day — 5 planted attack paths, known ground truth.
const TOOLS = ["Prowler", "ScoutSuite", "Checkov", "PMapper", "Cleave"] as const;

type Cell = { v: string } | { check: boolean };
const ROWS: { label: string; cells: Record<string, Cell> }[] = [
  {
    label: "Routes to admin found",
    cells: {
      Prowler: { v: "0" }, ScoutSuite: { v: "0" }, Checkov: { v: "0" },
      PMapper: { v: "2 / 5" }, Cleave: { v: "5 / 5" },
    },
  },
  {
    label: "Ranks by reachability",
    cells: { Prowler: { check: false }, ScoutSuite: { check: false }, Checkov: { check: false }, PMapper: { check: false }, Cleave: { check: true } },
  },
  {
    label: "Names the one fix (minimum cut)",
    cells: { Prowler: { check: false }, ScoutSuite: { check: false }, Checkov: { check: false }, PMapper: { check: false }, Cleave: { check: true } },
  },
  {
    label: "Blocks risky PRs (merge gate)",
    cells: { Prowler: { check: false }, ScoutSuite: { check: false }, Checkov: { check: false }, PMapper: { check: false }, Cleave: { check: true } },
  },
  {
    label: "What it is",
    cells: {
      Prowler: { v: "flat scanner" }, ScoutSuite: { v: "flat scanner" }, Checkov: { v: "IaC linter" },
      PMapper: { v: "IAM graph" }, Cleave: { v: "path engine" },
    },
  },
];

function CellView({ cell, cleave }: { cell: Cell; cleave: boolean }) {
  if ("check" in cell) {
    return cell.check ? (
      <span className="inline-flex size-6 items-center justify-center rounded-full bg-lime text-ink">
        <Check className="size-3.5" strokeWidth={3} />
      </span>
    ) : (
      <span className="text-mute/50" aria-label="no">—</span>
    );
  }
  return (
    <span className={cn("font-mono text-[13px]", cleave ? "font-semibold text-ink" : "text-mute")}>
      {cell.v}
    </span>
  );
}

export function Compare() {
  return (
    <Section id="compare">
      <Kicker n="07">Compare</Kicker>
      <div className="mt-2 grid gap-10 lg:grid-cols-[1fr_1.15fr] lg:items-end">
        <div>
          <Title className="lg:text-[64px]">Everyone finds the pieces. Cleave finds the path.</Title>
          <p className="mt-6 max-w-lg text-lg leading-relaxed text-mute text-pretty">
            Measured on the <span className="text-ink">same synthetic account, the same day</span> — 5 planted
            attack paths with known ground truth. The scanners find hundreds of misconfigurations; only Cleave
            turns them into <span className="mark text-ink">ranked routes to admin</span> and names the cut.
          </p>
        </div>
      </div>

      <Reveal className="mt-10 overflow-x-auto">
        <table className="w-full min-w-[720px] border-collapse text-left">
          <thead>
            <tr>
              <th className="w-[40%] py-4 pr-4 align-bottom font-mono text-[11px] font-normal uppercase tracking-[0.14em] text-mute">
                On a 5-path benchmark account
              </th>
              {TOOLS.map((t) => {
                const cleave = t === "Cleave";
                return (
                  <th
                    key={t}
                    className={cn(
                      "px-4 py-4 text-center align-bottom",
                      cleave && "rounded-t-2xl bg-ink text-paper",
                    )}
                  >
                    <span className={cn("font-display text-lg", cleave ? "text-paper" : "text-ink/70")}>{t}</span>
                  </th>
                );
              })}
            </tr>
          </thead>
          <tbody>
            {ROWS.map((row, ri) => (
              <tr key={row.label} className="border-t border-line">
                <td className="py-4 pr-4 text-[15px] font-medium text-ink">{row.label}</td>
                {TOOLS.map((t) => {
                  const cleave = t === "Cleave";
                  const last = ri === ROWS.length - 1;
                  return (
                    <td
                      key={t}
                      className={cn(
                        "px-4 py-4 text-center",
                        cleave && "bg-ink/[0.04]",
                        cleave && last && "rounded-b-2xl",
                      )}
                    >
                      <CellView cell={row.cells[t]} cleave={cleave} />
                    </td>
                  );
                })}
              </tr>
            ))}
          </tbody>
        </table>
      </Reveal>

      <div className="mt-8 flex flex-col gap-4 border-t border-line pt-6 sm:flex-row sm:items-start sm:justify-between">
        <p className="max-w-2xl text-[15px] leading-relaxed text-mute text-pretty">
          <span className="font-semibold text-ink">To be fair:</span> Prowler, ScoutSuite and Checkov are
          excellent at what they do — they find misconfigurations. PMapper maps IAM privilege escalation. Cleave
          is the only one that connects those pieces into ranked routes to admin, and names the single change
          that severs the most.
        </p>
        <a
          href={`${REPO}#why-its-different`}
          className="shrink-0 whitespace-nowrap font-mono text-sm text-ink underline decoration-lime decoration-2 underline-offset-4 transition-colors hover:text-mute"
        >
          See the full benchmark →
        </a>
      </div>
    </Section>
  );
}

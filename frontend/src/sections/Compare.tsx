import { Check, Minus } from "@phosphor-icons/react";
import { Section } from "../components/ui";

const COLS = ["Lists findings", "Computes paths", "Open source", "Runs locally", "Pre-deploy gate"];
type Cell = "yes" | "no" | "part";
const ROWS: { name: string; note: string; cells: Cell[]; self?: boolean }[] = [
  { name: "Free scanners", note: "Prowler, ScoutSuite", cells: ["yes", "no", "yes", "yes", "no"] },
  { name: "Config linters", note: "Checkov", cells: ["yes", "no", "yes", "yes", "part"] },
  { name: "Commercial", note: "Wiz and similar", cells: ["yes", "yes", "no", "no", "part"] },
  { name: "Cleave", note: "this project", cells: ["yes", "yes", "yes", "yes", "part"], self: true },
];

function Icon({ v }: { v: Cell }) {
  if (v === "yes") return <Check size={16} weight="bold" className="accent" />;
  if (v === "part") return <span className="mono text-[11px] text-[color:var(--muted)]">partial</span>;
  return <Minus size={16} className="text-[color:var(--dim)]" />;
}

export function Compare() {
  return (
    <Section id="compare" className="py-24">
      <h2 className="display text-[32px] leading-tight sm:text-[40px]">How it is different.</h2>
      <p className="mt-4 max-w-[58ch] text-[16px] leading-relaxed text-[color:var(--muted)]">
        Free tools list findings. Commercial tools compute attack paths but are closed and
        enterprise-priced. Cleave is the open implementation of the reasoning layer in between.
      </p>

      <div className="mt-10 overflow-x-auto">
        <table className="w-full min-w-[680px] border-collapse text-left">
          <thead>
            <tr className="border-b border-[color:var(--line)]">
              <th className="py-3 pr-4 text-[13px] font-medium text-[color:var(--dim)]"></th>
              {COLS.map((c) => (
                <th key={c} className="mono px-4 py-3 text-[11px] font-normal uppercase tracking-[0.1em] text-[color:var(--dim)]">
                  {c}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {ROWS.map((r) => (
              <tr key={r.name}
                  className={`border-b border-[color:var(--line)] ${r.self ? "bg-[color:var(--panel)]" : ""}`}>
                <td className="py-4 pr-4">
                  <div className={`text-[15px] ${r.self ? "accent font-semibold" : "text-[color:var(--text)]"}`}>{r.name}</div>
                  <div className="mono text-[11px] text-[color:var(--dim)]">{r.note}</div>
                </td>
                {r.cells.map((v, i) => (
                  <td key={i} className="px-4 py-4"><Icon v={v} /></td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <p className="mono mt-4 text-[12px] text-[color:var(--dim)]">
        Pre-deploy gate and the remediation pull request land in the second semester of the build.
      </p>
    </Section>
  );
}

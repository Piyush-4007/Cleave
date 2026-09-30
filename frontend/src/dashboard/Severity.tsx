import type { Reachability, Severity } from "./api";

/*
  Severity & reachability primitives. Severity colours are status colours (dataviz skill):
  they never carry meaning alone, so every use pairs the colour with its word AND a bar glyph
  whose count encodes rank (4 = critical … 1 = low, 0 = info) — readable in greyscale and
  for colour-vision deficiencies.
*/

export const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];
const BARS: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

export const sevVar = (s: Severity) => `var(--sev-${s})`;

export function SeverityGlyph({ severity, size = 12 }: { severity: Severity; size?: number }) {
  const n = BARS[severity];
  const w = size / 5;
  return (
    <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} aria-hidden className="shrink-0">
      {[0, 1, 2, 3].map((i) => {
        const h = (size * (i + 1)) / 4;
        return (
          <rect key={i} x={i * (w + w / 3)} y={size - h} width={w} height={h} rx={w / 3}
            fill={i < n ? sevVar(severity) : "var(--line)"} />
        );
      })}
    </svg>
  );
}

export function SeverityPill({ severity }: { severity: Severity }) {
  return (
    <span className="mono inline-flex w-[88px] shrink-0 items-center gap-1.5 text-[11px] uppercase tracking-[0.08em] text-[color:var(--text-2)]">
      <SeverityGlyph severity={severity} />
      {severity}
    </span>
  );
}

export const REACH: Record<Reachability, { label: string; short: string; hint: string }> = {
  on_path: { label: "On an attack path", short: "on path", hint: "part of a computed route to admin or sensitive data" },
  entry_point: { label: "Entry point", short: "entry", hint: "an external way in that does not chain further (yet)" },
  account: { label: "Account-wide", short: "account", hint: "an account setting, not tied to one resource" },
  not_reachable: { label: "Not reachable", short: "not reachable", hint: "a real weakness no computed route uses" },
};

export function ReachTag({ reach }: { reach: Reachability }) {
  const hot = reach === "on_path";
  return (
    <span title={REACH[reach].hint}
      className={`mono inline-flex shrink-0 items-center gap-1.5 rounded border px-2 py-0.5 text-[10.5px] uppercase tracking-[0.08em] ${
        hot ? "border-[color:var(--cut)] text-[color:var(--cut)]" : "border-[color:var(--line)] text-[color:var(--muted)]"}`}>
      {hot && <span className="h-1.5 w-1.5 rounded-full bg-[color:var(--cut)]" />}
      {REACH[reach].short}
    </span>
  );
}

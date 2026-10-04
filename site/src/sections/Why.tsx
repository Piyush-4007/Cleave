import { motion } from "framer-motion";
import { Kicker, Reveal, Section, Title } from "@/components/primitives";
import { cn } from "@/lib/utils";

// x: 0 = lists findings, 100 = reasons about paths. y: 0 = open & local, 100 = closed & SaaS.
const TOOLS = [
  { name: "Prowler", x: 14, y: 16 },
  { name: "ScoutSuite", x: 24, y: 30 },
  { name: "Checkov", x: 9, y: 42 },
  { name: "Cartography", x: 38, y: 40 },
  { name: "PMapper", x: 50, y: 25 },
  { name: "Wiz", x: 84, y: 76 },
  { name: "Orca", x: 72, y: 86 },
  { name: "Prisma Cloud", x: 62, y: 70 },
];

const BETTER = [
  ["Breadth", "Prowler runs hundreds of checks across three clouds. Cleave: 46, AWS only, deeper."],
  ["Runtime", "Commercial platforms see live workloads and image CVEs. Cleave reads configuration only."],
  ["Maturity", "The established scanners have years of rules, integrations and battle-testing. Cleave is new."],
];

export function Why() {
  return (
    <Section id="why" className="bg-ink pt-8 text-paper md:pt-8">
      <div className="rounded-[32px] bg-paper p-6 text-ink sm:p-10 lg:p-14">
        <Kicker n="04">Why Cleave</Kicker>
        <div className="mt-2 grid gap-14 lg:grid-cols-[1fr_1.05fr] lg:items-center">
          <div>
            <Title className="lg:text-[64px]">One corner of the map was empty.</Title>
            <p className="mt-6 max-w-lg text-lg leading-relaxed text-mute text-pretty">
              Attack-path analysis isn't new. The big platforms do it well, but they're closed, priced for enterprises,
              and want your account data in their cloud. The open tools stop at a list, or at an IAM-only graph you query
              yourself. <span className="mark text-ink">Nobody built the open reasoning layer.</span> So we did.
            </p>

            <div className="mt-10 border-t border-line pt-6">
              <div className="font-mono text-xs uppercase tracking-wider text-mute">Where the others win, honestly</div>
              <dl className="mt-4 space-y-3">
                {BETTER.map(([t, b]) => (
                  <div key={t} className="grid grid-cols-[96px_1fr] gap-3 text-[15px]">
                    <dt className="font-semibold">{t}</dt>
                    <dd className="text-mute">{b}</dd>
                  </div>
                ))}
              </dl>
            </div>
          </div>

          <Reveal>
            <Quadrant />
          </Reveal>
        </div>
      </div>
    </Section>
  );
}

function Quadrant() {
  return (
    <figure>
      <div className="relative aspect-square w-full rounded-3xl border border-line bg-white" role="img" aria-label="Map of AWS security tools. Open tools like Prowler, ScoutSuite and Checkov sit in the open-but-lists corner. Wiz, Orca and Prisma Cloud sit in the closed-but-reasons corner. Cleave is alone in the open-and-reasons corner.">
        <div aria-hidden className="dots absolute inset-0 rounded-3xl opacity-60" />
        <div aria-hidden className="absolute inset-y-6 left-1/2 w-px bg-line" />
        <div aria-hidden className="absolute inset-x-6 top-1/2 h-px bg-line" />

        {/* the empty corner, now ours */}
        <div aria-hidden className="absolute right-3 top-3 h-[calc(50%-12px)] w-[calc(50%-12px)] rounded-2xl bg-lime/35" />

        <span className="absolute left-4 top-4 font-mono text-[10px] uppercase tracking-wider text-mute sm:text-[11px]">Open · lists</span>
        <span className="absolute right-5 top-4 font-mono text-[10px] font-semibold uppercase tracking-wider text-ink sm:text-[11px]">Open · reasons</span>
        <span className="absolute bottom-4 right-4 font-mono text-[10px] uppercase tracking-wider text-mute sm:text-[11px]">Closed · reasons</span>
        <span className="absolute bottom-4 left-4 font-mono text-[10px] uppercase tracking-wider text-mute sm:text-[11px]">Closed · lists</span>

        {TOOLS.map((t, i) => (
          <motion.div
            key={t.name}
            className="absolute -translate-x-1/2 -translate-y-1/2"
            style={{ left: `${t.x}%`, top: `${t.y}%` }}
            initial={{ opacity: 0, scale: 0.6 }}
            whileInView={{ opacity: 1, scale: 1 }}
            viewport={{ once: true }}
            transition={{ delay: 0.1 + i * 0.05 }}
          >
            <span className="flex items-center gap-1.5 whitespace-nowrap rounded-full border border-line bg-paper px-2.5 py-1 text-[11px] font-medium text-ink/80 sm:text-xs">
              <span className="size-1.5 rounded-full bg-mute" aria-hidden />
              {t.name}
            </span>
          </motion.div>
        ))}

        <motion.div
          className="absolute -translate-x-1/2 -translate-y-1/2"
          style={{ left: "77%", top: "24%" }}
          initial={{ opacity: 0, scale: 0.4 }}
          whileInView={{ opacity: 1, scale: 1 }}
          viewport={{ once: true }}
          transition={{ delay: 0.7, type: "spring", stiffness: 260, damping: 16 }}
        >
          <span className={cn("flex items-center gap-2 rounded-full bg-ink px-4 py-2 font-display text-lg font-extrabold text-paper shadow-[0_10px_30px_-10px_rgb(12_12_12/0.6)] sm:text-xl")}>
            <span className="size-2.5 rounded-full bg-lime" aria-hidden />
            Cleave
          </span>
        </motion.div>
      </div>
      <figcaption className="mt-3 flex justify-between font-mono text-[11px] text-mute">
        <span>← lists findings</span>
        <span>reasons about paths →</span>
      </figcaption>
    </figure>
  );
}

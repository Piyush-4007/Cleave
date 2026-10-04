import { useState } from "react";
import { AnimatePresence, motion } from "framer-motion";
import { Container, Database, FileLock2, KeyRound, Laptop, MessageSquareText, RotateCcw, Scissors, Table2 } from "lucide-react";
import { Kicker, Reveal, Section, Title } from "@/components/primitives";
import { EDGES, HOPS } from "@/lib/samplePath";
import { cn } from "@/lib/utils";

const tile = "relative overflow-hidden rounded-[28px] p-6 sm:p-7";

export function Product() {
  return (
    <Section id="product" className="bg-paper">
      <div className="grid gap-10 lg:grid-cols-[1fr_0.8fr] lg:items-end">
        <div>
          <Kicker n="02">The product</Kicker>
          <Title>Everything it does, in boxes.</Title>
        </div>
        <p className="text-lg leading-relaxed text-mute text-pretty">
          Every step on a path is a documented attacker move, backed by evidence from your own account. Try the big box:
          follow the path, read the proof, then cut it.
        </p>
      </div>

      <div className="mt-16 grid auto-rows-[minmax(220px,auto)] grid-cols-1 gap-4 md:grid-cols-2 lg:grid-cols-4">
        <Reveal className="md:col-span-2 lg:row-span-2">
          <PathTile />
        </Reveal>

        <Reveal delay={0.05} className={cn(tile, "flex flex-col justify-between bg-lime")}>
          <KeyRound className="size-6" aria-hidden />
          <div>
            <div className="display text-[96px] leading-none">0</div>
            <p className="mt-2 font-medium">access keys stored. Ever. You paste a role ARN, or use your AWS login.</p>
          </div>
        </Reveal>

        <Reveal delay={0.1} className={cn(tile, "flex flex-col justify-between border border-line bg-paper-2")}>
          <div className="font-mono text-xs uppercase tracking-wider text-mute">scan time</div>
          <div>
            <div className="display text-[96px] leading-none">
              14<span className="text-5xl text-mute">s</span>
            </div>
            <p className="mt-2 text-mute">for a full scan of a real account, collectors running in parallel.</p>
          </div>
        </Reveal>

        <Reveal delay={0.05} className={cn(tile, "border border-line bg-white md:col-span-2")}>
          <div className="font-mono text-xs uppercase tracking-wider text-mute">privilege escalation</div>
          <h3 className="display mt-3 text-3xl">PassRole into seven compute services.</h3>
          <p className="mt-2 max-w-md text-mute">Each launch is checked against the target role's trust policy, so only real routes count.</p>
          <ul className="mt-5 flex flex-wrap gap-2">
            {["Lambda", "EC2", "ECS", "Glue", "SageMaker", "CodeBuild", "CloudFormation"].map((s) => (
              <li key={s} className="rounded-full bg-ink px-3 py-1.5 font-mono text-xs text-paper">
                {s}
              </li>
            ))}
          </ul>
        </Reveal>

        <Reveal className={cn(tile, "border border-line bg-paper-2")}>
          <div className="display text-6xl">46</div>
          <h3 className="mt-1 font-semibold">posture checks, CIS-mapped</h3>
          <ul className="mt-5 space-y-2 font-mono text-[11px]">
            <li className="flex items-center gap-2">
              <span className="rounded bg-cut px-1.5 py-0.5 font-semibold text-white">ON PATH</span> ranked first
            </li>
            <li className="flex items-center gap-2">
              <span className="rounded bg-ink px-1.5 py-0.5 font-semibold text-lime">ENTRY</span> where attackers start
            </li>
            <li className="flex items-center gap-2">
              <span className="rounded bg-line px-1.5 py-0.5 font-semibold text-mute">UNREACHABLE</span> fix when you can
            </li>
          </ul>
        </Reveal>

        <Reveal delay={0.05} className={cn(tile, "flex flex-col justify-between bg-ink text-paper")}>
          <div className="font-mono text-xs uppercase tracking-wider text-mute-dark">deterministic</div>
          <div>
            <div className="space-y-1.5 font-mono text-[11px] text-mute-dark">
              <div>
                run 1 <span className="text-lime">sha 9f3a…c21e</span>
              </div>
              <div>
                run 2 <span className="text-lime">sha 9f3a…c21e</span>
              </div>
            </div>
            <h3 className="display mt-4 text-3xl">Same in, same out.</h3>
            <p className="mt-2 text-sm text-mute-dark">Graph search, not machine learning. Every result is explainable.</p>
          </div>
        </Reveal>

        <Reveal delay={0.1} className={cn(tile, "border border-line bg-white md:col-span-2")}>
          <HistoryTile />
        </Reveal>

        <Reveal className={cn(tile, "bg-ink-2 text-paper md:col-span-2")}>
          <div className="font-mono text-xs uppercase tracking-wider text-mute-dark">sinks</div>
          <h3 className="display mt-3 text-3xl">Admin isn't the only prize.</h3>
          <p className="mt-2 max-w-md text-mute-dark">Routes into the data you care about count as findings too.</p>
          <ul className="mt-6 grid grid-cols-2 gap-2 sm:grid-cols-4">
            {[
              [FileLock2, "Secrets"],
              [Database, "RDS"],
              [Table2, "DynamoDB"],
              [Database, "S3 data"],
            ].map(([Icon, l]) => {
              const I = Icon as typeof Database;
              return (
                <li key={l as string} className="flex items-center gap-2 rounded-xl border border-white/10 px-3 py-3 text-sm">
                  <I className="size-4 text-cut" aria-hidden /> {l as string}
                </li>
              );
            })}
          </ul>
        </Reveal>

        <Reveal delay={0.05} className={cn(tile, "flex flex-col justify-between border border-line bg-paper-2")}>
          <MessageSquareText className="size-6" aria-hidden />
          <div>
            <h3 className="display text-2xl">Plain-English, optional.</h3>
            <p className="mt-2 text-sm text-mute">A language model can narrate a path. It never decides one. Off by default.</p>
          </div>
        </Reveal>

        <Reveal delay={0.1} className={cn(tile, "flex flex-col justify-between border border-line bg-paper-2")}>
          <div className="flex gap-2">
            <Container className="size-6" aria-hidden />
            <Laptop className="size-6" aria-hidden />
          </div>
          <div>
            <h3 className="display text-2xl">Docker or desktop.</h3>
            <p className="mt-2 text-sm text-mute">`docker compose up` anywhere, or the Windows app.</p>
          </div>
        </Reveal>
      </div>
    </Section>
  );
}

function HistoryTile() {
  const scans = [28, 28, 21, 12, 9, 0];
  return (
    <div className="flex h-full flex-col">
      <div className="font-mono text-xs uppercase tracking-wider text-mute">scan history</div>
      <div className="mt-3 flex flex-wrap items-end justify-between gap-4">
        <h3 className="display text-3xl">Watch paths close.</h3>
        <div className="flex gap-2 font-mono text-xs">
          <span className="rounded-full bg-lime px-2.5 py-1">−28 closed</span>
          <span className="rounded-full bg-paper-2 px-2.5 py-1 text-mute">+0 new</span>
        </div>
      </div>
      <div className="mt-6 flex flex-1 items-end gap-3" role="img" aria-label="Attack paths over six scans: 28, 28, 21, 12, 9, 0">
        {scans.map((v, i) => (
          <div key={i} className="flex flex-1 flex-col items-center gap-2">
            <span className="font-mono text-[11px] text-mute">{v}</span>
            <motion.div
              className={cn("w-full rounded-t-lg", v === 0 ? "bg-lime" : i === 0 ? "bg-cut" : "bg-ink")}
              initial={{ height: 4 }}
              whileInView={{ height: Math.max(6, (v / 28) * 96) }}
              viewport={{ once: true }}
              transition={{ duration: 0.6, delay: i * 0.08, ease: [0.16, 1, 0.3, 1] }}
            />
          </div>
        ))}
      </div>
    </div>
  );
}

const CUT_INDEX = EDGES.findIndex((e) => e.cut);

function PathTile() {
  const [sel, setSel] = useState(CUT_INDEX);
  const [cut, setCut] = useState(false);
  const edge = EDGES[sel];

  return (
    <div className={cn(tile, "flex h-full flex-col bg-ink text-paper")}>
      <div aria-hidden className="dots-dark absolute inset-0 opacity-60" />
      <div className="relative flex flex-wrap items-center justify-between gap-2">
        <div className="font-mono text-xs uppercase tracking-wider text-mute-dark">path #1 · score 0.94 · certain</div>
        <span className="font-mono text-xs text-mute-dark">click a step</span>
      </div>

      <ol className="relative mt-6 space-y-0" aria-label="Attack path steps">
        {HOPS.map((hop, i) => {
          const dead = cut && i > CUT_INDEX;
          const isEdge = i < EDGES.length;
          return (
            <li key={hop.id}>
              <div className={cn("flex items-center gap-3 transition-opacity duration-300", dead && "opacity-30")}>
                <span
                  className={cn(
                    "flex size-9 shrink-0 items-center justify-center rounded-full border-2",
                    hop.sink && !dead ? "border-cut text-cut" : "border-white/25",
                  )}
                >
                  <hop.icon className="size-4" aria-hidden />
                </span>
                <span className="font-mono text-sm">{hop.label}</span>
                <span className="hidden text-xs text-mute-dark sm:inline">{hop.kind}</span>
              </div>
              {isEdge && (
                <button
                  type="button"
                  onClick={() => setSel(i)}
                  aria-pressed={sel === i}
                  className="group ml-[17px] flex min-h-9 w-[calc(100%-17px)] cursor-pointer items-center gap-3 border-l-2 py-1 pl-6 text-left"
                  style={{ borderColor: cut && i === CUT_INDEX ? "#ff3b2f" : cut && i > CUT_INDEX ? "#333" : "#d4f53c" }}
                >
                  <span
                    className={cn(
                      "rounded-full px-2 py-0.5 font-mono text-[10.5px] transition-colors",
                      sel === i ? "bg-lime text-ink" : "bg-white/5 text-mute-dark group-hover:text-paper",
                      EDGES[i].cut && sel !== i && "text-cut",
                    )}
                  >
                    {EDGES[i].reason}
                  </span>
                  {cut && i === CUT_INDEX && <Scissors className="size-4 text-cut" aria-label="cut here" />}
                </button>
              )}
            </li>
          );
        })}
      </ol>

      <div className="relative mt-6 rounded-2xl bg-ink-3 p-4">
        <AnimatePresence mode="wait">
          <motion.div key={sel} initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} transition={{ duration: 0.15 }}>
            <p className="text-[15px] leading-snug">{edge.plain}</p>
            <pre className="mt-3 overflow-x-auto font-mono text-[11.5px] leading-relaxed text-mute-dark">{edge.evidence}</pre>
          </motion.div>
        </AnimatePresence>
      </div>

      <div className="relative mt-4 flex flex-wrap items-center gap-3">
        {!cut ? (
          <button
            key="cut"
            type="button"
            onClick={() => {
              setCut(true);
              setSel(CUT_INDEX);
            }}
            className="inline-flex min-h-11 cursor-pointer items-center gap-2 rounded-full bg-cut px-5 text-sm font-semibold text-ink transition-transform active:scale-95"
          >
            <Scissors className="size-4" aria-hidden /> Make the cut
          </button>
        ) : (
          <button
            key="undo"
            type="button"
            onClick={() => setCut(false)}
            className="inline-flex min-h-11 cursor-pointer items-center gap-2 rounded-full border border-white/25 px-5 text-sm font-semibold transition-colors hover:bg-white/5"
          >
            <RotateCcw className="size-4" aria-hidden /> Undo
          </button>
        )}
        <p role="status" aria-live="polite" className="text-sm text-mute-dark">
          {cut ? (
            <span className="text-lime">Broken. ci-deploy can no longer hand out AdminRole.</span>
          ) : (
            "Fix: scope one iam:PassRole. Breaks 8 of 28 paths."
          )}
        </p>
      </div>
    </div>
  );
}

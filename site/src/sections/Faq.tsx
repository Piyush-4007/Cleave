import { useState } from "react";
import { AnimatePresence, motion } from "framer-motion";
import { Plus } from "lucide-react";
import { Kicker, Section, Title } from "@/components/primitives";
import { cn } from "@/lib/utils";

const QA: [string, string][] = [
  ["Is it safe to run against production?", "Yes. It only makes read and list calls through a role limited to AWS's SecurityAudit and ViewOnlyAccess policies, so it cannot change anything, even by mistake. Those reads are free AWS API calls."],
  ["Does my data go anywhere?", "No. There is no Cleave server. The scan, the graph and the history live on your computer. The optional plain-English narration is the only feature that could call an outside model, and it's off unless you turn it on."],
  ["Why not just fix everything my scanner reports?", "In a real account that's hundreds of items, and most aren't reachable by anyone. Cleave tells you which handful sit on a route to admin or data, and which single change removes the most risk, so your first hour of work counts."],
  ["Is it AI?", "No. Finding paths is deterministic graph search: the same account gives the same result every time, and every edge carries evidence. A language model can optionally describe a path, but it never decides one."],
  ["What does it cost?", "Nothing. It's open source, and the AWS calls it makes are free reads."],
  ["Is it production-ready?", "It's a working research tool, validated on deliberately vulnerable test accounts and a real clean account. The Windows installer isn't code-signed yet, so Windows will warn on first launch. Fix pull requests and a pre-deploy gate are in progress."],
  ["Who built it?", "Piyush Singh — an independent, open-source project. Not affiliated with AWS."],
];

export function Faq() {
  const [open, setOpen] = useState<number | null>(0);
  return (
    <Section id="faq" className="bg-paper-2">
      <div className="grid gap-12 lg:grid-cols-[0.75fr_1.25fr]">
        <div>
          <Kicker n="06">FAQ</Kicker>
          <Title className="lg:text-6xl">Asked by every security team, first.</Title>
        </div>
        <ul className="border-t border-ink">
          {QA.map(([q, a], i) => {
            const isOpen = open === i;
            return (
              <li key={q} className="border-b border-ink/15">
                <h3>
                  <button
                    type="button"
                    id={`q-${i}`}
                    aria-expanded={isOpen}
                    aria-controls={`a-${i}`}
                    onClick={() => setOpen(isOpen ? null : i)}
                    className="flex min-h-16 w-full cursor-pointer items-center justify-between gap-6 py-5 text-left font-display text-xl font-bold tracking-tight sm:text-2xl"
                  >
                    {q}
                    <span
                      className={cn(
                        "flex size-10 shrink-0 items-center justify-center rounded-full border border-ink/20 transition-all duration-300",
                        isOpen && "rotate-45 border-ink bg-ink text-lime",
                      )}
                    >
                      <Plus className="size-5" aria-hidden />
                    </span>
                  </button>
                </h3>
                <AnimatePresence initial={false}>
                  {isOpen && (
                    <motion.div
                      id={`a-${i}`}
                      role="region"
                      aria-labelledby={`q-${i}`}
                      initial={{ height: 0, opacity: 0 }}
                      animate={{ height: "auto", opacity: 1 }}
                      exit={{ height: 0, opacity: 0 }}
                      transition={{ duration: 0.25, ease: [0.16, 1, 0.3, 1] }}
                      className="overflow-hidden"
                    >
                      <p className="max-w-2xl pb-6 text-lg leading-relaxed text-mute">{a}</p>
                    </motion.div>
                  )}
                </AnimatePresence>
              </li>
            );
          })}
        </ul>
      </div>
    </Section>
  );
}

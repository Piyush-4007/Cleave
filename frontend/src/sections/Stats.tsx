import { motion, useReducedMotion } from "motion/react";
import { Section } from "../components/ui";

const NUMBERS = [
  { n: "247", label: "findings.", body: "What your scanner returned.", tone: "dim" },
  { n: "3", label: "paths.", body: "The ones an attacker can actually walk to admin.", tone: "text" },
  { n: "1", label: "fix.", body: "The smallest change that breaks the most of them.", tone: "accent" },
] as const;

const toneClass = { dim: "text-[color:var(--line)]", text: "text-[color:var(--text)]", accent: "accent" };

export function Stats() {
  const reduce = useReducedMotion();
  return (
    <Section className="border-t border-[color:var(--line)] py-24">
      <h2 className="display mb-14 max-w-[24ch] text-[30px] leading-tight sm:text-[38px]">
        The same account, three ways of looking at it.
      </h2>

      <div className="grid grid-cols-1 gap-x-10 gap-y-10 md:grid-cols-3 md:divide-x md:divide-[color:var(--line)]">
        {NUMBERS.map((item, i) => (
          <motion.div
            key={item.label}
            initial={reduce ? false : { opacity: 0, y: 18 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true, amount: 0.4 }}
            transition={{ duration: 0.5, delay: i * 0.1 }}
            className="md:px-8 md:first:pl-0"
          >
            <div className={`display text-[84px] leading-[0.85] sm:text-[100px] ${toneClass[item.tone]}`}>
              {item.n}
            </div>
            <div className="display mt-5 text-[28px] leading-none">{item.label}</div>
            <p className="mt-3 max-w-[30ch] text-[15px] leading-relaxed text-[color:var(--muted)]">
              {item.body}
            </p>
          </motion.div>
        ))}
      </div>
    </Section>
  );
}

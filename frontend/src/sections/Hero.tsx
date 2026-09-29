import { motion, useReducedMotion } from "motion/react";
import { Section, Button } from "../components/ui";

export function Hero() {
  const reduce = useReducedMotion();
  const rise = (delay: number) => ({
    initial: reduce ? false : { opacity: 0, y: 22 },
    animate: { opacity: 1, y: 0 },
    transition: { duration: 0.6, delay, ease: [0.16, 1, 0.3, 1] as const },
  });

  return (
    <Section id="top" className="flex min-h-[calc(100dvh-68px)] flex-col justify-center py-16">
      <motion.p
        {...rise(0)}
        className="mono mb-8 text-[12px] uppercase tracking-[0.2em] text-[color:var(--muted)]"
      >
        Attack-path analysis for AWS <span className="text-[color:var(--dim)]">·</span> open{" "}
        <span className="text-[color:var(--dim)]">·</span> runs on your machine
      </motion.p>

      <motion.h1
        {...rise(0.08)}
        className="display max-w-[16ch] text-[46px] leading-[1.03] sm:text-[64px] lg:text-[76px]"
      >
        Find the attack paths in your AWS account.
      </motion.h1>

      <motion.p
        {...rise(0.18)}
        className="mt-7 max-w-[60ch] text-[18px] leading-relaxed text-[color:var(--text-2)]"
      >
        Cleave connects every resource and identity, follows the routes an attacker could walk to
        admin, and names the one change that breaks the most of them.
      </motion.p>

      <motion.div {...rise(0.28)} className="mt-10 flex flex-wrap items-center gap-3">
        <Button href="#start">Get started</Button>
        <a
          href="#start"
          className="mono inline-flex items-center gap-2 rounded-md border border-[color:var(--line)] px-5 py-2.5 text-[13px] text-[color:var(--text-2)] transition-colors hover:border-[color:var(--accent)]"
        >
          <span className="text-[color:var(--dim)]">$</span> docker compose up
        </a>
      </motion.div>
    </Section>
  );
}

import { motion, useReducedMotion } from "motion/react";
import { Section } from "../components/ui";

const STEPS = [
  ["01", "Collect", "A read-only snapshot of IAM, S3, EC2, VPC, Lambda, RDS, Secrets, KMS."],
  ["02", "Graph", "Every resource and identity becomes a node; every permission an edge."],
  ["03", "Search", "Walk from entry points to admin and to sensitive data. Rank what is found."],
  ["04", "Cut", "Compute the smallest set of changes that disconnects them."],
];

export function Method() {
  const reduce = useReducedMotion();
  return (
    <Section id="method" className="border-t border-[color:var(--line)] py-24">
      <h2 className="display mb-14 text-[32px] leading-tight sm:text-[40px]">
        Four steps, and no model in the loop.
      </h2>
      <div className="grid grid-cols-1 gap-px overflow-hidden rounded-lg border border-[color:var(--line)] bg-[color:var(--line)] sm:grid-cols-2 lg:grid-cols-4">
        {STEPS.map(([n, title, body], i) => (
          <motion.div
            key={n}
            initial={reduce ? false : { opacity: 0, y: 18 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true, amount: 0.4 }}
            transition={{ duration: 0.5, delay: i * 0.08 }}
            className="bg-[color:var(--bg)] p-6"
          >
            <div className="mono text-[13px] accent">{n}</div>
            <div className="display mt-3 text-[22px]">{title}</div>
            <p className="mt-2 text-[14px] leading-relaxed text-[color:var(--muted)]">{body}</p>
          </motion.div>
        ))}
      </div>
      <p className="mono mt-6 text-[12px] text-[color:var(--dim)]">
        Detection is deterministic. Same account in, same paths out. The language model only
        turns a found path into a sentence; switch it off and the findings are identical.
      </p>
    </Section>
  );
}

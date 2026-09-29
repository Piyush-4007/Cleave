import { motion, useReducedMotion } from "motion/react";
import { Section } from "../components/ui";

/* The credential-theft path Cleave validated live, drawn left to right.
   This is the product's own visual language (a path graph), not a screenshot mock. */
const NODES = [
  { x: 60, type: "internet", name: "anyone" },
  { x: 250, type: "ec2", name: "web-01" },
  { x: 440, type: "role", name: "web-app-role" },
  { x: 650, type: "s3", name: "prod-config/.env" },
  { x: 880, type: "role", name: "AdminRole" },
];
const EDGES = [
  { from: 0, to: 1, label: "reaches", cut: false },
  { from: 1, to: 2, label: "runs as", cut: false },
  { from: 2, to: 3, label: "reads", cut: true },
  { from: 3, to: 4, label: "unlocks", cut: false },
];
const NODE_W = 120;
const CY = 150;

export function PathShowcase() {
  const reduce = useReducedMotion();
  return (
    <Section className="border-t border-[color:var(--line)] py-24">
      <div className="max-w-[62ch]">
        <h2 className="display text-[34px] leading-tight sm:text-[42px]">
          The internet reaches an admin role through a config file.
        </h2>
        <p className="mt-4 text-[16px] leading-relaxed text-[color:var(--muted)]">
          No single step here is a finding. A reachable box, a role that can read a bucket, a
          key left in a file. Cleave follows the whole chain, then names the one edge to cut.
        </p>
      </div>

      <div className="mt-12 overflow-x-auto rounded-lg border border-[color:var(--line)] bg-[color:var(--panel)] p-6">
        <svg viewBox="0 0 1000 240" className="w-full min-w-[760px]" role="img"
             aria-label="Attack path from the internet to an admin role, with the cut edge marked">
          {EDGES.map((e, i) => {
            const a = NODES[e.from].x + NODE_W / 2;
            const b = NODES[e.to].x - NODE_W / 2;
            const mid = (a + b) / 2;
            const stroke = e.cut ? "var(--cut)" : "var(--dim)";
            return (
              <g key={i}>
                <motion.line
                  x1={a} y1={CY} x2={b} y2={CY}
                  stroke={stroke} strokeWidth={e.cut ? 2 : 1.4}
                  strokeDasharray={e.cut ? "6 5" : undefined}
                  initial={reduce ? false : { pathLength: 0, opacity: 0 }}
                  whileInView={{ pathLength: 1, opacity: 1 }}
                  viewport={{ once: true }}
                  transition={{ duration: 0.5, delay: 0.15 * i }}
                />
                <path d={`M${b - 8} ${CY - 4} L${b} ${CY} L${b - 8} ${CY + 4}`}
                      fill="none" stroke={stroke} strokeWidth={e.cut ? 2 : 1.4} />
                <text x={mid} y={CY - 12} textAnchor="middle"
                      className="mono" fontSize="11"
                      fill={e.cut ? "var(--cut)" : "var(--muted)"}>
                  {e.label}
                </text>
                {e.cut && (
                  <text x={mid} y={CY + 48} textAnchor="middle" className="mono" fontSize="10"
                        fill="var(--cut)">✕ cut, breaks 8 of 11</text>
                )}
              </g>
            );
          })}

          {NODES.map((node, i) => {
            const isSink = i === NODES.length - 1;
            const isSource = i === 0;
            return (
              <g key={node.name}>
                <rect
                  x={node.x - NODE_W / 2} y={CY - 26} width={NODE_W} height={52} rx={7}
                  fill="var(--panel-2)"
                  stroke={isSink ? "var(--cut)" : isSource ? "var(--accent)" : "var(--line)"}
                  strokeWidth={isSink || isSource ? 1.6 : 1}
                />
                <text x={node.x} y={CY - 6} textAnchor="middle" className="mono" fontSize="9.5"
                      fill="var(--dim)">{node.type}</text>
                <text x={node.x} y={CY + 12} textAnchor="middle" className="mono" fontSize="11"
                      fill="var(--text)">{node.name}</text>
              </g>
            );
          })}
        </svg>
      </div>
    </Section>
  );
}

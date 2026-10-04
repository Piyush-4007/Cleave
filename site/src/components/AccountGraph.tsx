import { useEffect, useMemo, useState } from "react";
import { motion, useReducedMotion } from "framer-motion";
import { RotateCcw } from "lucide-react";
import { cn } from "@/lib/utils";

// A whole account as a graph: ~70 grey resources, one lime path from the internet to admin,
// and a red cut that slices it. Positions are seeded so the picture is the same every load.

const W = 1200;
const H = 520;

const PATH = [
  { x: 90, y: 300, label: "internet" },
  { x: 300, y: 170, label: "s3://acme-backups" },
  { x: 500, y: 330, label: "key in deploy.env" },
  { x: 705, y: 190, label: "iam/ci-deploy" },
  { x: 905, y: 345, label: "λ nightly-report" },
  { x: 1105, y: 215, label: "AdminRole" },
];
const CUT_EDGE = 3; // ci-deploy -> lambda (iam:PassRole)

function rng(seed: number) {
  return () => {
    seed = (seed * 16807) % 2147483647;
    return (seed - 1) / 2147483646;
  };
}

function useGraph() {
  return useMemo(() => {
    const r = rng(42);
    const nodes: { x: number; y: number }[] = [];
    let guard = 0;
    while (nodes.length < 72 && guard++ < 4000) {
      const p = { x: 30 + r() * (W - 60), y: 30 + r() * (H - 60) };
      const clear = [...PATH, ...nodes].every((q) => Math.hypot(q.x - p.x, q.y - p.y) > 58);
      if (clear) nodes.push(p);
    }
    const all = [...nodes, ...PATH];
    const edges: [number, number][] = [];
    nodes.forEach((n, i) => {
      const near = all
        .map((m, j) => ({ j, d: Math.hypot(m.x - n.x, m.y - n.y) }))
        .filter((o) => o.j !== i)
        .sort((a, b) => a.d - b.d)
        .slice(0, 2);
      near.forEach((o) => edges.push([i, o.j]));
    });
    return { all, nodes, edges };
  }, []);
}

export function AccountGraph() {
  const reduce = useReducedMotion();
  const { all, nodes, edges } = useGraph();
  const [run, setRun] = useState(0);
  const [cut, setCut] = useState(!!reduce);

  useEffect(() => {
    if (reduce) return;
    setCut(false);
    const t = setTimeout(() => setCut(true), 2900);
    return () => clearTimeout(t);
  }, [run, reduce]);

  const a = PATH[CUT_EDGE];
  const b = PATH[CUT_EDGE + 1];
  const mx = (a.x + b.x) / 2;
  const my = (a.y + b.y) / 2;
  const ang = Math.atan2(b.y - a.y, b.x - a.x) + Math.PI / 2;
  const L = 46;

  return (
    <figure className="relative overflow-hidden rounded-[28px] bg-ink text-paper">
      <div aria-hidden className="dots-dark absolute inset-0" />

      <div className="relative flex flex-wrap items-center justify-between gap-3 px-5 pt-5 sm:px-7 sm:pt-6">
        <div className="flex items-center gap-2 font-mono text-xs text-mute-dark">
          <span className="size-2 rounded-full bg-lime" aria-hidden /> account 1234-5678-9012 · us-east-1 · read-only scan
        </div>
        <button
          type="button"
          onClick={() => setRun((n) => n + 1)}
          className="inline-flex min-h-10 cursor-pointer items-center gap-2 rounded-full border border-white/15 px-4 font-mono text-xs text-mute-dark transition-colors hover:border-white/40 hover:text-paper"
        >
          <RotateCcw className="size-3.5" aria-hidden /> Replay
        </button>
      </div>

      <svg
        key={run}
        viewBox={`0 0 ${W} ${H}`}
        className="relative block h-auto w-full"
        role="img"
        aria-label="An account graph of 78 resources. One path is highlighted from the internet, through a public bucket, a leaked key, the ci-deploy user and a Lambda function, to the AdminRole. A red cut on the PassRole step disconnects it."
      >
        {edges.map(([i, j], k) => (
          <line key={k} x1={all[i].x} y1={all[i].y} x2={all[j].x} y2={all[j].y} stroke="#fff" strokeOpacity="0.08" strokeWidth="1" />
        ))}
        {nodes.map((n, i) => (
          <circle key={i} cx={n.x} cy={n.y} r={i % 7 === 0 ? 5 : 3.2} fill="#fff" fillOpacity={i % 7 === 0 ? 0.28 : 0.18} />
        ))}

        {/* the path */}
        {PATH.slice(0, -1).map((p, i) => {
          const q = PATH[i + 1];
          const dead = cut && i >= CUT_EDGE;
          return (
            <motion.line
              key={i}
              x1={p.x}
              y1={p.y}
              x2={q.x}
              y2={q.y}
              strokeWidth={3}
              strokeLinecap="round"
              strokeDasharray={dead ? "6 8" : undefined}
              initial={reduce ? false : { pathLength: 0 }}
              animate={{ pathLength: 1, stroke: dead ? "#4a4a4a" : "#d4f53c" }}
              transition={{ pathLength: { delay: 0.4 + i * 0.4, duration: 0.4, ease: "easeInOut" }, stroke: { duration: 0.4 } }}
            />
          );
        })}

        {PATH.map((p, i) => {
          const dead = cut && i > CUT_EDGE;
          const sink = i === PATH.length - 1;
          const color = dead ? "#4a4a4a" : sink ? "#ff3b2f" : "#d4f53c";
          const above = i % 2 === 1;
          return (
            <motion.g
              key={i}
              initial={reduce ? false : { opacity: 0, scale: 0.4 }}
              animate={{ opacity: 1, scale: 1 }}
              transition={{ delay: 0.3 + i * 0.4, duration: 0.35 }}
              style={{ transformOrigin: `${p.x}px ${p.y}px` }}
            >
              {sink && !dead && <circle cx={p.x} cy={p.y} r="22" fill="#ff3b2f" fillOpacity="0.18" />}
              <circle cx={p.x} cy={p.y} r="10" fill="#0c0c0c" stroke={color} strokeWidth="3" style={{ transition: "stroke .4s" }} />
              <text
                x={p.x}
                y={above ? p.y - 24 : p.y + 36}
                textAnchor="middle"
                className="hidden font-mono sm:block"
                fontSize="15"
                fill={dead ? "#6b6b6b" : "#f2f0eb"}
                style={{ transition: "fill .4s" }}
              >
                {p.label}
              </text>
            </motion.g>
          );
        })}

        {/* the cut */}
        {cut && (
          <g>
            <motion.line
              x1={mx - Math.cos(ang) * L}
              y1={my - Math.sin(ang) * L}
              x2={mx + Math.cos(ang) * L}
              y2={my + Math.sin(ang) * L}
              stroke="#ff3b2f"
              strokeWidth="5"
              strokeLinecap="round"
              initial={reduce ? false : { pathLength: 0 }}
              animate={{ pathLength: 1 }}
              transition={{ duration: 0.25, ease: [0.7, 0, 0.3, 1] }}
            />
            <motion.g initial={reduce ? false : { opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.25 }}>
              <rect x={mx + 26} y={my - 64} width="150" height="30" rx="15" fill="#ff3b2f" />
              <text x={mx + 101} y={my - 44} textAnchor="middle" fontSize="14" fontWeight="600" fill="#0c0c0c" className="font-mono">
                CUT · iam:PassRole
              </text>
            </motion.g>
          </g>
        )}
      </svg>

      <figcaption className="relative grid grid-cols-2 border-t border-white/10 font-mono text-xs sm:grid-cols-4">
        {[
          ["78", "resources"],
          ["1", "path to admin"],
          ["5", "hops"],
          [cut ? "0" : "1", "paths after the cut"],
        ].map(([n, l], i) => (
          <div key={l} className={cn("px-5 py-4 sm:px-7", i > 0 && "border-l border-white/10", i === 2 && "max-sm:border-l-0 max-sm:border-t", i === 3 && "max-sm:border-t")}>
            <div className={cn("display text-3xl", i === 3 && (cut ? "text-lime" : "text-cut"))}>{n}</div>
            <div className="mt-1 text-mute-dark">{l}</div>
          </div>
        ))}
      </figcaption>
    </figure>
  );
}

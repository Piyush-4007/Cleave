import { useState } from "react";
import { useParams, useNavigate } from "react-router-dom";
import {
  Globe, Desktop, IdentificationBadge, UserCircle, Package, Lightning, Database,
  FileText, Crown, ArrowRight, Gear,
} from "@phosphor-icons/react";
import { useAnalysis } from "./useAnalysis";
import type { AttackPath, PathNode, CutEdge } from "./api";

const ICON: Record<string, React.ElementType> = {
  internet: Globe, ec2: Desktop, role: IdentificationBadge, user: UserCircle,
  s3: Package, lambda: Lightning, rds: Database, policy: FileText, admin: Crown,
  glue: Gear, sagemaker: Gear, codebuild: Gear, ecs: Package, secret: FileText,
  kms: FileText, sns: Lightning, sqs: Lightning, ecr: Package,
  dynamodb: Database, apigw: Globe, eks: Package,
};

function recommendedCut(path: AttackPath, fixes: CutEdge[]): number {
  let best = -1, bestCut = -1;
  path.hops.forEach((h, i) => {
    const m = fixes.find((f) => f.frm === h.frm && f.to === h.to && f.rel === h.rel);
    if (m && m.paths_cut > bestCut) { bestCut = m.paths_cut; best = i; }
  });
  return best;
}

export function PathViewer() {
  const { data, loading } = useAnalysis();
  const { id } = useParams();
  const nav = useNavigate();

  if (loading || !data) return <Loading />;
  const paths = data.paths;
  if (paths.length === 0)
    return <div className="mono p-10 text-[13px] text-[color:var(--muted)]">No attack paths in this scan.</div>;
  const path = paths.find((p) => p.id === id) ?? paths[0];

  return (
    <div className="grid grid-cols-1 lg:grid-cols-[248px_1fr_330px] lg:h-[calc(100dvh-60px)]">
      {/* ranked list */}
      <aside className="border-b border-[color:var(--line)] lg:overflow-y-auto lg:border-b-0 lg:border-r">
        <div className="mono px-5 py-4 text-[11px] uppercase tracking-[0.16em] text-[color:var(--dim)]">
          {paths.length} paths · by score
        </div>
        {paths.map((p) => {
          const active = p.id === path.id;
          return (
            <button
              key={p.id}
              onClick={() => nav(`/dashboard/paths/${p.id}`)}
              className={`block w-full border-l-2 px-5 py-3.5 text-left transition-colors ${
                active
                  ? "border-[color:var(--accent)] bg-[color:var(--panel)]"
                  : "border-transparent hover:bg-[color:var(--panel)]/60"
              }`}
            >
              <div className="flex items-baseline justify-between gap-2">
                <span className="mono text-[11px] text-[color:var(--dim)]">{p.id}</span>
                <span className={`mono text-[12px] ${active ? "accent" : "text-[color:var(--muted)]"}`}>
                  {p.score.toFixed(1)}
                </span>
              </div>
              <div className="mt-1 text-[13.5px] leading-snug text-[color:var(--text)]">{p.title}</div>
            </button>
          );
        })}
      </aside>

      <PathDetail key={path.id} path={path} fixes={data.best_single_fix} />
    </div>
  );
}

function PathDetail({ path, fixes }: { path: AttackPath; fixes: CutEdge[] }) {
  const cutIdx = recommendedCut(path, fixes);
  const cutHop = cutIdx >= 0 ? path.hops[cutIdx] : null;
  const [sel, setSel] = useState<PathNode>(path.nodes[path.nodes.length - 1]);

  return (
    <>
      <section className="px-6 py-8 lg:overflow-y-auto lg:px-10">
        <div className="mono text-[11px] uppercase tracking-[0.14em] text-[color:var(--muted)]">
          {path.source.kind.replace("_", " ")} <span className="text-[color:var(--dim)]">→</span>{" "}
          {path.sink.kind === "SENSITIVE_DATA" ? "sensitive data" : "admin"}{" "}
          <span className="text-[color:var(--dim)]">·</span>{" "}
          <span className={path.confidence === "Certain" ? "" : "cut"}>{path.confidence.toLowerCase()}</span>{" "}
          <span className="text-[color:var(--dim)]">·</span> score {path.score.toFixed(1)}
        </div>
        <h1 className="display mt-3 max-w-[22ch] text-[30px] leading-tight sm:text-[38px]">{path.title}</h1>
        {path.technique && (
          <div className="mt-4 inline-flex rounded-full border border-[color:var(--line)] px-3 py-1 text-[12px] text-[color:var(--muted)]">
            technique · {path.technique}
          </div>
        )}

        <ol className="mt-10">
          {path.nodes.map((node, i) => {
            const inHop = i > 0 ? path.hops[i - 1] : null;
            const isCutTarget = cutIdx >= 0 && i - 1 === cutIdx;
            const Icon = ICON[node.type] ?? IdentificationBadge;
            const isSource = i === 0;
            const isSink = i === path.nodes.length - 1;
            return (
              <li key={node.id + i} className="grid grid-cols-[150px_1fr] gap-4">
                {/* left: incoming relation label */}
                <div className="pt-1 text-right">
                  {inHop && (
                    <span className={`mono text-[11px] ${isCutTarget ? "cut" : "text-[color:var(--muted)]"}`}>
                      {inHop.rel.toLowerCase().replace(/_/g, " ")}
                    </span>
                  )}
                </div>
                {/* right: connector + node */}
                <div className="relative pb-8">
                  {/* connector line up from this marker */}
                  {i > 0 && (
                    <span
                      className="absolute -top-8 left-[7px] h-8 w-px"
                      style={{ background: isCutTarget ? "var(--cut)" : "var(--line)" }}
                    />
                  )}
                  <div className="flex items-start gap-3">
                    <span
                      className="mt-1 grid h-[15px] w-[15px] shrink-0 place-items-center rounded-full border-2"
                      style={{
                        borderColor: isCutTarget ? "var(--cut)" : isSource ? "var(--accent)" : isSink ? "var(--accent)" : "var(--muted)",
                        background: "var(--bg)",
                      }}
                    />
                    <button onClick={() => setSel(node)} className="min-w-0 text-left">
                      <div className="flex items-center gap-2">
                        <Icon size={15} className="text-[color:var(--muted)]" weight={isSink ? "fill" : "regular"} />
                        <span className="mono text-[14px] text-[color:var(--text)]">{node.name}</span>
                        <span className="mono text-[10px] text-[color:var(--dim)]">{node.type}</span>
                      </div>
                      {inHop && (
                        <p className="mt-1 max-w-[52ch] text-[13.5px] leading-relaxed text-[color:var(--muted)]">
                          {inHop.reason}.
                        </p>
                      )}
                    </button>
                  </div>

                  {isCutTarget && cutHop && (
                    <div className="ml-6 mt-3 rounded-lg border border-[color:var(--cut)]/40 bg-[color:var(--cut)]/8 px-4 py-3">
                      <div className="mono text-[12px] cut">✕ cut this edge</div>
                      <p className="mt-1 text-[13px] leading-relaxed text-[color:var(--text-2)]">
                        {fixes.find((f) => f.frm === cutHop.frm && f.to === cutHop.to && f.rel === cutHop.rel)?.fix}.
                        {" "}Breaks{" "}
                        <span className="cut">{fixes.find((f) => f.frm === cutHop.frm && f.rel === cutHop.rel)?.paths_cut}</span>{" "}
                        of {path.hops.length && fixes[0]?.paths_total} paths.
                      </p>
                    </div>
                  )}
                </div>
              </li>
            );
          })}
        </ol>
      </section>

      <Inspector node={sel} />
    </>
  );
}

function Inspector({ node }: { node: PathNode }) {
  return (
    <aside className="border-t border-[color:var(--line)] bg-[color:var(--panel)]/40 px-6 py-6 lg:overflow-y-auto lg:border-l lg:border-t-0">
      <div className="mono text-[11px] uppercase tracking-[0.16em] text-[color:var(--dim)]">
        inspector · {node.type}
      </div>
      <div className="mono mt-3 break-all text-[13px] text-[color:var(--text)]">{node.name}</div>
      {node.detail?.arn && (
        <div className="mono mt-1 break-all text-[11px] text-[color:var(--dim)]">{node.detail.arn}</div>
      )}

      {node.detail?.policy && (
        <pre className="mono mt-5 overflow-x-auto rounded-md border border-[color:var(--line)] bg-[color:var(--bg)] p-3 text-[11.5px] leading-relaxed text-[color:var(--text-2)]">
          {node.detail.policy}
        </pre>
      )}

      {node.detail?.facts && (
        <dl className="mt-5 space-y-2.5">
          {node.detail.facts.map(([k, v]) => (
            <div key={k} className="flex items-baseline justify-between gap-4">
              <dt className="mono text-[11px] text-[color:var(--dim)]">{k}</dt>
              <dd className="mono text-right text-[11.5px] text-[color:var(--text-2)]">{v}</dd>
            </div>
          ))}
        </dl>
      )}

      <a
        href="/dashboard/remediation"
        className="mt-7 inline-flex items-center gap-2 rounded-md bg-[color:var(--accent)] px-4 py-2 text-[13px] font-medium text-[color:var(--accent-ink)]"
      >
        Open fix in remediation <ArrowRight size={14} />
      </a>
    </aside>
  );
}

function Loading() {
  return <div className="mono p-10 text-[13px] text-[color:var(--muted)]">Loading analysis…</div>;
}

import { useState } from "react";
import { useParams, useNavigate } from "react-router-dom";
import {
  Globe, Desktop, IdentificationBadge, UserCircle, Package, Lightning, Database,
  FileText, Crown, ArrowRight, Gear, Graph, ListBullets,
} from "@phosphor-icons/react";
import { useAnalysis } from "./useAnalysis";
import { PathGraph } from "./PathGraph";
import type { AttackPath, PathNode, CutEdge } from "./api";

const ICON: Record<string, React.ElementType> = {
  internet: Globe, ec2: Desktop, role: IdentificationBadge, user: UserCircle,
  s3: Package, lambda: Lightning, rds: Database, policy: FileText, admin: Crown,
  glue: Gear, sagemaker: Gear, codebuild: Gear, ecs: Package, secret: FileText,
  kms: FileText, sns: Lightning, sqs: Lightning, ecr: Package,
  dynamodb: Database, apigw: Globe, eks: Package,
};

type View = "graph" | "list";

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
  const [view, setView] = useState<View>("graph");

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

      <PathWorkspace
        key={path.id}
        path={path}
        allPaths={paths}
        fixes={data.best_single_fix}
        cut={data.minimum_cut.edges.length ? data.minimum_cut.edges : data.best_single_fix}
        view={view}
        setView={setView}
        onSelectPath={(pid) => nav(`/dashboard/paths/${pid}`)}
      />
    </div>
  );
}

function ViewToggle({ view, setView }: { view: View; setView: (v: View) => void }) {
  const Btn = ({ v, Icon, label }: { v: View; Icon: React.ElementType; label: string }) => (
    <button
      onClick={() => setView(v)}
      className={`flex items-center gap-1.5 rounded-md px-2.5 py-1 text-[11px] transition-colors ${
        view === v
          ? "bg-[color:var(--accent)] text-[color:var(--accent-ink)]"
          : "text-[color:var(--muted)] hover:text-[color:var(--text)]"
      }`}
    >
      <Icon size={13} /> {label}
    </button>
  );
  return (
    <div className="flex items-center gap-0.5 rounded-lg border border-[color:var(--line)] p-0.5">
      <Btn v="graph" Icon={Graph} label="Graph" />
      <Btn v="list" Icon={ListBullets} label="List" />
    </div>
  );
}

function PathWorkspace({ path, allPaths, fixes, cut, view, setView, onSelectPath }: {
  path: AttackPath; allPaths: AttackPath[]; fixes: CutEdge[]; cut: CutEdge[];
  view: View; setView: (v: View) => void; onSelectPath: (id: string) => void;
}) {
  const [sel, setSel] = useState<PathNode>(path.nodes[path.nodes.length - 1]);

  return (
    <>
      <section className="flex flex-col lg:overflow-hidden">
        {/* header: path meta + view toggle */}
        <div className="flex items-start justify-between gap-4 border-b border-[color:var(--line)] px-6 py-4 lg:px-10">
          <div className="min-w-0">
            <div className="mono text-[11px] uppercase tracking-[0.14em] text-[color:var(--muted)]">
              {path.source.kind.replace("_", " ")} <span className="text-[color:var(--dim)]">→</span>{" "}
              {path.sink.kind === "SENSITIVE_DATA" ? "sensitive data" : "admin"}{" "}
              <span className="text-[color:var(--dim)]">·</span>{" "}
              <span className={path.confidence === "Certain" ? "" : "cut"}>{path.confidence.toLowerCase()}</span>{" "}
              <span className="text-[color:var(--dim)]">·</span> score {path.score.toFixed(1)}
            </div>
            <div className="mt-1 truncate text-[15px] text-[color:var(--text)] lg:text-[16px]">{path.title}</div>
          </div>
          <ViewToggle view={view} setView={setView} />
        </div>

        {view === "graph" ? (
          <div className="h-[70vh] lg:h-auto lg:min-h-0 lg:flex-1">
            <PathGraph
              paths={allPaths}
              cutEdges={cut}
              selectedId={path.id}
              onSelectNode={setSel}
              onSelectPath={onSelectPath}
            />
          </div>
        ) : (
          <div className="px-6 py-8 lg:overflow-y-auto lg:px-10">
            <PathTimeline path={path} fixes={fixes} onSelect={setSel} />
          </div>
        )}
      </section>

      <Inspector node={sel} />
    </>
  );
}

function PathTimeline({ path, fixes, onSelect }: {
  path: AttackPath; fixes: CutEdge[]; onSelect: (n: PathNode) => void;
}) {
  const cutIdx = recommendedCut(path, fixes);
  const cutHop = cutIdx >= 0 ? path.hops[cutIdx] : null;
  return (
    <>
      {path.technique && (
        <div className="mb-8 inline-flex rounded-full border border-[color:var(--line)] px-3 py-1 text-[12px] text-[color:var(--muted)]">
          technique · {path.technique}
        </div>
      )}
      <ol>
        {path.nodes.map((node, i) => {
          const inHop = i > 0 ? path.hops[i - 1] : null;
          const isCutTarget = cutIdx >= 0 && i - 1 === cutIdx;
          const Icon = ICON[node.type] ?? IdentificationBadge;
          const isSource = i === 0;
          const isSink = i === path.nodes.length - 1;
          return (
            <li key={node.id + i} className="grid grid-cols-[150px_1fr] gap-4">
              <div className="pt-1 text-right">
                {inHop && (
                  <span className={`mono text-[11px] ${isCutTarget ? "cut" : "text-[color:var(--muted)]"}`}>
                    {inHop.rel.toLowerCase().replace(/_/g, " ")}
                  </span>
                )}
              </div>
              <div className="relative pb-8">
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
                  <button onClick={() => onSelect(node)} className="min-w-0 text-left">
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

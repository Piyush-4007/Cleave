/*
  The attack-path graph — the handbook's "star": the discovered paths drawn as one
  left-to-right node-link diagram that fans in and converges on the sink, with the minimum
  cut in red. HARD RULE (handbook): only ever the path subgraph (the union of the paths),
  never the full account graph. Cytoscape + dagre for the layered layout; colours are read
  from the live CSS theme tokens so it tracks dark/light and the two brand identities.
*/
import { useEffect, useRef } from "react";
import cytoscape from "cytoscape";
import dagre from "cytoscape-dagre";
import type { AttackPath, PathNode, CutEdge } from "./api";

cytoscape.use(dagre);

const humanize = (rel: string) => rel.toLowerCase().replace(/_/g, " ");

function tokens() {
  const s = getComputedStyle(document.documentElement);
  const v = (n: string) => s.getPropertyValue(n).trim();
  return {
    bg: v("--bg"), panel: v("--panel"), line: v("--line"), muted: v("--muted"),
    dim: v("--dim"), accent: v("--accent"), accentInk: v("--accent-ink"),
    cut: v("--cut"), text: v("--text"), text2: v("--text-2"),
  };
}

function stylesheet(t: ReturnType<typeof tokens>): any {
  return [
    {
      selector: "node",
      style: {
        shape: "round-rectangle", "background-color": t.panel,
        "border-width": 1.5, "border-color": t.line,
        label: "data(label)", color: t.text,
        "font-family": "'Geist Mono', ui-monospace, monospace", "font-size": 13,
        "text-valign": "center", "text-halign": "center", "line-height": 1.3,
        width: "label", height: "label",
        padding: "13px", "text-max-width": "200px", "text-wrap": "ellipsis",
      },
    },
    { selector: 'node[kind = "source"]',
      style: { "border-color": t.accent, "border-width": 2 } },
    { selector: 'node[kind = "sink"]',
      style: { "background-color": t.accent, color: t.accentInk,
               "border-color": t.accent, "border-width": 2, "font-weight": 600 } },
    {
      selector: "edge",
      style: {
        "curve-style": "bezier", width: 1.6, "line-color": t.line,
        "target-arrow-shape": "triangle", "target-arrow-color": t.line,
        "arrow-scale": 0.9,
        label: "data(label)", color: t.muted,
        "font-family": "'Geist Mono', ui-monospace, monospace", "font-size": 10,
        "text-background-color": t.bg, "text-background-opacity": 1,
        "text-background-padding": "2px", "text-rotation": "none" as any,
      },
    },
    { selector: "edge.sel",
      style: { "line-color": t.accent, "target-arrow-color": t.accent,
               width: 2.4, color: t.text2 } },
    { selector: "edge.cut",
      style: { "line-color": t.cut, "target-arrow-color": t.cut, width: 3,
               label: "data(cutLabel)", color: t.cut, "font-weight": 600,
               "line-style": "dashed", "line-dash-pattern": [7, 4], "z-index": 10 } },
    { selector: ".dim", style: { opacity: 0.3 } },
  ];
}

interface Props {
  paths: AttackPath[];
  cutEdges: CutEdge[];
  selectedId: string;
  onSelectNode: (n: PathNode) => void;
  onSelectPath: (id: string) => void;
}

export function PathGraph({ paths, cutEdges, selectedId, onSelectNode, onSelectPath }: Props) {
  const box = useRef<HTMLDivElement>(null);
  const cyRef = useRef<cytoscape.Core | null>(null);

  // Build the union of nodes + edges once per data change. Edges are derived from each
  // path's ORDERED nodes (guaranteeing valid endpoints); the hop supplies the label, the
  // cut flag (matched on the backend uids), and the reason.
  const nodeMap = new Map<string, PathNode>();
  const sources = new Set<string>();
  const sinks = new Set<string>();
  paths.forEach((p) => {
    p.nodes.forEach((n) => { if (!nodeMap.has(n.id)) nodeMap.set(n.id, n); });
    if (p.nodes[0]) sources.add(p.nodes[0].id);
    const last = p.nodes[p.nodes.length - 1];
    if (last) sinks.add(last.id);
  });
  const isCut = (h?: { frm: string; to: string; rel: string }) =>
    !!h && cutEdges.some((f) => f.frm === h.frm && f.to === h.to && f.rel === h.rel);

  type E = { id: string; source: string; target: string; rel: string; cut: boolean; paths: Set<string> };
  const edgeMap = new Map<string, E>();
  paths.forEach((p) => {
    for (let i = 1; i < p.nodes.length; i++) {
      const src = p.nodes[i - 1].id, tgt = p.nodes[i].id, h = p.hops[i - 1];
      const key = `${src}|${tgt}|${h?.rel ?? ""}`;
      const e = edgeMap.get(key) ?? { id: key, source: src, target: tgt, rel: h?.rel ?? "",
                                      cut: isCut(h), paths: new Set<string>() };
      e.paths.add(p.id);
      edgeMap.set(key, e);
    }
  });

  const elements: cytoscape.ElementDefinition[] = [
    ...[...nodeMap.values()].map((n) => ({
      data: { id: n.id, label: `${n.name}\n${n.type}`,
              kind: sources.has(n.id) ? "source" : sinks.has(n.id) ? "sink" : "mid" },
    })),
    ...[...edgeMap.values()].map((e) => ({
      data: { id: e.id, source: e.source, target: e.target, label: humanize(e.rel),
              cutLabel: `✕ ${humanize(e.rel)}`, cut: e.cut },
    })),
  ];

  // init once
  useEffect(() => {
    if (!box.current) return;
    const cy = cytoscape({
      container: box.current, elements, style: stylesheet(tokens()),
      minZoom: 0.3, maxZoom: 2.2, wheelSensitivity: 0.2,
      autoungrabify: true, boxSelectionEnabled: false,
    });
    cyRef.current = cy;
    const layout = cy.layout({ name: "dagre", rankDir: "LR", nodeSep: 46, rankSep: 115,
                               edgeSep: 14, padding: 30 } as any);
    layout.one("layoutstop", () => {
      cy.fit(undefined, 34);
      if (cy.zoom() < 0.78) { cy.zoom(0.78); cy.center(); } // keep nodes readable
    });
    layout.run();
    cy.on("tap", "node", (ev) => {
      const n = nodeMap.get(ev.target.id());
      if (n) onSelectNode(n);
    });
    cy.on("tap", "edge", (ev) => {
      const ps = [...edgeMap.get(ev.target.id())?.paths ?? []];
      if (ps.length) onSelectPath(ps.includes(selectedId) ? selectedId : ps[0]);
    });

    const ro = new ResizeObserver(() => { cy.resize(); cy.fit(undefined, 24); });
    ro.observe(box.current);

    // re-theme on dark/light or brand switch
    const mo = new MutationObserver(() => cy.style(stylesheet(tokens()) as any));
    mo.observe(document.documentElement, { attributes: true, attributeFilter: ["data-theme"] });
    const mq = window.matchMedia("(prefers-color-scheme: dark)");
    const onScheme = () => cy.style(stylesheet(tokens()) as any);
    mq.addEventListener("change", onScheme);

    return () => { ro.disconnect(); mo.disconnect(); mq.removeEventListener("change", onScheme); cy.destroy(); };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [paths]);

  // highlight the selected path; dim the rest; the cut always stays red
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;
    const sel = paths.find((p) => p.id === selectedId);
    const selNodes = new Set(sel?.nodes.map((n) => n.id));
    const selEdges = new Set<string>();
    if (sel) for (let i = 1; i < sel.nodes.length; i++)
      selEdges.add(`${sel.nodes[i - 1].id}|${sel.nodes[i].id}|${sel.hops[i - 1]?.rel ?? ""}`);

    cy.batch(() => {
      cy.elements().removeClass("sel dim");
      if (!sel) return;
      cy.edges().forEach((e) => {
        if (selEdges.has(e.id())) e.addClass("sel");
        else if (!e.data("cut")) e.addClass("dim");
      });
      cy.nodes().forEach((n) => { if (!selNodes.has(n.id())) n.addClass("dim"); });
    });
  }, [selectedId, paths]);

  return (
    <div className="relative h-full min-h-[360px]">
      <div ref={box} className="h-full w-full" />
      {/* legend */}
      <div className="pointer-events-none absolute bottom-3 left-3 flex flex-wrap gap-x-4 gap-y-1 rounded-md border border-[color:var(--line)] bg-[color:var(--panel)]/85 px-3 py-2 text-[10.5px] mono text-[color:var(--muted)] backdrop-blur">
        <span className="flex items-center gap-1.5"><i className="inline-block h-2 w-2 rounded-sm border-2" style={{ borderColor: "var(--accent)" }} />entry</span>
        <span className="flex items-center gap-1.5"><i className="inline-block h-2 w-2 rounded-sm" style={{ background: "var(--accent)" }} />admin / sink</span>
        <span className="flex items-center gap-1.5"><i className="inline-block w-4" style={{ borderTop: "2px dashed var(--cut)" }} /><span className="cut">minimum cut</span></span>
        <span className="text-[color:var(--dim)]">click a node to inspect</span>
      </div>
    </div>
  );
}

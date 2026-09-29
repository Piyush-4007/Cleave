/*
  Dashboard data layer.

  Types mirror the backend `/analysis` API (cleave.paths.analysis). The client tries the
  live backend first and falls back to the bundled mock, so the dashboard is demo-able with
  no backend running, and wiring to real data is just the fetch succeeding. The live account
  currently returns zero paths, which is why the mock carries a realistic set.
*/

export type SourceKind = "EXTERNAL" | "ASSUMED_COMPROMISE";
export type SinkKind = "ADMIN" | "SENSITIVE_DATA";
export type Confidence = "Certain" | "Possible";

export interface Hop {
  frm: string;
  to: string;
  rel: string;
  reason: string;
  confidence: Confidence;
}

export interface PathNode {
  id: string;
  type: string; // aws resource kind, e.g. "role", "s3", "ec2"
  name: string;
  detail?: {
    arn?: string;
    policy?: string; // raw policy JSON, shown in the inspector
    facts?: [string, string][]; // key/value rows (attached via, last used, trust...)
  };
}

export interface AttackPath {
  id: string;
  rank: number;
  title: string; // the narrated headline
  source: { name: string; kind: SourceKind };
  sink: { name: string; kind: SinkKind };
  score: number;
  confidence: Confidence;
  technique: string | null;
  nodes: PathNode[]; // ordered stops, source first, sink last
  hops: Hop[]; // nodes[i] -> nodes[i+1]
}

export interface CutEdge {
  frm: string;
  to: string;
  rel: string;
  cost: number;
  fix: string;
  paths_cut: number;
  paths_total: number;
}

export interface Analysis {
  source: "neo4j" | "raw" | "mock";
  account: string;
  generated_at: string;
  summary: {
    resources: number;
    sources: number;
    sources_external: number;
    paths_found: number;
    sinks_admin: number;
    sinks_sensitive_data: number;
    top_score: number;
    best_single_fix: { fix: string; breaks: number; of: number; cost: number } | null;
  };
  paths: AttackPath[];
  minimum_cut: { edges: CutEdge[]; total_cost: number; paths_total: number };
  best_single_fix: CutEdge[];
}

// ---- client ------------------------------------------------------------------------

import { MOCK } from "./mock";

const API_BASE = import.meta.env.VITE_API_BASE ?? "http://localhost:8000";

export async function getAnalysis(): Promise<Analysis> {
  try {
    const r = await fetch(`${API_BASE}/analysis`, { signal: AbortSignal.timeout(2500) });
    if (r.ok) {
      const live = await r.json();
      // A scanned-but-clean account has no paths; the mock is more useful for the demo.
      if (live?.paths?.length) return mapLive(live);
    }
  } catch {
    /* backend not running — fall back to the mock */
  }
  return MOCK;
}

// Map the live /analysis response onto the UI types. The backend enriches each path with
// `view` (node names, types, inspector detail) and `title`, so live data renders as richly
// as the mock.
function mapLive(a: any): Analysis {
  const paths: AttackPath[] = (a.paths ?? []).map((d: any) => ({
    id: d.id,
    rank: d.rank,
    title: d.title ?? `${d.source?.kind} to ${d.sink?.kind}`,
    source: { name: d.view?.[0]?.name ?? d.source?.uid, kind: d.source?.kind },
    sink: { name: d.view?.[d.view.length - 1]?.name ?? d.sink?.uid, kind: d.sink?.kind },
    score: d.ranking?.score ?? 0,
    confidence: d.confidence,
    technique: d.ranking?.technique ?? null,
    nodes: (d.view ?? []).map((v: any) => ({ id: v.id, type: v.type, name: v.name, detail: v.detail ?? undefined })),
    hops: (d.hops ?? []).map((h: any) => ({ frm: h.frm, to: h.to, rel: h.rel, reason: h.reason, confidence: h.confidence })),
  }));

  const mapEdge = (e: any): CutEdge => ({
    frm: e.frm, to: e.to, rel: e.rel, cost: e.cost,
    fix: e.fix, paths_cut: e.paths_cut ?? 0, paths_total: e.paths_total ?? a.summary?.paths_found ?? paths.length,
  });

  return {
    source: a.source ?? "neo4j",
    account: a.account ?? "connected account",
    generated_at: a.generated_at ?? new Date().toISOString(),
    summary: {
      resources: a.graph?.nodes ?? 0,
      sources: a.summary?.sources ?? 0,
      sources_external: a.summary?.sources_external ?? 0,
      paths_found: a.summary?.paths_found ?? paths.length,
      sinks_admin: a.summary?.sinks_admin ?? 0,
      sinks_sensitive_data: a.summary?.sinks_sensitive_data ?? 0,
      top_score: a.summary?.top_score ?? 0,
      best_single_fix: a.summary?.best_single_fix ?? null,
    },
    paths,
    minimum_cut: {
      edges: (a.minimum_cut?.edges ?? []).map(mapEdge),
      total_cost: a.minimum_cut?.total_cost ?? 0,
      paths_total: a.minimum_cut?.paths_total ?? paths.length,
    },
    best_single_fix: (a.best_single_fix ?? []).map(mapEdge),
  };
}

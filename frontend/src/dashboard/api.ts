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

// Minimal mapper from the live API shape onto the UI types. The live subgraph endpoint
// does not yet return per-node policy detail, so the inspector shows less on live data
// until the backend `_node_view` is extended (tracked in REQUIREMENTS.md).
function mapLive(a: any): Analysis {
  return { ...MOCK, source: a.source ?? "neo4j", summary: { ...MOCK.summary, ...a.summary } };
}

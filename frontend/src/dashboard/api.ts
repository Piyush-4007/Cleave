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

export interface ScanInfo {
  mode: "login" | "role" | "cli";
  scanned_at: string; // ISO
  // who the scan ran as (absent on older saved scans)
  alias?: string | null;
  arn?: string;
  principal_type?: "user" | "role" | "root" | "unknown";
  principal_name?: string;
  role_arn?: string | null; // the role assumed, in role mode (lets "rescan" repeat it)
  admin_credentials?: boolean | null;
  resources?: number;
  duration_s?: number;
}

export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type Reachability = "on_path" | "entry_point" | "account" | "not_reachable";

/** One per-resource finding (the Nessus-style layer), tagged by reachability. */
export interface Finding {
  id: string;
  rank: number;
  check: string; // e.g. "IAM.USER_NO_MFA"
  title: string;
  service: string;
  severity: Severity;
  base_severity: Severity;
  severity_reason: string | null;
  cis: string | null; // CIS AWS Foundations v3.0.0 control, if one applies
  caveat?: string | null; // honest limit of what a read-only scan can see (e.g. EKS)
  remediation: string;
  resource: string;
  resource_name: string;
  region: string | null;
  evidence: string;
  reachability: Reachability;
  paths: string[]; // attack path ids this finding sits on
}

export interface FindingsSummary {
  total: number;
  by_severity: Record<Severity, number>;
  by_reachability: Record<Reachability, number>;
  checks_run: number;
  checks_failed: number;
}

export interface Analysis {
  source: "neo4j" | "raw" | "mock" | "scan";
  account: string;
  generated_at: string;
  scan?: ScanInfo; // absent for the mock and older dumps
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
  findings: Finding[];
  findings_summary: FindingsSummary | null;
}

// ---- client ------------------------------------------------------------------------

import { MOCK } from "./mock";
import { DESKTOP } from "../desktop";

const API_BASE = DESKTOP?.apiBase ?? import.meta.env.VITE_API_BASE ?? "http://localhost:8000";

/** Every call carries the desktop token when there is one. */
function api(path: string, init: RequestInit = {}): Promise<Response> {
  const headers = new Headers(init.headers);
  if (DESKTOP) headers.set("X-Cleave-Token", DESKTOP.token);
  return fetch(`${API_BASE}${path}`, { ...init, headers });
}

/** Desktop: the backend starts alongside the window, so wait for it (up to ~30s). */
export async function waitForBackend(timeoutMs = 30000): Promise<void> {
  const until = Date.now() + timeoutMs;
  while (Date.now() < until) {
    try {
      const r = await fetch(`${API_BASE}/health`, { signal: AbortSignal.timeout(1500) });
      if (r.ok) return;
    } catch {
      /* not up yet */
    }
    await new Promise((res) => setTimeout(res, 300));
  }
  throw new Error("The Cleave engine did not start. Try reopening the app.");
}

export async function getAnalysis(): Promise<Analysis> {
  if (DESKTOP) {
    // Never show the sample account in the desktop app: it would read as the user's own
    // result. Wait for the engine and surface a real error instead.
    await waitForBackend();
    const r = await api("/analysis");
    if (!r.ok) throw new Error(`analysis failed (${r.status})`);
    return mapLive(await r.json());
  }
  try {
    const r = await api("/analysis", { signal: AbortSignal.timeout(3000) });
    if (r.ok) return mapLive(await r.json());
  } catch {
    /* backend not running (e.g. the landing's live-demo peek) — show the sample account */
  }
  return MOCK;
}

export interface Connection {
  connected: boolean;
  scanning: boolean;
  account: string | null;
  mode: string | null;
  paths_found: number | null;
  last_scan: { account: string; mode: string; scanned_at: string } | null;
}

export async function getConnection(): Promise<Connection> {
  const r = await api("/connection");
  if (!r.ok) throw new Error(`connection check failed (${r.status})`);
  return r.json();
}

/** Connect to an AWS account and scan it. mode "login" = the machine's AWS creds; "role" =
 *  assume the read-only role. Read-only, local-first. Returns when the scan completes. */
export async function connect(mode: "login" | "role", roleArn?: string): Promise<Connection> {
  const r = await api("/scan", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ mode, role_arn: roleArn ?? null }),
  });
  if (!r.ok) {
    const err = await r.json().catch(() => ({ detail: r.statusText }));
    throw new Error(err.detail || "scan failed");
  }
  return r.json();
}

/** Forget the connected account on this machine. Cleave holds no AWS credentials, so
 *  nothing is revoked; the current scan (and, if asked, its history) is deleted. */
export async function disconnect(forgetHistory: boolean): Promise<{ history_deleted: number }> {
  const r = await api("/disconnect", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ forget_history: forgetHistory }),
  });
  if (!r.ok) throw new Error(`disconnect failed (${r.status})`);
  return r.json();
}

export interface ScanRecord {
  id: number;
  account: string;
  alias: string | null;
  arn: string | null;
  principal_name: string | null;
  principal_type: string | null;
  mode: string | null;
  scanned_at: string;
  duration_s: number | null;
  resources: number | null;
  paths_found: number;
  findings_total: number;
  on_path: number;
  by_severity: Partial<Record<Severity, number>>;
  delta: null | { previous_id: number; findings_new: number; findings_newly_checked: number;
    findings_resolved: number; paths_new: number; paths_resolved: number };
}

export interface HistoryFinding {
  key: string; check_id: string; resource: string; resource_name: string; title: string;
  severity: Severity; reachability: Reachability; evidence: string;
  newly_checked?: boolean; // from a check the previous scan did not run: seen now, not introduced now
}
export interface HistoryPath { key: string; path_id: string; title: string; score: number }

export interface HistoryDiff {
  scan: ScanRecord;
  previous: ScanRecord | null;
  coverage_changed: boolean;
  findings: { new: HistoryFinding[]; resolved: HistoryFinding[]; unchanged: number };
  paths: { new: HistoryPath[]; resolved: HistoryPath[]; unchanged: number };
}

/** Stored scans (newest first); [] when there is no backend (web demo). */
export async function getHistory(account?: string): Promise<ScanRecord[]> {
  try {
    const r = await api(`/history${account ? `?account=${encodeURIComponent(account)}` : ""}`);
    return r.ok ? r.json() : [];
  } catch {
    return [];
  }
}

export async function getHistoryDiff(id: number): Promise<HistoryDiff> {
  const r = await api(`/history/${id}`);
  if (!r.ok) throw new Error(`history ${id} failed (${r.status})`);
  return r.json();
}

/** "cleave-dev (IAM user)" — who a scan ran as, in one phrase. */
export function whoLabel(s?: { principal_name?: string | null; principal_type?: string | null } | null): string | null {
  if (!s?.principal_name) return null;
  const kind = s.principal_type === "role" ? "IAM role" : s.principal_type === "user" ? "IAM user" : null;
  return s.principal_type === "root" ? "root account" : kind ? `${s.principal_name} (${kind})` : s.principal_name;
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
    scan: a.last_scan ?? undefined,
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
    findings: a.findings ?? [],
    findings_summary: a.findings_summary ?? null,
  };
}

export type ResultStatus =
  | "PASS"
  | "FAIL"
  | "NOT_APPLICABLE"
  | "UNKNOWN"
  | "ERROR"
  | "MANUAL_REQUIRED";

export interface Problem {
  title: string;
  status: number;
  code: string;
  detail: string;
  request_id: string;
  errors?: Array<{ field: string; code: string }>;
}

export interface Page<T> {
  items: T[];
  next_cursor: string | null;
}

export interface PrincipalView {
  user_id: string;
  org_id: string;
  roles: string[];
  site_ids: string[];
  csrf_token: string;
}

let csrfToken: string | null = null;
export function setCsrfToken(value: string | null) { csrfToken = value; }

export interface Asset {
  id: string;
  org_id: string;
  site_id: string;
  category: "windows" | "linux" | "firewall" | "router" | "switch";
  name: string;
  address: string;
  port: number;
  adapter_id: string;
  declared_role: string;
  identity: Record<string, unknown> | null;
  criticality: "critical" | "high" | "normal" | "low";
  owner_id: string | null;
  tags: Record<string, string>;
  archived_at: string | null;
}

export interface Scan {
  scan_id: string;
  status: string;
  target_count: number;
  policy_revision_id: string;
  created_at: string;
}

export interface Site {
  id: string;
  org_id: string;
  name: string;
  timezone: string;
  scope: {
    allowed_cidrs: string[];
    allowed_dns_suffixes: string[];
    allowed_ports: number[];
  };
}

export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
    readonly requestId: string,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

export async function apiGet<T>(path: string, signal?: AbortSignal): Promise<T> {
  const response = await fetch(path, {
    method: "GET",
    credentials: "same-origin",
    headers: { Accept: "application/json, application/problem+json" },
    signal,
  });
  const body: unknown = await response.json().catch(() => null);
  if (!response.ok) {
    const problem = body as Partial<Problem> | null;
    throw new ApiError(
      response.status,
      problem?.code ?? "HTTP_ERROR",
      problem?.detail ?? "The request could not be completed.",
      problem?.request_id ?? response.headers.get("X-Request-ID") ?? "unknown",
    );
  }
  if (path === "/api/v1/me" && body && typeof body === "object" && "csrf_token" in body) {
    csrfToken = String(body.csrf_token);
  }
  return body as T;
}

export async function apiWrite<T>(path: string, body?: unknown, options?: { method?: "POST" | "PATCH"; etag?: string }): Promise<T> {
  const headers: Record<string, string> = { Accept: "application/json, application/problem+json", "Content-Type": "application/json", "Idempotency-Key": crypto.randomUUID() };
  if (csrfToken) headers["X-CSRF-Token"] = csrfToken;
  if (options?.etag) headers["If-Match"] = options.etag;
  const response = await fetch(path, { method: options?.method ?? "POST", credentials: "same-origin", headers, body: body === undefined ? undefined : JSON.stringify(body) });
  const payload: unknown = response.status === 204 ? null : await response.json().catch(() => null);
  if (!response.ok) {
    const problem = payload as Partial<Problem> | null;
    throw new ApiError(response.status, problem?.code ?? "HTTP_ERROR", problem?.detail ?? "The request could not be completed.", problem?.request_id ?? "unknown");
  }
  return payload as T;
}

export type Severity = "critical" | "high" | "medium" | "low";
export type FindingState = "OPEN" | "RESOLVED" | "RISK_ACCEPTED";

export interface PostureRow {
  asset_id: string; name: string; category: string; criticality: string; role: string; address: string;
  compliance_pct: number | null; completeness_pct: number | null; passed: number; failed: number; unknown: number;
  source: string | null; observed_at: string | null; freshness: "fresh" | "stale" | "never";
}

export interface Overview {
  compliance_pct: number | null;
  completeness_pct: number | null;
  totals: Record<"passed" | "failed" | "not_applicable" | "unknown" | "error" | "manual_required", number>;
  asset_count: number;
  freshness: { fresh: number; stale: number; never: number };
  open_by_severity: Record<Severity, number>;
  findings_by_state: Record<FindingState, number>;
  posture: PostureRow[];
  trend: Array<{ at: string; compliance_pct: number | null; failed: number }>;
  latest_run: { id: string; status: string; created_at: string } | null;
  recent_events: Array<{ kind: string; title: string; severity: Severity; asset: string; at: string }>;
}

export interface FindingItem {
  id: string; asset_id: string; asset_name: string; site_id: string; control_key: string; control_revision: number;
  title: string; severity: Severity; state: FindingState; first_seen_at: string; last_seen_at: string;
  owner_id: string | null; owner_email: string | null; due_at: string | null; exception_state: string | null;
}

export interface Remediation { template: string; summary: string; steps: string[]; verify: string; impact: string; authority: string }

export interface FindingDetail extends FindingItem {
  events: Array<{ kind: string; at: string; actor: string | null; payload: Record<string, unknown> }>;
  last_result: { result_id: string; status: string; reason_code: string; expected: Record<string, unknown>; actual: unknown; assessment_quality: string; evidence: unknown[] } | null;
  remediation: Remediation | null;
  exceptions: Array<{ id: string; state: string; reason: string; expires_at: string }>;
}

export interface Assessment {
  id: string; status: string; reason: string; created_at: string; finished_at: string | null; source: string;
  targets: Array<{ asset: string; state: string; compliance_pct: number | null; failed: number | null; digest: string | null }>;
}

export interface ExceptionItem {
  id: string; asset_id: string; asset_name: string; control_key: string; reason: string; compensating_controls: string;
  requested_by: string; requester_email: string; approved_by: string | null; approver_email: string | null;
  approved_at: string | null; expires_at: string; state: string; effective_state: string;
}

export interface ReportItem {
  id: string; format: string; state: string; cutoff_at: string; created_at: string; manifest_digest: string | null;
  scope_summary: { assets?: number; results?: number; filename?: string; bytes?: number; evidence_level?: string; policy?: string };
}

export interface PolicyOverview {
  policies: Array<{ id: string; name: string; revision: number; state: string; digest: string; published_at: string | null }>;
  controls: Array<{ key: string; title: string; severity: Severity; origin: string; pack: string; version: string; rationale: string | null; has_remediation: boolean; results: Record<string, number> }>;
}

export interface SampleBundle {
  adapter_id: string; declared_identity: Record<string, unknown>; observed_start: string; observed_end: string;
  capture_attested: boolean; attested_by: string; facts: Record<string, unknown>;
}

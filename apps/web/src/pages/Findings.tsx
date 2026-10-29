import { useState, type FormEvent } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useSearchParams } from "react-router-dom";
import { ApiError, apiGet, apiWrite, type FindingDetail, type FindingItem, type FindingState, type Severity } from "../lib/api";
import { hasRole, usePrincipal } from "../lib/hooks";
import { ago, label, observed, shortKey, show, when } from "../lib/format";
import { Chip, CodeBlock, Drawer, Empty, ErrorNotice, PageHeading, SeverityChip, Skeleton, StateChip, useToast } from "../components/ui";

const STATES: Array<[string, FindingState | ""]> = [["All", ""], ["Open", "OPEN"], ["Risk accepted", "RISK_ACCEPTED"], ["Resolved", "RESOLVED"]];
const SEVERITIES: Array<Severity | ""> = ["", "critical", "high", "medium", "low"];

export default function Findings() {
  const [params, setParams] = useSearchParams();
  const state = params.get("state") ?? "OPEN";
  const severity = params.get("severity") ?? "";
  const asset = params.get("asset") ?? "";
  const [query, setQuery] = useState("");
  const [selected, setSelected] = useState<string | null>(null);

  const search = new URLSearchParams({ limit: "200" });
  if (state) search.set("state", state);
  if (severity) search.set("severity", severity);
  if (asset) search.set("asset_id", asset);
  if (query) search.set("q", query);
  const findings = useQuery({ queryKey: ["findings", state, severity, asset, query], queryFn: ({ signal }) => apiGet<{ items: FindingItem[]; total: number }>(`/api/v1/findings?${search}`, signal) });

  function setFilter(key: string, value: string) {
    const next = new URLSearchParams(params);
    if (value) next.set(key, value); else next.delete(key);
    if (key === "state" && !value) next.set("state", "");
    setParams(next, { replace: true });
  }

  return (
    <>
      <PageHeading title="Findings" description="Confirmed deviations, ordered by status and severity. Only a newer passing assessment resolves a finding — marking it done does not." />
      <section className="panel">
        <div className="filters">
          <div className="pill-group" role="group" aria-label="State">
            {STATES.map(([text, value]) => <button key={text} className="pill" aria-pressed={state === value} onClick={() => setFilter("state", value)}>{text}</button>)}
          </div>
          <div className="pill-group" role="group" aria-label="Severity">
            {SEVERITIES.map((value) => <button key={value || "any"} className="pill" aria-pressed={severity === value} onClick={() => setFilter("severity", value)}>{value ? label(value) : "Any severity"}</button>)}
          </div>
          <input type="search" placeholder="Search title, control or asset" aria-label="Search findings" value={query} onChange={(e) => setQuery(e.target.value)} />
          {asset && <button className="btn sm" onClick={() => setFilter("asset", "")}>Clear asset filter ×</button>}
          <span className="quiet" style={{ marginLeft: "auto" }}>{findings.data ? `${findings.data.items.length} of ${findings.data.total}` : ""}</span>
        </div>
        {findings.isPending && <Skeleton rows={6} />}
        {findings.isError && <ErrorNotice error={findings.error} />}
        {findings.isSuccess && findings.data.items.length === 0 && <Empty icon="check" title="No findings match these filters">Adjust the filters, or run a new assessment. Hidden-by-filter results are not deleted.</Empty>}
        {findings.isSuccess && findings.data.items.length > 0 && (
          <div className="table-wrap">
            <table>
              <thead><tr><th scope="col">Severity</th><th scope="col">Finding</th><th scope="col">Asset</th><th scope="col">State</th><th scope="col">Owner</th><th scope="col">Due</th><th scope="col">Last seen</th></tr></thead>
              <tbody>
                {findings.data.items.map((f) => (
                  <tr key={f.id} className="clickable" tabIndex={0} onClick={() => setSelected(f.id)} onKeyDown={(e) => e.key === "Enter" && setSelected(f.id)}>
                    <td><SeverityChip severity={f.severity} /></td>
                    <th scope="row">{f.title}<span className="cell-sub">{shortKey(f.control_key)}</span></th>
                    <td>{f.asset_name}</td>
                    <td><StateChip state={f.state} /></td>
                    <td>{f.owner_email ? f.owner_email.split("@")[0] : <span className="quiet">Unassigned</span>}</td>
                    <td>{f.due_at ? when(f.due_at).split(",")[0] : <span className="quiet">—</span>}</td>
                    <td className="quiet">{ago(f.last_seen_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
      {selected && <FindingDrawer id={selected} onClose={() => setSelected(null)} />}
    </>
  );
}

function FindingDrawer({ id, onClose }: { id: string; onClose: () => void }) {
  const detail = useQuery({ queryKey: ["finding", id], queryFn: ({ signal }) => apiGet<FindingDetail>(`/api/v1/findings/${id}`, signal) });
  const principal = usePrincipal();
  const users = useQuery({ queryKey: ["users"], queryFn: ({ signal }) => apiGet<{ items: Array<{ id: string; email: string }> }>("/api/v1/users", signal) });
  const cache = useQueryClient();
  const toast = useToast();
  const [showException, setShowException] = useState(false);
  const canReview = hasRole(principal.data?.roles, "manual_assessor", "platform_admin");
  const review = useMutation({
    mutationFn: (body: { decision: string; rationale: string; expires_at: string }) => apiWrite(`/api/v1/findings/${id}/review`, body),
    onSuccess: async () => { toast("ok", "Manual assessment recorded"); await refresh(); },
    onError: (error) => toast("err", error.message),
  });
  const canWork = hasRole(principal.data?.roles, "analyst", "scan_operator", "platform_admin");

  const refresh = async () => { await Promise.all([cache.invalidateQueries({ queryKey: ["finding", id] }), cache.invalidateQueries({ queryKey: ["findings"] }), cache.invalidateQueries({ queryKey: ["overview"] })]); };
  const patch = useMutation({
    mutationFn: (body: { owner_id?: string; due_at?: string; comment?: string }) => apiWrite(`/api/v1/findings/${id}`, body, { method: "PATCH" }),
    onSuccess: async () => { toast("ok", "Finding updated"); await refresh(); },
    onError: (error) => toast("err", error.message),
  });
  const exception = useMutation({
    mutationFn: (body: { asset_id: string; control_key: string; reason: string; compensating_controls: string; expires_at: string }) => apiWrite("/api/v1/exceptions", body),
    onSuccess: async () => { toast("ok", "Exception requested — awaiting an independent approver"); setShowException(false); await refresh(); await cache.invalidateQueries({ queryKey: ["exceptions"] }); },
    onError: (error) => toast("err", error instanceof ApiError ? error.message : "Request failed"),
  });

  const f = detail.data;
  const failing = f?.last_result?.status === "FAIL";
  return (
    <Drawer title={f?.title ?? "Finding"} onClose={onClose} meta={f && <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}><SeverityChip severity={f.severity} /><StateChip state={f.state} />{f.exception_state && <Chip tone="APPROVED">Exception active</Chip>}</div>}>
      {detail.isPending && <Skeleton rows={6} />}
      {detail.isError && <ErrorNotice error={detail.error} />}
      {f && (
        <>
          <section>
            <p className="section-title">Expected vs observed</p>
            <div className="compare">
              <div className="expected"><small>Expected</small><code>{show(f.last_result?.expected.value ?? f.last_result?.expected.description)}</code>{f.last_result?.expected.operator ? <span className="cell-sub">operator: {String(f.last_result.expected.operator)}</span> : null}</div>
              <div className={`actual ${failing ? "bad" : ""}`}><small>Observed</small><code>{observed(f.last_result?.actual, f.last_result?.expected.fact)}</code><span className="cell-sub">{f.last_result ? label(f.last_result.reason_code) : ""}</span></div>
            </div>
          </section>
          <section>
            <p className="section-title">Details</p>
            <dl className="kv">
              <dt>Asset</dt><dd>{f.asset_name}</dd>
              <dt>Control</dt><dd><code>{f.control_key}</code> (rev {f.control_revision})</dd>
              <dt>Assessment</dt><dd>{f.last_result ? label(f.last_result.assessment_quality) : "—"}</dd>
              <dt>First seen</dt><dd>{when(f.first_seen_at)}</dd>
              <dt>Last seen</dt><dd>{when(f.last_seen_at)}</dd>
              <dt>Owner</dt><dd>{f.owner_email ?? "Unassigned"}</dd>
              <dt>Due</dt><dd>{when(f.due_at)}</dd>
            </dl>
          </section>
          {f.remediation && (
            <section>
              <p className="section-title">Reviewed remediation plan</p>
              <p style={{ marginBottom: 10 }}>{f.remediation.summary}</p>
              <CodeBlock lines={f.remediation.steps} />
              <dl className="kv" style={{ marginTop: 12 }}>
                <dt>Verify</dt><dd><code>{f.remediation.verify}</code></dd>
                <dt>Impact</dt><dd>{f.remediation.impact}</dd>
                <dt>Authority</dt><dd>{f.remediation.authority}</dd>
              </dl>
              <p className="quiet" style={{ marginTop: 10 }}>BaselineGuard never changes target configuration. Apply through your change process, then rescan — only a newer passing result closes this finding.</p>
            </section>
          )}
          {canWork && f.state !== "RESOLVED" && (
            <section>
              <p className="section-title">Workflow</p>
              <WorkflowForm users={users.data?.items ?? []} busy={patch.isPending} onSubmit={(body) => patch.mutate(body)} />
              {f.state === "OPEN" && <button className="btn sm" style={{ marginTop: 12 }} onClick={() => setShowException((v) => !v)}>{showException ? "Cancel exception" : "Request risk exception"}</button>}
              {showException && <ExceptionForm busy={exception.isPending} onSubmit={(body) => exception.mutate({ asset_id: f.asset_id, control_key: f.control_key, ...body })} />}
            </section>
          )}
          {canReview && (
            <section>
              <p className="section-title">Manual assessment</p>
              <form className="form-grid" onSubmit={(e) => { e.preventDefault(); const form = new FormData(e.currentTarget); review.mutate({ decision: String(form.get("decision")), rationale: String(form.get("rationale")), expires_at: new Date(Date.now() + 90 * 86_400_000).toISOString() }); e.currentTarget.reset(); }}>
                <label className="field">Decision<select name="decision"><option value="CONFIRMED_FAIL">Confirm failure</option><option value="CONFIRMED_PASS">Confirm pass (needs rescan to close)</option><option value="REJECTED_ASSESSMENT">Reject automated assessment</option></select></label>
                <label className="field">Rationale<textarea name="rationale" required minLength={10} maxLength={2000} /></label>
                <button className="btn" disabled={review.isPending}>Record assessment (valid 90 days)</button>
              </form>
            </section>
          )}
          {f.exceptions.length > 0 && (
            <section><p className="section-title">Exceptions</p>
              {f.exceptions.map((e) => <p key={e.id} style={{ marginBottom: 6 }}><StateChip state={e.state} /> <span className="quiet">expires {when(e.expires_at)}</span><br />{e.reason}</p>)}
            </section>
          )}
          <section>
            <p className="section-title">History</p>
            <div className="timeline">
              {f.events.map((event, i) => (
                <div className="timeline-item" key={i}>
                  {label(event.kind)}{typeof event.payload.comment === "string" ? `: ${event.payload.comment}` : ""}
                  <small>{when(event.at)}{event.actor ? ` · ${event.actor}` : ""}</small>
                </div>
              ))}
            </div>
          </section>
        </>
      )}
    </Drawer>
  );
}

function WorkflowForm({ users, busy, onSubmit }: { users: Array<{ id: string; email: string }>; busy: boolean; onSubmit: (body: { owner_id?: string; due_at?: string; comment?: string }) => void }) {
  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const body: { owner_id?: string; due_at?: string; comment?: string } = {};
    if (form.get("owner")) body.owner_id = String(form.get("owner"));
    if (form.get("due")) body.due_at = new Date(`${String(form.get("due"))}T12:00:00Z`).toISOString();
    if (String(form.get("comment")).trim()) body.comment = String(form.get("comment")).trim();
    if (Object.keys(body).length === 0) return;
    onSubmit(body);
    event.currentTarget.reset();
  }
  return (
    <form className="form-grid" onSubmit={submit}>
      <div className="form-grid two">
        <label className="field">Owner<select name="owner" defaultValue=""><option value="">Keep current</option>{users.map((u) => <option key={u.id} value={u.id}>{u.email}</option>)}</select></label>
        <label className="field">Due date<input type="date" name="due" /></label>
      </div>
      <label className="field">Comment<input name="comment" maxLength={2000} placeholder="Add a note to the history" /></label>
      <button className="btn primary" disabled={busy}>{busy ? "Saving…" : "Save changes"}</button>
    </form>
  );
}

function ExceptionForm({ busy, onSubmit }: { busy: boolean; onSubmit: (body: { reason: string; compensating_controls: string; expires_at: string }) => void }) {
  const [days, setDays] = useState(30);
  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    onSubmit({ reason: String(form.get("reason")), compensating_controls: String(form.get("compensating")), expires_at: new Date(Date.now() + days * 86_400_000).toISOString() });
  }
  return (
    <form className="form-grid" style={{ marginTop: 14 }} onSubmit={submit}>
      <label className="field">Justification<textarea name="reason" required minLength={10} maxLength={2000} placeholder="Why is this deviation temporarily acceptable?" /></label>
      <label className="field">Compensating controls<textarea name="compensating" required minLength={10} maxLength={2000} placeholder="What reduces the risk in the meantime?" /></label>
      <label className="field">Expires in {days} days<input type="range" min={1} max={365} value={days} onChange={(e) => setDays(Number(e.target.value))} /></label>
      <p className="quiet">A different person with the risk-approver role must approve this. Expiry automatically restores the finding to actionable.</p>
      <button className="btn primary" disabled={busy}>{busy ? "Submitting…" : "Submit for approval"}</button>
    </form>
  );
}

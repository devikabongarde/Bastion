import { useState, type FormEvent } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { apiGet, apiWrite, type PolicyOverview } from "../lib/api";
import { hasRole, usePrincipal } from "../lib/hooks";
import { Chip, Drawer, Empty, ErrorNotice, Skeleton, StateChip, useToast } from "../components/ui";

interface PolicyRead {
  id: string; name: string; revision: number; state: string; etag: string; author_id: string;
  spec: { exclusions: Record<string, string> };
  coverage?: { selected_controls: number; excluded_controls: number };
  rule_packs: Array<{ id: string; pack_key: string; version: string }>;
}

interface DraftImpact {
  policy_id: string;
  total_active_assets: number;
  affected_assets_count: number;
  flipping_to_pass: number;
  flipping_to_fail: number;
  controls_impact: Array<{
    control_id: string;
    title: string;
    prior_status: string;
    projected_status: string;
    affected_asset_names: string[];
  }>;
}

export default function PolicyEditor({ overview }: { overview: PolicyOverview }) {
  const principal = usePrincipal();
  const cache = useQueryClient();
  const toast = useToast();
  const policies = useQuery({ queryKey: ["policies-full"], queryFn: ({ signal }) => apiGet<{ items: PolicyRead[] }>("/api/v1/policies?limit=100", signal) });
  const packs = useQuery({ queryKey: ["packs"], queryFn: ({ signal }) => apiGet<{ items: Array<{ id: string; pack_key: string; version: string; state: string }> }>("/api/v1/packs", signal) });
  const [excluded, setExcluded] = useState<Record<string, string>>({});
  const [inspectingImpact, setInspectingImpact] = useState<PolicyRead | null>(null);

  const canAuthor = hasRole(principal.data?.roles, "policy_author", "platform_admin");
  const canApprove = hasRole(principal.data?.roles, "policy_approver");
  const refresh = () => Promise.all([cache.invalidateQueries({ queryKey: ["policies-full"] }), cache.invalidateQueries({ queryKey: ["policy-overview"] })]);

  const impactQuery = useQuery({
    queryKey: ["draft-impact", inspectingImpact?.id],
    queryFn: ({ signal }) =>
      apiGet<DraftImpact>(`/api/v1/policy-drafts/${inspectingImpact?.id}/impact`, signal),
    enabled: !!inspectingImpact,
  });

  const create = useMutation({
    mutationFn: (body: unknown) => apiWrite("/api/v1/policy-drafts", body),
    onSuccess: async () => { toast("ok", "Draft created — a different approver must publish it"); setExcluded({}); await refresh(); },
    onError: (e) => toast("err", e.message),
  });
  const publish = useMutation({
    mutationFn: (p: PolicyRead) => apiWrite(`/api/v1/policy-drafts/${p.id}/publish`, { reason: "Reviewed and approved for use." }, { etag: p.etag }),
    onSuccess: async () => { toast("ok", "Policy published"); await refresh(); },
    onError: (e) => toast("err", e.message),
  });

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const approved = packs.data?.items.filter((p) => p.state === "approved") ?? [];
    create.mutate({
      name: String(form.get("name")),
      rule_pack_ids: approved.map((p) => p.id),
      spec: { schema_version: "1.0", site_ids: [], overrides: {}, exclusions: excluded },
      reason: String(form.get("reason")),
    });
  }
  const drafts = policies.data?.items.filter((p) => p.state === "draft") ?? [];
  return (
    <>
      <div className="grid two">
        <section className="panel">
          <div className="panel-head"><h2>Drafts awaiting approval</h2><span className="sub">Two-person publish</span></div>
          {policies.isPending && <Skeleton rows={3} />}
          {policies.isError && <ErrorNotice error={policies.error} />}
          {policies.isSuccess && drafts.length === 0 && <Empty icon="policies" title="No drafts">Create a draft to tailor the baseline. Published revisions are immutable.</Empty>}
          {drafts.map((p) => (
            <div key={p.id} className="row-between" style={{ padding: "10px 0", borderTop: "1px solid var(--line)" }}>
              <div>
                <b>{p.name}</b> <span className="quiet">r{p.revision}</span><br />
                <StateChip state="REQUESTED" /> <span className="quiet">{Object.keys(p.spec.exclusions).length} exclusions</span>
              </div>
              <div style={{ display: "flex", gap: "6px", alignItems: "center" }}>
                <button className="btn sm" onClick={() => setInspectingImpact(p)}>Preview Impact</button>
                {canApprove && p.author_id !== principal.data?.user_id
                  ? <button className="btn sm primary" disabled={publish.isPending} onClick={() => publish.mutate(p)}>Publish</button>
                  : <Chip tone="neutral">Needs another approver</Chip>}
              </div>
            </div>
          ))}
        </section>
        <section className="panel">
          <div className="panel-head"><h2>New draft</h2></div>
          {canAuthor ? (
            <form className="form-grid" onSubmit={submit}>
              <label className="field">Name<input name="name" required maxLength={255} defaultValue="Ubuntu 22.04 tailored" /></label>
              <fieldset style={{ border: 0, padding: 0, margin: 0 }}>
                <legend className="section-title">Excluded controls (stay visible in coverage)</legend>
                <div style={{ maxHeight: 180, overflowY: "auto", display: "grid", gap: 6 }}>
                  {overview.controls.map((c) => (
                    <label key={c.key} style={{ display: "flex", gap: 8, alignItems: "center", fontSize: 12 }}>
                      <input type="checkbox" style={{ width: "auto" }} checked={c.key in excluded} onChange={(e) => setExcluded((cur) => { const next = { ...cur }; if (e.target.checked) next[c.key] = "Not applicable to this environment per owner review."; else delete next[c.key]; return next; })} />
                      {c.title}
                    </label>
                  ))}
                </div>
              </fieldset>
              <label className="field">Reason<input name="reason" required minLength={10} maxLength={1000} placeholder="Why this tailoring is needed" /></label>
              <button className="btn primary" disabled={create.isPending}>{create.isPending ? "Creating…" : "Create draft"}</button>
              <p className="quiet">A tailored score is never labeled as unmodified source-benchmark compliance.</p>
            </form>
          ) : <Empty icon="lock" title="Read-only access">Your role cannot author policies.</Empty>}
        </section>
      </div>

      {inspectingImpact && (
        <Drawer title={`Policy Impact Preview: ${inspectingImpact.name}`} onClose={() => setInspectingImpact(null)}>
          {impactQuery.isPending && <Skeleton rows={4} />}
          {impactQuery.isError && <ErrorNotice error={impactQuery.error} />}
          {impactQuery.isSuccess && (
            <div style={{ display: "grid", gap: "16px" }}>
              <div style={{ display: "flex", gap: "10px", flexWrap: "wrap" }}>
                <Chip tone="neutral">{impactQuery.data.total_active_assets} Total Active Assets</Chip>
                <Chip tone="ok">{impactQuery.data.flipping_to_pass} Flipping to Pass/N.A.</Chip>
                {impactQuery.data.flipping_to_fail > 0 && (
                  <Chip tone="critical">{impactQuery.data.flipping_to_fail} Flipping to Fail</Chip>
                )}
              </div>

              {impactQuery.data.controls_impact.length === 0 ? (
                <Empty icon="check" title="No Status Changes">
                  This draft will produce identical results across all active assets with current posture.
                </Empty>
              ) : (
                <div className="table-wrap">
                  <table>
                    <thead>
                      <tr>
                        <th>Control</th>
                        <th>Prior Status</th>
                        <th>Projected Status</th>
                        <th>Affected Assets</th>
                      </tr>
                    </thead>
                    <tbody>
                      {impactQuery.data.controls_impact.map((c) => (
                        <tr key={c.control_id}>
                          <td><b>{c.title}</b><br /><code className="cell-sub">{c.control_id}</code></td>
                          <td><Chip tone={c.prior_status === "PASS" ? "ok" : "fail"}>{c.prior_status}</Chip></td>
                          <td><Chip tone={c.projected_status === "PASS" || c.projected_status === "NOT_APPLICABLE" ? "ok" : "fail"}>{c.projected_status}</Chip></td>
                          <td>{c.affected_asset_names.join(", ")}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          )}
        </Drawer>
      )}
    </>
  );
}

import { useState, type ChangeEvent } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { apiGet, apiWrite, type Asset, type Assessment, type Page, type PolicyOverview, type SampleBundle } from "../lib/api";
import { hasRole, usePrincipal } from "../lib/hooks";
import { ago, label, pct } from "../lib/format";
import { Chip, Empty, ErrorNotice, Icon, PageHeading, Skeleton, StateChip, useToast } from "../components/ui";

export default function Assessments() {
  const principal = usePrincipal();
  const runs = useQuery({ queryKey: ["assessments"], queryFn: ({ signal }) => apiGet<{ items: Assessment[] }>("/api/v1/assessments", signal), refetchInterval: 4000 });
  const canScan = hasRole(principal.data?.roles, "scan_operator", "platform_admin");
  return (
    <>
      <PageHeading title="Assessments" description="Submit configuration evidence for evaluation and track every run from request to result." />
      <div className="grid two">
        <section className="panel">
          <div className="panel-head"><h2>Recent assessments</h2><span className="sub">Auto-refreshing</span></div>
          {runs.isPending && <Skeleton rows={4} />}
          {runs.isError && <ErrorNotice error={runs.error} />}
          {runs.isSuccess && runs.data.items.length === 0 && <Empty icon="scans" title="No assessments yet">Import evidence for an asset to create the first one.</Empty>}
          {runs.isSuccess && runs.data.items.length > 0 && (
            <div className="table-wrap">
              <table>
                <thead><tr><th scope="col">Run</th><th scope="col">State</th><th scope="col">Targets</th><th scope="col">Source</th><th scope="col">Created</th></tr></thead>
                <tbody>
                  {runs.data.items.map((run) => (
                    <tr key={run.id}>
                      <th scope="row">{run.reason}<span className="cell-sub"><code>{run.id.slice(0, 8)}</code></span></th>
                      <td><StateChip state={run.status} /></td>
                      <td>{run.targets.map((t) => <div key={t.asset} style={{ whiteSpace: "nowrap" }}>{t.asset} <span className="quiet">{t.compliance_pct !== null ? `${pct(t.compliance_pct)} · ${t.failed} failed` : label(t.state)}</span></div>)}</td>
                      <td><Chip tone={run.source} /></td>
                      <td className="quiet">{ago(run.created_at)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
        {canScan ? <ImportPanel /> : <section className="panel"><Empty icon="lock" title="Read-only access">Your role cannot submit evidence. Ask an administrator for the scan operator role.</Empty></section>}
      </div>
    </>
  );
}

function ImportPanel() {
  const cache = useQueryClient();
  const toast = useToast();
  const assets = useQuery({ queryKey: ["assets", "list"], queryFn: ({ signal }) => apiGet<Page<Asset>>("/api/v1/assets?limit=100", signal) });
  const policies = useQuery({ queryKey: ["policy-overview"], queryFn: ({ signal }) => apiGet<PolicyOverview>("/api/v1/policy-overview", signal) });
  const [assetId, setAssetId] = useState("");
  const [bundle, setBundle] = useState<SampleBundle | null>(null);
  const [fileName, setFileName] = useState("");
  const [problem, setProblem] = useState<string | null>(null);
  const published = policies.data?.policies.find((p) => p.state === "published");

  const sample = useMutation({
    mutationFn: (profile: string) => apiGet<SampleBundle>(`/api/v1/imports/sample?profile=${profile}`),
    onSuccess: (data) => { setBundle(data); setFileName("generated sample"); setProblem(null); },
    onError: (error) => setProblem(error.message),
  });
  const submit = useMutation({
    mutationFn: () => apiWrite<{ scan_id: string }>("/api/v1/imports", { ...bundle, asset_id: assetId, policy_revision_id: published?.id }),
    onSuccess: async () => {
      toast("ok", "Evidence accepted — evaluation running");
      setBundle(null); setFileName("");
      await Promise.all(["assessments", "overview", "findings"].map((key) => cache.invalidateQueries({ queryKey: [key] })));
    },
    onError: (error) => setProblem(error.message),
  });

  async function onFile(event: ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0];
    if (!file) return;
    try {
      const parsed = JSON.parse(await file.text()) as SampleBundle;
      if (!parsed.facts || typeof parsed.facts !== "object") throw new Error("missing facts");
      setBundle(parsed); setFileName(file.name); setProblem(null);
    } catch {
      setProblem("That file is not a valid evidence bundle (JSON with a facts object).");
    }
  }

  return (
    <section className="panel" aria-labelledby="import-heading">
      <div className="panel-head"><h2 id="import-heading">Submit evidence</h2><Chip tone="import">Offline import</Chip></div>
      <div className="form-grid">
        <label className="field">Target asset
          <select value={assetId} onChange={(e) => setAssetId(e.target.value)}>
            <option value="">Select an asset…</option>
            {assets.data?.items.map((a) => <option key={a.id} value={a.id}>{a.name} — {a.address}</option>)}
          </select>
        </label>
        <div>
          <p className="section-title">Evidence bundle</p>
          <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
            <label className="btn sm" style={{ cursor: "pointer" }}><Icon name="upload" />Upload JSON<input type="file" accept="application/json,.json" onChange={onFile} style={{ display: "none" }} /></label>
            {(["hardened", "mixed", "weak"] as const).map((p) => <button key={p} type="button" className="btn sm" disabled={sample.isPending} onClick={() => sample.mutate(p)}>Sample: {p}</button>)}
          </div>
          {bundle && <p className="quiet" style={{ marginTop: 10 }}>Loaded <b>{fileName}</b> · {Object.keys(bundle.facts).length} facts</p>}
        </div>
        <dl className="kv"><dt>Policy</dt><dd>{published ? `${published.name} · rev ${published.revision}` : "No published policy"}</dd></dl>
        {problem && <p className="form-error" role="alert">{problem}</p>}
        <button className="btn primary" disabled={!assetId || !bundle || !published || submit.isPending} onClick={() => submit.mutate()}>{submit.isPending ? "Submitting…" : "Evaluate evidence"}</button>
        <p className="quiet">Imported evidence is recorded with its uploader and labeled <b>import</b> throughout — it is never presented as a fresh live collection.</p>
      </div>
    </section>
  );
}

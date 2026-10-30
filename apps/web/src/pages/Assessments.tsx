import { useEffect, useState, type ChangeEvent } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { apiGet, apiWrite, type Asset, type Assessment, type Page, type SampleBundle } from "../lib/api";
import { hasRole, useActivePolicy, usePrincipal } from "../lib/hooks";
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
                <thead><tr><th scope="col" style={{ minWidth: 180 }}>Run</th><th scope="col">State</th><th scope="col">Targets</th><th scope="col">Source</th><th scope="col">Created</th></tr></thead>
                <tbody>
                  {runs.data.items.map((run) => (
                    <tr key={run.id}>
                      <th scope="row">{run.reason}<span className="cell-sub"><code>{run.id.slice(0, 8)}</code></span></th>
                      <td><StateChip state={run.status} /></td>
                      <td>{run.targets.map((t) => <div key={t.asset}>{t.asset} <span className="quiet">{t.compliance_pct !== null ? `${pct(t.compliance_pct)} · ${t.failed} failed` : label(t.state)}</span></div>)}</td>
                      <td><Chip tone={run.source} /></td>
                      <td className="quiet">{ago(run.created_at)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
        {canScan ? (
          <div style={{ display: "grid", gap: 16, alignContent: "start" }}>
            <LiveScanPanel />
            <ImportPanel />
          </div>
        ) : <section className="panel"><Empty icon="lock" title="Read-only access">Your role cannot submit evidence. Ask an administrator for the scan operator role.</Empty></section>}
      </div>
    </>
  );
}

/** Live collection: SSH devices with a pinned host key + bound credential, and this machine. */
function LiveScanPanel() {
  const cache = useQueryClient();
  const toast = useToast();
  const policy = useActivePolicy();
  const assets = useQuery({ queryKey: ["assets", "list"], queryFn: ({ signal }) => apiGet<Page<Asset>>("/api/v1/assets?limit=200", signal) });
  const live = (assets.data?.items ?? []).filter((a) => a.collection_mode === "live_local" || a.collection_mode === "live_ssh");
  const ready = live.filter((a) => a.collection_mode === "live_local" || (a.host_key_fingerprint && a.credential_bound));
  const [picked, setPicked] = useState<Set<string> | null>(null);
  const selected = picked ?? new Set(ready.map((a) => a.id));
  const [running, setRunning] = useState<string | null>(null);

  const status = useQuery({
    queryKey: ["scan", running],
    queryFn: ({ signal }) => apiGet<{ status: string }>(`/api/v1/scans/${running}`, signal),
    enabled: Boolean(running),
    refetchInterval: 1000,
  });
  const finalState = status.data && ["COMPLETED", "PARTIAL", "FAILED", "CANCELED", "CANCELLED"].includes(status.data.status) ? status.data.status : null;
  useEffect(() => {
    if (!running || !finalState) return;
    setRunning(null);
    toast(finalState === "FAILED" ? "err" : "ok", `Live scan ${finalState.toLowerCase()} — results updated`);
    void Promise.all(["assessments", "overview", "findings", "assets"].map((key) => cache.invalidateQueries({ queryKey: [key] })));
  }, [running, finalState, toast, cache]);

  const start = useMutation({
    mutationFn: () => apiWrite<{ scan_id: string }>("/api/v1/scans", {
      asset_ids: [...selected], policy_revision_id: policy.data?.id, reason: "Live scan from console",
    }),
    onSuccess: (data) => { setRunning(data.scan_id); void cache.invalidateQueries({ queryKey: ["assessments"] }); },
    onError: (error) => toast("err", error.message),
  });

  function toggle(id: string) {
    const next = new Set(selected);
    if (next.has(id)) next.delete(id); else next.add(id);
    setPicked(next);
  }

  return (
    <section className="panel" aria-labelledby="live-heading">
      <div className="panel-head"><h2 id="live-heading">Live scan</h2><Chip tone="live">Real-time collection</Chip></div>
      {live.length === 0 ? (
        <p className="quiet">No live assets yet. Add an asset with a live adapter on the Assets page.</p>
      ) : (
        <div className="form-grid">
          <div style={{ display: "grid", gap: 6 }}>
            {live.map((a) => {
              const isReady = a.collection_mode === "live_local" || (a.host_key_fingerprint && a.credential_bound);
              return (
                <label key={a.id} className="field" style={{ display: "flex", alignItems: "center", gap: 10, fontWeight: 500, opacity: isReady ? 1 : 0.6 }}>
                  <input type="checkbox" checked={selected.has(a.id)} disabled={!isReady || Boolean(running)} onChange={() => toggle(a.id)} style={{ width: 16, height: 16 }} />
                  <span style={{ flex: 1 }}><b>{a.name}</b> <span className="quiet">· {a.collection_mode === "live_local" ? "this machine" : `${a.address}:${a.port}`}</span></span>
                  {!isReady && <span className="quiet">connect on Assets</span>}
                </label>
              );
            })}
          </div>
          <dl className="kv"><dt>Policy</dt><dd>{policy.data ? `${policy.data.name} · rev ${policy.data.revision}` : "No published policy"}</dd></dl>
          <button className="btn primary" disabled={!policy.data || selected.size === 0 || start.isPending || Boolean(running)} onClick={() => start.mutate()}>
            {running ? `Scanning… ${status.data?.status ? label(status.data.status) : ""}` : `Scan ${selected.size} asset${selected.size === 1 ? "" : "s"} now`}
          </button>
          <p className="quiet">Read-only commands only. SSH devices are reached through their pinned host key; anything else is refused.</p>
        </div>
      )}
    </section>
  );
}

function ImportPanel() {
  const cache = useQueryClient();
  const toast = useToast();
  const assets = useQuery({ queryKey: ["assets", "list"], queryFn: ({ signal }) => apiGet<Page<Asset>>("/api/v1/assets?limit=100", signal) });
  const policy = useActivePolicy();
  const [assetId, setAssetId] = useState("");
  const [bundle, setBundle] = useState<SampleBundle | null>(null);
  const [fileName, setFileName] = useState("");
  const [problem, setProblem] = useState<string | null>(null);
  const published = policy.data;
  const asset = assets.data?.items.find((a) => a.id === assetId);

  const sample = useMutation({
    mutationFn: (profile: string) => {
      // Generate a sample matching the selected asset's platform (and role for Cisco).
      const family = String(asset?.identity?.family ?? "ubuntu");
      const role = asset?.declared_role === "router" || asset?.declared_role === "switch" ? `&role=${asset.declared_role}` : "";
      return apiGet<SampleBundle>(`/api/v1/imports/sample?profile=${profile}&family=${family}${role}`);
    },
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

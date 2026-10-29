import { useState, type FormEvent } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { apiGet, apiWrite, type Asset, type Page, type Site } from "../lib/api";
import { hasRole, usePrincipal } from "../lib/hooks";
import { useOverview } from "../lib/hooks";
import { ago, label, pct, when } from "../lib/format";
import { Chip, Drawer, Empty, ErrorNotice, PageHeading, Skeleton, useToast } from "../components/ui";

export default function Assets() {
  const assets = useQuery({ queryKey: ["assets", "list"], queryFn: ({ signal }) => apiGet<Page<Asset>>("/api/v1/assets?limit=100", signal) });
  const overview = useOverview();
  const principal = usePrincipal();
  const cache = useQueryClient();
  const toast = useToast();
  const [adding, setAdding] = useState(false);
  const [importingCsv, setImportingCsv] = useState(false);
  const [driftFor, setDriftFor] = useState<Asset | null>(null);
  const [csvText, setCsvText] = useState("");
  const [defaultSite, setDefaultSite] = useState<string>("");
  const [previewData, setPreviewData] = useState<{
    total_rows: number;
    valid_rows: number;
    invalid_rows: number;
    rows: Array<{
      row_index: number;
      name: string;
      address: string;
      port: number;
      category: string;
      criticality: string;
      declared_role: string;
      adapter_id: string;
      site_id: string | null;
      site_name: string | null;
      valid: boolean;
      errors: string[];
    }>;
  } | null>(null);

  const sites = useQuery({ queryKey: ["sites"], queryFn: ({ signal }) => apiGet<Page<Site>>("/api/v1/sites", signal), enabled: adding || importingCsv });
  const create = useMutation({
    mutationFn: (body: Record<string, unknown>) => apiWrite("/api/v1/assets", body),
    onSuccess: async () => { toast("ok", "Asset registered"); setAdding(false); await cache.invalidateQueries({ queryKey: ["assets"] }); },
    onError: (e) => toast("err", e.message),
  });
  const archive = useMutation({
    mutationFn: (id: string) => apiWrite(`/api/v1/assets/${id}/archive`),
    onSuccess: async () => { toast("ok", "Asset archived"); await cache.invalidateQueries({ queryKey: ["assets"] }); await cache.invalidateQueries({ queryKey: ["overview"] }); },
    onError: (e) => toast("err", e.message),
  });

  const previewMutation = useMutation({
    mutationFn: (body: { csv_text: string; default_site_id?: string }) =>
      apiWrite<any>("/api/v1/assets/import-preview", body),
    onSuccess: (data) => {
      setPreviewData(data);
      toast("ok", `Validated ${data.total_rows} rows: ${data.valid_rows} valid`);
    },
    onError: (e) => toast("err", e.message),
  });

  const commitMutation = useMutation({
    mutationFn: (body: { rows: Array<any> }) =>
      apiWrite<{ created_count: number; created_ids: string[] }>("/api/v1/assets/import-commit", body),
    onSuccess: async (data) => {
      toast("ok", `Successfully imported ${data.created_count} assets`);
      setImportingCsv(false);
      setPreviewData(null);
      setCsvText("");
      await cache.invalidateQueries({ queryKey: ["assets"] });
      await cache.invalidateQueries({ queryKey: ["overview"] });
    },
    onError: (e) => toast("err", e.message),
  });

  const canEdit = hasRole(principal.data?.roles, "inventory_editor", "platform_admin");
  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const f = new FormData(event.currentTarget);
    create.mutate({ site_id: f.get("site"), category: f.get("category"), name: f.get("name"), address: f.get("address"), port: Number(f.get("port")), adapter_id: f.get("adapter"), declared_role: f.get("role"), criticality: f.get("criticality"), tags: {} });
  }

  function handlePreviewCsv(e: FormEvent) {
    e.preventDefault();
    if (!csvText.trim()) return;
    previewMutation.mutate({ csv_text: csvText, default_site_id: defaultSite || undefined });
  }

  function handleCommitCsv() {
    if (!previewData || previewData.valid_rows === 0) return;
    const validRows = previewData.rows.filter((r) => r.valid).map((r) => ({
      name: r.name,
      address: r.address,
      port: r.port,
      category: r.category,
      criticality: r.criticality,
      declared_role: r.declared_role,
      adapter_id: r.adapter_id,
      site_id: r.site_id,
      tags: [],
    }));
    commitMutation.mutate({ rows: validRows });
  }

  const posture = new Map(overview.data?.posture.map((row) => [row.asset_id, row]));
  return (
    <>
      <PageHeading
        title="Assets"
        description="Authorized targets registered in this organization, with their latest assessed posture."
        actions={
          canEdit && (
            <div style={{ display: "flex", gap: "8px" }}>
              <button className="btn" onClick={() => { setImportingCsv(true); setPreviewData(null); }}>Import CSV</button>
              <button className="btn primary" onClick={() => setAdding(true)}>Add asset</button>
            </div>
          )
        }
      />
      <section className="panel">
        <div className="panel-head"><h2>Asset inventory</h2><span className="sub">{assets.data ? `${assets.data.items.length} registered` : ""}</span></div>
        {assets.isPending && <Skeleton rows={5} />}
        {assets.isError && <ErrorNotice error={assets.error} />}
        {assets.isSuccess && assets.data.items.length === 0 && <Empty icon="assets" title="No assets registered">No assets are registered in your visible site scope.</Empty>}
        {assets.isSuccess && assets.data.items.length > 0 && (
          <div className="table-wrap">
            <table>
              <thead><tr><th scope="col">Asset</th><th scope="col">Platform</th><th scope="col">Criticality</th><th scope="col">Compliance</th><th scope="col">Last evidence</th><th scope="col"><span className="sr-only">Actions</span></th></tr></thead>
              <tbody>
                {assets.data.items.map((asset) => {
                  const row = posture.get(asset.id);
                  return (
                    <tr key={asset.id}>
                      <th scope="row">{asset.name}<span className="cell-sub"><code>{asset.address}:{asset.port}</code></span></th>
                      <td>{label(asset.category)}<span className="cell-sub">{label(asset.declared_role)} · {asset.adapter_id}</span></td>
                      <td><Chip tone={asset.criticality === "critical" ? "critical" : asset.criticality === "high" ? "high" : asset.criticality === "low" ? "low" : "neutral"}>{label(asset.criticality)}</Chip></td>
                      <td>{row ? <div className="mini-bar"><div className={`bar tone-${(row.compliance_pct ?? 0) >= 85 ? "pass" : (row.compliance_pct ?? 0) >= 60 ? "warn" : "fail"}`}><i style={{ width: `${row.compliance_pct ?? 0}%` }} /></div><b>{pct(row.compliance_pct)}</b></div> : <Chip tone="never">Not assessed</Chip>}</td>
                      <td>{row ? <><Chip tone={row.freshness} /> <span className="quiet">{ago(row.observed_at)}</span></> : <span className="quiet">—</span>}</td>
                      <td className="num"><div style={{ display: "inline-flex", gap: 6 }}>
                        {row && row.failed > 0 && <Link className="btn sm" to={`/findings?asset=${asset.id}`}>{row.failed} findings</Link>}
                        {row && <button className="btn sm" onClick={() => setDriftFor(asset)}>Drift</button>}
                        {canEdit && <button className="btn sm danger" disabled={archive.isPending} onClick={() => { if (confirm(`Archive ${asset.name}?`)) archive.mutate(asset.id); }}>Archive</button>}
                      </div></td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </section>
      {driftFor && <DriftPanel asset={driftFor} onClose={() => setDriftFor(null)} />}
      {adding && (
        <Drawer title="Register asset" onClose={() => setAdding(false)}>
          <form className="form-grid" onSubmit={submit}>
            <label className="field">Site<select name="site" required>{sites.data?.items.map((x) => <option key={x.id} value={x.id}>{x.name}</option>)}</select></label>
            <label className="field">Name<input name="name" required maxLength={255} /></label>
            <div className="form-grid two">
              <label className="field">Address<input name="address" required placeholder="10.20.1.50" /></label>
              <label className="field">Port<input name="port" type="number" min={1} max={65535} defaultValue={22} required /></label>
            </div>
            <div className="form-grid two">
              <label className="field">Category<select name="category"><option>linux</option><option>windows</option><option>firewall</option><option>router</option><option>switch</option></select></label>
              <label className="field">Role<input name="role" defaultValue="server" required /></label>
            </div>
            <div className="form-grid two">
              <label className="field">Adapter<select name="adapter"><option value="linux-ssh">linux-ssh (live)</option><option value="linux-ssh-fixture">linux-ssh-fixture (offline)</option><option value="windows-local">windows-local</option><option value="cisco-iosxe">cisco-iosxe</option><option value="fortigate-ssh">fortigate-ssh</option></select></label>
              <label className="field">Criticality<select name="criticality" defaultValue="normal"><option>critical</option><option>high</option><option>normal</option><option>low</option></select></label>
            </div>
            <p className="quiet">The address and port must fall inside the site’s approved scope; the server rejects anything else.</p>
            <button className="btn primary" disabled={create.isPending}>{create.isPending ? "Registering…" : "Register asset"}</button>
          </form>
        </Drawer>
      )}

      {importingCsv && (
        <Drawer title="Bulk CSV Asset Import" onClose={() => setImportingCsv(false)}>
          <form className="form-grid" onSubmit={handlePreviewCsv}>
            <label className="field">
              Default Site
              <select value={defaultSite} onChange={(e) => setDefaultSite(e.target.value)}>
                <option value="">Select a default site...</option>
                {sites.data?.items.map((x) => (
                  <option key={x.id} value={x.id}>{x.name}</option>
                ))}
              </select>
            </label>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <label className="field" style={{ margin: 0 }}>CSV Data</label>
              <button
                type="button"
                className="btn sm"
                onClick={() =>
                  setCsvText(
                    "name,address,port,category,criticality,role\n" +
                    "prod-win-01,10.20.1.101,5986,windows,high,server\n" +
                    "edge-fw-01,10.20.0.1,443,firewall,critical,firewall\n" +
                    "core-sw-01,10.20.0.2,22,network,high,switch\n"
                  )
                }
              >
                Insert Sample Template
              </button>
            </div>
            <textarea
              rows={8}
              value={csvText}
              onChange={(e) => setCsvText(e.target.value)}
              placeholder="name,address,port,category,criticality,role&#10;web-01,10.20.1.11,22,linux,critical,server"
              style={{ fontFamily: "monospace", fontSize: "0.85rem", width: "100%" }}
              required
            />
            <button className="btn primary" disabled={previewMutation.isPending}>
              {previewMutation.isPending ? "Validating CSV…" : "Validate & Preview Rows"}
            </button>
          </form>

          {previewData && (
            <div style={{ marginTop: "20px" }}>
              <div style={{ display: "flex", gap: "10px", marginBottom: "12px", alignItems: "center" }}>
                <Chip tone="neutral">{previewData.total_rows} Total Rows</Chip>
                <Chip tone="ok">{previewData.valid_rows} Valid</Chip>
                {previewData.invalid_rows > 0 && <Chip tone="critical">{previewData.invalid_rows} Invalid</Chip>}
              </div>

              <div className="table-wrap" style={{ maxHeight: "280px", overflowY: "auto" }}>
                <table>
                  <thead>
                    <tr>
                      <th>Status</th>
                      <th>Row</th>
                      <th>Name</th>
                      <th>Address</th>
                      <th>Category</th>
                      <th>Errors</th>
                    </tr>
                  </thead>
                  <tbody>
                    {previewData.rows.map((r) => (
                      <tr key={r.row_index}>
                        <td>{r.valid ? <Chip tone="ok">Valid</Chip> : <Chip tone="critical">Error</Chip>}</td>
                        <td>#{r.row_index}</td>
                        <td>{r.name}</td>
                        <td><code>{r.address}:{r.port}</code></td>
                        <td>{r.category}</td>
                        <td style={{ color: r.valid ? "inherit" : "var(--color-critical)" }}>
                          {r.errors.length > 0 ? r.errors.join("; ") : "—"}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>

              {previewData.valid_rows > 0 && (
                <div style={{ marginTop: "16px" }}>
                  <button
                    className="btn primary"
                    onClick={handleCommitCsv}
                    disabled={commitMutation.isPending}
                    style={{ width: "100%" }}
                  >
                    {commitMutation.isPending ? "Importing Assets…" : `Confirm & Import ${previewData.valid_rows} Valid Assets`}
                  </button>
                </div>
              )}
            </div>
          )}
        </Drawer>
      )}
    </>
  );
}

function DriftPanel({ asset, onClose }: { asset: Asset; onClose: () => void }) {
  const drift = useQuery({ queryKey: ["drift", asset.id], queryFn: ({ signal }) => apiGet<{ comparable: boolean; reason: string | null; from_at?: string; to_at?: string; changes: Array<{ control_key: string; from: string | null; to: string }> }>(`/api/v1/assets/${asset.id}/drift`, signal) });
  return (
    <Drawer title={`Drift: ${asset.name}`} onClose={onClose}>
      {drift.isPending && <Skeleton rows={4} />}
      {drift.isError && <ErrorNotice error={drift.error} />}
      {drift.data && (
        <>
          {drift.data.reason && <div className="notice">{drift.data.reason}</div>}
          {drift.data.from_at && <p className="quiet">{when(drift.data.from_at)} → {when(drift.data.to_at)}</p>}
          {drift.data.changes.length === 0 && drift.data.from_at && <Empty icon="check" title="No changes">Control results are identical between the two assessments.</Empty>}
          {drift.data.changes.map((c) => <p key={c.control_key}><code>{c.control_key.split(".").pop()}</code>: <Chip tone={c.from === "PASS" ? "ok" : "fail"}>{c.from ?? "new"}</Chip> → <Chip tone={c.to === "PASS" ? "ok" : "fail"}>{c.to}</Chip></p>)}
        </>
      )}
    </Drawer>
  );
}

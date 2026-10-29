import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { apiGet, apiWrite, type ReportItem } from "../lib/api";
import { hasRole, usePrincipal } from "../lib/hooks";
import { label, when } from "../lib/format";
import { Chip, Empty, ErrorNotice, Icon, PageHeading, Skeleton, StateChip, useToast } from "../components/ui";

export default function Reports() {
  const principal = usePrincipal();
  const cache = useQueryClient();
  const toast = useToast();
  const [format, setFormat] = useState<"html" | "csv" | "json" | "pdf">("html");
  const [level, setLevel] = useState<"summary" | "standard" | "full">("standard");
  const list = useQuery({ queryKey: ["reports"], queryFn: ({ signal }) => apiGet<{ items: ReportItem[] }>("/api/v1/reports", signal) });
  const create = useMutation({
    mutationFn: () => apiWrite<ReportItem>("/api/v1/reports", { format, evidence_level: level }),
    onSuccess: async () => { toast("ok", "Report generated from the latest results"); await cache.invalidateQueries({ queryKey: ["reports"] }); },
    onError: (error) => toast("err", error.message),
  });
  const canCreate = hasRole(principal.data?.roles, "auditor", "analyst", "platform_admin");
  return (
    <>
      <PageHeading title="Reports" description="Frozen, locally rendered audit exports. Each report records its scope, cutoff time and a SHA-256 digest of the exact bytes." />
      <div className="grid two">
        <section className="panel">
          <div className="panel-head"><h2>Generated reports</h2></div>
          {list.isPending && <Skeleton rows={4} />}
          {list.isError && <ErrorNotice error={list.error} />}
          {list.isSuccess && list.data.items.length === 0 && <Empty icon="reports" title="No reports yet">Generate the first export from the panel on the right.</Empty>}
          {list.isSuccess && list.data.items.length > 0 && (
            <div className="table-wrap">
              <table>
                <thead><tr><th scope="col">Report</th><th scope="col">Scope</th><th scope="col">State</th><th scope="col">Digest</th><th scope="col"><span className="sr-only">Download</span></th></tr></thead>
                <tbody>
                  {list.data.items.map((r) => (
                    <tr key={r.id}>
                      <th scope="row"><Chip tone="neutral">{r.format.toUpperCase()}</Chip><span className="cell-sub">{when(r.created_at)}</span></th>
                      <td>{r.scope_summary.assets} assets · {r.scope_summary.results} results<span className="cell-sub">{r.scope_summary.policy} · {label(r.scope_summary.evidence_level ?? "standard")}</span></td>
                      <td><StateChip state={r.state} /></td>
                      <td><code title={r.manifest_digest ?? ""}>{r.manifest_digest?.slice(0, 12)}…</code></td>
                      <td className="num">{r.state === "COMPLETED" && <a className="btn sm" href={`/api/v1/reports/${r.id}/download`} download><Icon name="download" />Download</a>}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
        <section className="panel">
          <div className="panel-head"><h2>New report</h2></div>
          {canCreate ? (
            <div className="form-grid">
              <label className="field">Format<select value={format} onChange={(e) => setFormat(e.target.value as typeof format)}><option value="html">Self-contained HTML</option><option value="pdf">PDF (text layout)</option><option value="csv">CSV (spreadsheet-safe)</option><option value="json">JSON (machine-readable)</option></select></label>
              <label className="field">Evidence level<select value={level} onChange={(e) => setLevel(e.target.value as typeof level)}><option value="summary">Summary — failures and unresolved only</option><option value="standard">Standard — all results</option><option value="full">Full — all results with evidence pointers</option></select></label>
              <button className="btn primary" disabled={create.isPending} onClick={() => create.mutate()}>{create.isPending ? "Rendering…" : "Generate report"}</button>
              <p className="quiet">Reports use the newest result for every asset at the moment you click. Later exceptions or renames never rewrite an issued report.</p>
            </div>
          ) : <Empty icon="lock" title="Read-only access">Your role cannot create reports.</Empty>}
        </section>
      </div>
    </>
  );
}

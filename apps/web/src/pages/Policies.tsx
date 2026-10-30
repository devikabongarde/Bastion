import { useQuery } from "@tanstack/react-query";
import { apiGet, type PolicyOverview } from "../lib/api";
import { label } from "../lib/format";
import PolicyEditor from "./PolicyEditor";
import { Chip, Empty, ErrorNotice, PageHeading, SeverityChip, Skeleton, StateChip } from "../components/ui";

export default function Policies() {
  const policy = useQuery({ queryKey: ["policy-overview"], queryFn: ({ signal }) => apiGet<PolicyOverview>("/api/v1/policy-overview", signal) });
  return (
    <>
      <PageHeading title="Policies" description="Published, immutable baselines and the controls they evaluate. Unmapped controls are labeled organizational hardening — never CIS compliance." />
      {policy.isPending && <section className="panel"><Skeleton rows={6} /></section>}
      {policy.isError && <ErrorNotice error={policy.error} />}
      {policy.isSuccess && (
        <div className="stack">
          <section className="panel">
            <div className="panel-head"><h2>Policy revisions</h2></div>
            {policy.data.policies.length === 0 ? <Empty icon="policies" title="No policies">Publish a policy to start assessing.</Empty> : (
              <div className="table-wrap"><table>
                <thead><tr><th scope="col">Name</th><th scope="col">Revision</th><th scope="col">State</th><th scope="col">Digest</th></tr></thead>
                <tbody>{policy.data.policies.map((p) => <tr key={p.id}><th scope="row">{p.name}</th><td>r{p.revision}</td><td><StateChip state={p.state.toUpperCase() === "PUBLISHED" ? "COMPLETED" : p.state.toUpperCase()} /></td><td><code>{p.digest.slice(0, 16)}…</code></td></tr>)}</tbody>
              </table></div>
            )}
          </section>
          <PolicyEditor overview={policy.data} />
          <section className="panel">
            <div className="panel-head"><h2>Controls</h2><span className="sub">{policy.data.controls.length} controls · latest results across assets</span></div>
            <div className="table-wrap"><table>
              <thead><tr><th scope="col">Severity</th><th scope="col">Control</th><th scope="col">Origin</th><th scope="col">Passing</th><th scope="col">Failing</th><th scope="col">Plan</th></tr></thead>
              <tbody>
                {policy.data.controls.map((c, i) => (
                  <tr key={`${c.key}-${i}`}>
                    <td><SeverityChip severity={c.severity} /></td>
                    <th scope="row">{c.title}<span className="cell-sub">{c.rationale?.slice(0, 110)}</span></th>
                    <td><Chip tone="neutral">{label(c.origin)}</Chip></td>
                    <td className="num" style={{ color: "var(--pass)" }}>{c.results.PASS ?? 0}</td>
                    <td className="num" style={{ color: (c.results.FAIL ?? 0) > 0 ? "var(--fail)" : undefined }}>{c.results.FAIL ?? 0}</td>
                    <td>{c.has_remediation ? <Chip tone="ok">Reviewed</Chip> : <Chip tone="never">None</Chip>}</td>
                  </tr>
                ))}
              </tbody>
            </table></div>
          </section>
        </div>
      )}
    </>
  );
}

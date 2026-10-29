import { Link, useNavigate } from "react-router-dom";
import { useOverview } from "../lib/hooks";
import { ago, label, pct } from "../lib/format";
import { Chip, Empty, ErrorNotice, Meter, PageHeading, Ring, SeverityChip, Skeleton, Stacked, Trend } from "../components/ui";

const SEV_COLORS = { critical: "var(--sev-critical)", high: "var(--sev-high)", medium: "var(--sev-medium)", low: "var(--sev-low)" } as const;

export default function Overview() {
  const overview = useOverview();
  const navigate = useNavigate();
  const heading = <PageHeading title="Overview" description="State and completeness of authorized configuration assessments, shown side by side." actions={<Link className="btn primary" to="/assessments">New assessment</Link>} />;
  if (overview.isPending) return <>{heading}<div className="grid hero"><div className="panel"><Skeleton rows={5} /></div><div className="panel"><Skeleton rows={5} /></div></div></>;
  if (overview.isError) return <>{heading}<ErrorNotice error={overview.error} /></>;
  const o = overview.data;
  const hasResults = o.compliance_pct !== null;
  const openTotal = Object.values(o.open_by_severity).reduce((a, b) => a + b, 0);
  const urgent = o.open_by_severity.critical + o.open_by_severity.high;
  const complianceTone = o.compliance_pct === null ? undefined : o.compliance_pct >= 85 ? "pass" : o.compliance_pct >= 60 ? "warn" : "fail";

  return (
    <>
      {heading}
      {!hasResults ? (
        <section className="panel"><Empty icon="shield" title="No assessment results yet">Register an asset, then import evidence or run an assessment. Scores stay unmeasured until the evaluator stores results — no placeholder numbers are shown.</Empty></section>
      ) : (
        <div className="stack">
          <div className="grid hero">
            <section className="panel score-card" aria-label="Compliance and completeness">
              <Ring value={o.compliance_pct} caption="Compliance" />
              <div className="score-meta">
                <Meter label="Evaluated compliance" value={o.compliance_pct} tone={complianceTone} />
                <Meter label="Assessment completeness" value={o.completeness_pct} />
                <p className="quiet">{o.totals.passed} passed · {o.totals.failed} failed · {o.totals.unknown + o.totals.error + o.totals.manual_required} unresolved across {o.asset_count} assets</p>
              </div>
            </section>
            <div className="grid cols-4" style={{ gridTemplateColumns: "repeat(2, minmax(0, 1fr))" }}>
              <section className="panel kpi" style={{ ["--kpi-glow" as string]: "rgb(255 93 115 / 22%)" }}><span className="label">Open findings</span><span className="value">{o.findings_by_state.OPEN}</span><span className="hint">{o.findings_by_state.RISK_ACCEPTED} risk-accepted · {o.findings_by_state.RESOLVED} resolved</span></section>
              <section className="panel kpi" style={{ ["--kpi-glow" as string]: "rgb(255 146 72 / 22%)" }}><span className="label">Critical + high</span><span className="value">{urgent}</span><span className="hint">of {openTotal} open findings</span></section>
              <section className="panel kpi"><span className="label">Assets in scope</span><span className="value">{o.asset_count}</span><span className="hint">{o.freshness.fresh} fresh · {o.freshness.stale} stale · {o.freshness.never} never assessed</span></section>
              <section className="panel kpi" style={{ ["--kpi-glow" as string]: "rgb(129 140 248 / 22%)" }}><span className="label">Latest run</span><span className="value" style={{ fontSize: 22, paddingTop: 8 }}>{o.latest_run ? label(o.latest_run.status) : "None"}</span><span className="hint">{o.latest_run ? ago(o.latest_run.created_at) : "No runs yet"}</span></section>
            </div>
          </div>

          <div className="grid halves">
            <section className="panel">
              <div className="panel-head"><h2>Compliance trend</h2><span className="sub">{o.trend.length} result sets</span></div>
              <Trend points={o.trend.map((t) => t.compliance_pct)} />
            </section>
            <section className="panel">
              <div className="panel-head"><h2>Open findings by severity</h2><Link className="btn sm" to="/findings">Open queue</Link></div>
              <Stacked parts={(["critical", "high", "medium", "low"] as const).map((s) => ({ label: label(s), value: o.open_by_severity[s], color: SEV_COLORS[s] }))} />
            </section>
          </div>

          <div className="grid two">
            <section className="panel">
              <div className="panel-head"><h2>Asset posture</h2><span className="sub">Latest result per asset</span></div>
              <div className="table-wrap">
                <table>
                  <thead><tr><th scope="col">Asset</th><th scope="col">Compliance</th><th scope="col" className="num">Failed</th><th scope="col">Evidence</th></tr></thead>
                  <tbody>
                    {o.posture.map((row) => (
                      <tr key={row.asset_id} className="clickable" tabIndex={0} onClick={() => navigate(`/findings?asset=${row.asset_id}`)} onKeyDown={(e) => e.key === "Enter" && navigate(`/findings?asset=${row.asset_id}`)}>
                        <th scope="row">{row.name}<span className="cell-sub">{row.address} · {row.role}</span></th>
                        <td><div className="mini-bar"><div className={`bar tone-${(row.compliance_pct ?? 0) >= 85 ? "pass" : (row.compliance_pct ?? 0) >= 60 ? "warn" : "fail"}`}><i style={{ width: `${row.compliance_pct ?? 0}%` }} /></div><b>{pct(row.compliance_pct)}</b></div></td>
                        <td className="num">{row.failed}</td>
                        <td><Chip tone={row.freshness} /> {row.source && <Chip tone={row.source} />}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </section>
            <section className="panel">
              <div className="panel-head"><h2>Recent activity</h2></div>
              {o.recent_events.length === 0 ? <p className="quiet">No finding activity yet.</p> : (
                <div className="feed">
                  {o.recent_events.map((event, index) => (
                    <div className="feed-item" key={index}>
                      <span className={`pip ${event.kind}`} />
                      <p>{event.title}<br /><small>{event.asset} · {label(event.kind)} · <SeverityChip severity={event.severity} /></small></p>
                      <time>{ago(event.at)}</time>
                    </div>
                  ))}
                </div>
              )}
            </section>
          </div>
        </div>
      )}
    </>
  );
}

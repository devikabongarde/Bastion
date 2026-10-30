import { useMemo } from "react";
import { Link, useNavigate } from "react-router-dom";
import {
  Activity,
  ArrowDownRight,
  ArrowRight,
  ArrowUpRight,
  CheckCircle2,
  Clock,
  FileText,
  Monitor,
  Network,
  PlayCircle,
  Server,
  ShieldAlert,
  Terminal,
  TriangleAlert,
} from "lucide-react";
import { useOverview, usePrincipal } from "../lib/hooks";
import { ago } from "../lib/format";
import type { Overview as OverviewData, PostureRow, Severity } from "../lib/api";
import { CountUp } from "../components/reactbits/CountUp";
import { ErrorNotice, Skeleton } from "../components/ui";

/* ---------- helpers ---------- */

const verdicts = [
  { key: "passed", label: "Pass", color: "var(--db-pass)" },
  { key: "failed", label: "Fail", color: "var(--db-fail)" },
  { key: "unknown", label: "Unknown", color: "var(--db-unknown)" },
  { key: "error", label: "Error", color: "var(--db-error)" },
  { key: "manual_required", label: "Manual", color: "var(--db-manual)" },
  { key: "not_applicable", label: "N/A", color: "var(--db-na)" },
] as const;

const severities: Array<{ key: Severity; label: string; color: string }> = [
  { key: "critical", label: "Critical", color: "var(--db-critical)" },
  { key: "high", label: "High", color: "var(--db-high)" },
  { key: "medium", label: "Medium", color: "var(--db-medium)" },
  { key: "low", label: "Low", color: "var(--db-low)" },
];

const roleNames: Record<string, string> = {
  platform_admin: "Platform admin",
  risk_approver: "Risk approver",
  auditor: "Auditor",
  analyst: "Analyst",
  scan_operator: "Scan operator",
  viewer: "Viewer",
};

function greeting() {
  const h = new Date().getHours();
  return h < 12 ? "Good morning" : h < 18 ? "Good afternoon" : "Good evening";
}

function platformIcon(category: string) {
  const c = category.toLowerCase();
  if (c.includes("windows")) return Monitor;
  if (c.includes("cisco") || c.includes("switch") || c.includes("router")) return Network;
  if (c.includes("forti") || c.includes("firewall") || c.includes("pan")) return ShieldAlert;
  if (c.includes("linux") || c.includes("ubuntu") || c.includes("rhel")) return Terminal;
  return Server;
}

/** Smooth SVG path through points (Catmull-Rom → cubic Bézier). */
function smoothPath(points: Array<[number, number]>) {
  if (points.length < 2) return "";
  let d = `M${points[0][0]},${points[0][1]}`;
  for (let i = 0; i < points.length - 1; i++) {
    const p0 = points[i - 1] ?? points[i];
    const p1 = points[i];
    const p2 = points[i + 1];
    const p3 = points[i + 2] ?? p2;
    const c1 = [p1[0] + (p2[0] - p0[0]) / 6, p1[1] + (p2[1] - p0[1]) / 6];
    const c2 = [p2[0] - (p3[0] - p1[0]) / 6, p2[1] - (p3[1] - p1[1]) / 6];
    d += ` C${c1[0]},${c1[1]} ${c2[0]},${c2[1]} ${p2[0]},${p2[1]}`;
  }
  return d;
}

const platformGroups = [
  { key: "windows", label: "Windows", icon: Monitor, categories: ["windows"] },
  { key: "linux", label: "Linux", icon: Terminal, categories: ["linux"] },
  { key: "firewall", label: "Firewalls", icon: ShieldAlert, categories: ["firewall"] },
  { key: "network", label: "Routers & switches", icon: Network, categories: ["router", "switch"] },
];

/* ---------- pieces ---------- */

function PlatformBreakdown({ rows }: { rows: PostureRow[] }) {
  return (
    <section className="db-platforms" aria-label="Compliance by asset type">
      {platformGroups.map((g) => {
        const members = rows.filter((r) => g.categories.includes(r.category));
        const passed = members.reduce((s, r) => s + r.passed, 0);
        const failed = members.reduce((s, r) => s + r.failed, 0);
        const pctValue = passed + failed > 0 ? (passed / (passed + failed)) * 100 : null;
        const tone = pctValue === null ? "none" : pctValue >= 90 ? "good" : pctValue >= 60 ? "warn" : "bad";
        const Icon = g.icon;
        return (
          <Link key={g.key} to="/assets" className="db-card db-platform">
            <div className="db-platform-head">
              <span className="db-asset-icon"><Icon className="w-4 h-4" /></span>
              <b>{g.label}</b>
            </div>
            <span className={`db-platform-pct ${tone}`}>{pctValue === null ? "—" : `${pctValue.toFixed(1)}%`}</span>
            <span className="db-bar"><i className={tone} style={{ width: `${pctValue ?? 0}%` }} /></span>
            <span className="db-kpi-foot">
              {members.length} asset{members.length === 1 ? "" : "s"} · {failed} failing check{failed === 1 ? "" : "s"}
            </span>
          </Link>
        );
      })}
    </section>
  );
}

function Sparkline({ values }: { values: number[] }) {
  if (values.length < 2) return null;
  const min = Math.min(...values), max = Math.max(...values);
  const pts = values.map((v, i): [number, number] => [(i / (values.length - 1)) * 80, 22 - ((v - min) / (max - min || 1)) * 18]);
  return (
    <svg viewBox="0 0 80 24" className="db-spark" aria-hidden="true">
      <path d={smoothPath(pts)} />
    </svg>
  );
}

function TrendChart({ trend }: { trend: OverviewData["trend"] }) {
  const rows = trend.filter((t) => t.compliance_pct !== null) as Array<{ at: string; compliance_pct: number; failed: number }>;
  if (rows.length < 2) {
    return <div className="db-empty-chart">Run at least two assessments to see a trend.</div>;
  }
  const W = 600, H = 200, padY = 14;
  const pts = rows.map((r, i): [number, number] => [(i / (rows.length - 1)) * W, padY + (1 - r.compliance_pct / 100) * (H - padY * 2)]);
  const line = smoothPath(pts);
  const last = pts[pts.length - 1];
  return (
    <div className="db-chart-wrap">
      <div className="db-chart-y" aria-hidden="true"><span>100%</span><span>50%</span><span>0%</span></div>
      <svg viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="none" className="db-chart" role="img" aria-label={`Compliance moved from ${rows[0].compliance_pct}% to ${rows[rows.length - 1].compliance_pct}%`}>
        <defs>
          <linearGradient id="db-area" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0" stopColor="var(--db-pass)" stopOpacity=".28" />
            <stop offset="1" stopColor="var(--db-pass)" stopOpacity="0" />
          </linearGradient>
        </defs>
        {[padY, H / 2, H - padY].map((y) => <line key={y} x1="0" x2={W} y1={y} y2={y} className="db-gridline" />)}
        <path d={`${line} L${W},${H} L0,${H} Z`} fill="url(#db-area)" className="db-area" />
        <path d={line} className="db-line" />
        {pts.map(([x, y], i) => <circle key={i} cx={x} cy={y} r={i === pts.length - 1 ? 0 : 3} className="db-point" />)}
        <circle cx={last[0]} cy={last[1]} r="5" className="db-point-last" />
      </svg>
      <div className="db-chart-x" aria-hidden="true">
        <span>{new Date(rows[0].at).toLocaleDateString(undefined, { month: "short", day: "numeric" })}</span>
        <span>{rows.length} assessments</span>
        <span>Latest</span>
      </div>
    </div>
  );
}

function VerdictDonut({ totals }: { totals: OverviewData["totals"] }) {
  const total = verdicts.reduce((s, v) => s + totals[v.key], 0);
  const R = 52, C = 2 * Math.PI * R;
  let offset = 0;
  return (
    <div className="db-donut-wrap">
      <div className="db-donut">
        <svg viewBox="0 0 132 132" aria-hidden="true">
          <circle cx="66" cy="66" r={R} className="db-donut-track" />
          {total > 0 && verdicts.map((v) => {
            const len = (totals[v.key] / total) * C;
            const seg = (
              <circle key={v.key} cx="66" cy="66" r={R} stroke={v.color} strokeDasharray={`${Math.max(len - 2, 0)} ${C}`} strokeDashoffset={-offset} className="db-donut-seg" />
            );
            offset += len;
            return totals[v.key] > 0 ? seg : null;
          })}
        </svg>
        <div className="db-donut-center"><b><CountUp to={total} /></b><span>checks</span></div>
      </div>
      <ul className="db-legend">
        {verdicts.map((v) => (
          <li key={v.key}>
            <i style={{ background: v.color }} />
            <span>{v.label}</span>
            <b>{totals[v.key]}</b>
          </li>
        ))}
      </ul>
    </div>
  );
}

function PostureList({ rows }: { rows: PostureRow[] }) {
  const navigate = useNavigate();
  const sorted = [...rows].sort((a, b) => (a.compliance_pct ?? -1) - (b.compliance_pct ?? -1));
  if (!sorted.length) return <div className="db-empty-chart">No assets yet. Add one from the Assets page.</div>;
  return (
    <div className="db-posture">
      {sorted.map((r) => {
        const Icon = platformIcon(r.category);
        const pctVal = r.compliance_pct ?? 0;
        const tone = r.compliance_pct === null ? "none" : pctVal >= 90 ? "good" : pctVal >= 60 ? "warn" : "bad";
        return (
          <button key={r.asset_id} type="button" className="db-posture-row" onClick={() => navigate(`/findings?asset=${r.asset_id}`)}>
            <span className="db-asset-icon"><Icon className="w-4 h-4" /></span>
            <span className="db-asset-name">
              <b>{r.name}</b>
              <small>{r.address} · {r.role}</small>
            </span>
            <span className={`db-crit ${r.criticality}`}>{r.criticality}</span>
            <span className="db-bar"><i className={tone} style={{ width: `${pctVal}%` }} /></span>
            <span className={`db-pct ${tone}`}>{r.compliance_pct === null ? "—" : `${Math.round(pctVal)}%`}</span>
            <span className="db-fails">{r.failed > 0 ? <><TriangleAlert className="w-3.5 h-3.5" /> {r.failed}</> : <CheckCircle2 className="w-4 h-4 db-ok" />}</span>
          </button>
        );
      })}
    </div>
  );
}

const eventMeta: Record<string, { label: string; tone: string; icon: typeof CheckCircle2 }> = {
  FIXED_VERIFIED: { label: "Fixed & verified", tone: "good", icon: CheckCircle2 },
  OPENED: { label: "New finding", tone: "bad", icon: TriangleAlert },
  REOPENED: { label: "Reopened", tone: "bad", icon: TriangleAlert },
};

/* ---------- page ---------- */

export default function Overview() {
  const overview = useOverview();
  const principal = usePrincipal();
  const navigate = useNavigate();
  const data = overview.data;

  const trendValues = useMemo(
    () => (data?.trend ?? []).map((t) => t.compliance_pct).filter((v): v is number => v !== null),
    [data]
  );

  if (overview.isPending) {
    return <div className="db"><Skeleton rows={6} /></div>;
  }
  if (overview.isError || !data) {
    return <div className="db"><ErrorNotice error={overview.error} /></div>;
  }

  const role = principal.data?.roles.find((r) => roleNames[r]);
  const open = data.findings_by_state.OPEN ?? 0;
  const urgent = data.open_by_severity.critical + data.open_by_severity.high;
  const delta = trendValues.length >= 2 ? trendValues[trendValues.length - 1] - trendValues[trendValues.length - 2] : null;
  const maxSev = Math.max(1, ...severities.map((s) => data.open_by_severity[s.key]));
  const freshTotal = data.freshness.fresh + data.freshness.stale + data.freshness.never;
  const hasResults = data.compliance_pct !== null;

  return (
    <div className="db">
      {/* ---------- header ---------- */}
      <header className="db-header">
        <div>
          <p className="db-greet">{greeting()}{role ? ` · ${roleNames[role]}` : ""}</p>
          <h1>Fleet posture</h1>
          <p className="db-sub">
            {data.asset_count} assets monitored · last assessment {data.latest_run ? ago(data.latest_run.created_at) : "never"}
            <span className="db-live"><i /> Live</span>
          </p>
        </div>
        <div className="db-actions">
          <button type="button" className="db-btn secondary" onClick={() => navigate("/reports")}>
            <FileText className="w-4 h-4" /> Export report
          </button>
          <button type="button" className="db-btn primary" onClick={() => navigate("/assessments")}>
            <PlayCircle className="w-4 h-4" /> Run assessment
          </button>
        </div>
      </header>

      {!hasResults && (
        <div className="db-card db-onboard">
          <Activity className="w-5 h-5" />
          <div>
            <b>No assessment results yet</b>
            <span>Submit evidence for an asset to see compliance, findings and trends here.</span>
          </div>
          <button type="button" className="db-btn primary" onClick={() => navigate("/assessments")}>Start first assessment</button>
        </div>
      )}

      {/* ---------- KPIs ---------- */}
      <section className="db-kpis" aria-label="Key metrics">
        <div className="db-card db-kpi featured">
          <span className="db-kpi-label">Compliance</span>
          <b className="db-kpi-value">{hasResults ? <><CountUp to={data.compliance_pct ?? 0} decimals={1} />%</> : "—"}</b>
          <span className="db-kpi-foot">
            {delta !== null && (
              <em className={delta >= 0 ? "up" : "down"}>
                {delta >= 0 ? <ArrowUpRight className="w-3.5 h-3.5" /> : <ArrowDownRight className="w-3.5 h-3.5" />}
                {Math.abs(delta).toFixed(1)} pts
              </em>
            )}
            {data.totals.passed} of {data.totals.passed + data.totals.failed} evaluated passed
          </span>
          <Sparkline values={trendValues} />
        </div>
        <div className="db-card db-kpi">
          <span className="db-kpi-label">Completeness</span>
          <b className="db-kpi-value">{data.completeness_pct !== null ? <><CountUp to={data.completeness_pct} decimals={1} />%</> : "—"}</b>
          <span className="db-meter"><i style={{ width: `${data.completeness_pct ?? 0}%` }} /></span>
          <span className="db-kpi-foot">Share of controls with a definite verdict</span>
        </div>
        <Link to="/findings" className="db-card db-kpi link">
          <span className="db-kpi-label">Open findings <ArrowRight className="w-3.5 h-3.5" /></span>
          <b className="db-kpi-value"><CountUp to={open} /></b>
          <span className="db-kpi-foot">
            {urgent > 0 ? <em className="down"><TriangleAlert className="w-3.5 h-3.5" /> {urgent} critical/high</em> : <em className="up">No critical or high</em>}
            {data.findings_by_state.RESOLVED ?? 0} resolved
          </span>
        </Link>
        <Link to="/assets" className="db-card db-kpi link">
          <span className="db-kpi-label">Assets <ArrowRight className="w-3.5 h-3.5" /></span>
          <b className="db-kpi-value"><CountUp to={data.asset_count} /></b>
          <span className="db-fresh">
            <i className="fresh" style={{ flex: data.freshness.fresh || 0.0001 }} />
            <i className="stale" style={{ flex: data.freshness.stale || 0.0001 }} />
            <i className="never" style={{ flex: data.freshness.never || 0.0001 }} />
          </span>
          <span className="db-kpi-foot">
            <Clock className="w-3.5 h-3.5" /> {data.freshness.fresh}/{freshTotal} fresh evidence
          </span>
        </Link>
      </section>

      {/* ---------- by asset type ---------- */}
      <PlatformBreakdown rows={data.posture} />

      {/* ---------- charts ---------- */}
      <section className="db-grid two">
        <div className="db-card">
          <div className="db-card-head">
            <div><h2>Compliance trend</h2><p>Across recent assessments</p></div>
            {trendValues.length > 0 && <span className="db-chip">{trendValues[trendValues.length - 1].toFixed(1)}% now</span>}
          </div>
          <TrendChart trend={data.trend} />
        </div>
        <div className="db-card">
          <div className="db-card-head"><div><h2>Verdict distribution</h2><p>Every control on every asset</p></div></div>
          <VerdictDonut totals={data.totals} />
        </div>
      </section>

      {/* ---------- detail ---------- */}
      <section className="db-grid three">
        <div className="db-card">
          <div className="db-card-head">
            <div><h2>Asset posture</h2><p>Lowest compliance first</p></div>
            <Link to="/assets" className="db-link">All assets <ArrowRight className="w-3.5 h-3.5" /></Link>
          </div>
          <PostureList rows={data.posture} />
        </div>

        <div className="db-stack">
          <div className="db-card">
            <div className="db-card-head">
              <div><h2>Open by severity</h2><p>{open} findings need attention</p></div>
              <Link to="/findings" className="db-link">Queue <ArrowRight className="w-3.5 h-3.5" /></Link>
            </div>
            <div className="db-sev">
              {severities.map((s) => (
                <Link key={s.key} to={`/findings?severity=${s.key}`} className="db-sev-row">
                  <span><i style={{ background: s.color }} />{s.label}</span>
                  <span className="db-sev-track"><i style={{ width: `${(data.open_by_severity[s.key] / maxSev) * 100}%`, background: s.color }} /></span>
                  <b>{data.open_by_severity[s.key]}</b>
                </Link>
              ))}
            </div>
          </div>

          <div className="db-card">
            <div className="db-card-head"><div><h2>Recent activity</h2><p>Latest finding events</p></div></div>
            {data.recent_events.length === 0 ? (
              <div className="db-empty-chart">No activity yet.</div>
            ) : (
              <ol className="db-timeline">
                {data.recent_events.slice(0, 5).map((e, i) => {
                  const meta = eventMeta[e.kind] ?? { label: e.kind.replaceAll("_", " ").toLowerCase(), tone: "neutral", icon: Activity };
                  const Icon = meta.icon;
                  return (
                    <li key={i}>
                      <span className={`db-tl-icon ${meta.tone}`}><Icon className="w-3.5 h-3.5" /></span>
                      <div>
                        <b>{e.title}</b>
                        <small><span className={`db-tl-tag ${meta.tone}`}>{meta.label}</span> {e.asset} · {ago(e.at)}</small>
                      </div>
                    </li>
                  );
                })}
              </ol>
            )}
          </div>
        </div>
      </section>
    </div>
  );
}

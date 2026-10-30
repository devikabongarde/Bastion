import { useEffect, useMemo, useState, type ReactNode } from "react";
import { useNavigate } from "react-router-dom";
import { ArrowLeft, ArrowRight, Info, Search, TriangleAlert } from "lucide-react";
import { Logo } from "../components/Logo";

/* ---------- table of contents ---------- */

const sections = [
  {
    group: "Getting started",
    items: [
      { id: "introduction", title: "Introduction" },
      { id: "signing-in", title: "Signing in" },
      { id: "roles", title: "Roles & permissions" },
      { id: "navigating", title: "Finding your way around" },
    ],
  },
  {
    group: "Core concepts",
    items: [
      { id: "verdicts", title: "Verdicts" },
      { id: "scores", title: "Compliance & completeness" },
      { id: "evidence", title: "Evidence & integrity" },
    ],
  },
  {
    group: "Using the console",
    items: [
      { id: "assets", title: "Managing assets" },
      { id: "assessments", title: "Running assessments" },
      { id: "findings", title: "Reviewing findings" },
      { id: "policies", title: "Policies & impact preview" },
      { id: "exceptions", title: "Risk exceptions" },
      { id: "schedules", title: "Schedules" },
      { id: "reports", title: "Reports" },
    ],
  },
  {
    group: "Reference",
    items: [
      { id: "security", title: "Security & privacy" },
      { id: "limits", title: "What Bastion won't do" },
      { id: "faq", title: "FAQ" },
    ],
  },
];

const flat = sections.flatMap((s) => s.items);

/* ---------- small prose building blocks ---------- */

function Section({ id, eyebrow, title, children }: { id: string; eyebrow?: string; title: string; children: ReactNode }) {
  return (
    <section id={id} className="docs-section" data-docs-section>
      {eyebrow && <p className="docs-eyebrow">{eyebrow}</p>}
      <h2>
        <a href={`#${id}`} className="docs-anchor">{title}</a>
      </h2>
      {children}
    </section>
  );
}

function Steps({ children }: { children: ReactNode }) {
  return <ol className="docs-steps">{children}</ol>;
}

function Callout({ tone = "info", title, children }: { tone?: "info" | "warn"; title: string; children: ReactNode }) {
  const Icon = tone === "warn" ? TriangleAlert : Info;
  return (
    <div className={`docs-callout ${tone}`}>
      <Icon className="w-[18px] h-[18px] shrink-0 mt-0.5" />
      <div>
        <strong>{title}</strong>
        <div>{children}</div>
      </div>
    </div>
  );
}

function Kbd({ children }: { children: ReactNode }) {
  return <kbd className="docs-kbd">{children}</kbd>;
}

const verdicts = [
  { name: "PASS", cls: "pass", text: "The collected evidence proves the control is configured as the policy expects." },
  { name: "FAIL", cls: "fail", text: "The evidence proves the setting differs from the expected value. You get observed vs. expected values and a remediation." },
  { name: "UNKNOWN", cls: "unknown", text: "Bastion could not prove either way — a command was missing, output could not be parsed, or data was incomplete." },
  { name: "ERROR", cls: "error", text: "Collection itself failed: a connection dropped, credentials were refused, or permissions were missing." },
  { name: "MANUAL", cls: "manual", text: "The control needs a human to verify it (for example, a physical or procedural check)." },
  { name: "N/A", cls: "na", text: "The control does not apply to this asset's platform or role." },
];

/* ---------- page ---------- */

export default function Docs() {
  const navigate = useNavigate();
  const [query, setQuery] = useState("");
  const [active, setActive] = useState(flat[0].id);

  // Scroll-spy: highlight the section currently in view
  useEffect(() => {
    const els = Array.from(document.querySelectorAll<HTMLElement>("[data-docs-section]"));
    const observer = new IntersectionObserver(
      (entries) => {
        const visible = entries.filter((e) => e.isIntersecting).sort((a, b) => a.boundingClientRect.top - b.boundingClientRect.top);
        if (visible[0]) setActive(visible[0].target.id);
      },
      { rootMargin: "-80px 0px -65% 0px" }
    );
    els.forEach((el) => observer.observe(el));
    return () => observer.disconnect();
  }, []);

  // Honour deep links like /docs#verdicts; otherwise start at the top
  useEffect(() => {
    const target = window.location.hash && document.getElementById(window.location.hash.slice(1));
    if (target) target.scrollIntoView();
    else window.scrollTo(0, 0);
  }, []);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return sections;
    return sections
      .map((s) => ({ ...s, items: s.items.filter((i) => i.title.toLowerCase().includes(q)) }))
      .filter((s) => s.items.length > 0);
  }, [query]);

  const index = flat.findIndex((i) => i.id === active);
  const prev = flat[index - 1];
  const next = flat[index + 1];

  return (
    <div className="docs-root">
      <header className="docs-header">
        <div className="flex items-center gap-4">
          <button type="button" className="docs-logo-btn" onClick={() => navigate("/")} aria-label="Bastion home">
            <Logo size={26} />
          </button>
          <span className="docs-badge">Docs</span>
        </div>
        <div className="flex items-center gap-2">
          <button type="button" className="docs-link-btn" onClick={() => navigate("/")}>Home</button>
          <button type="button" className="docs-primary-btn" onClick={() => navigate("/login")}>
            Sign in <ArrowRight className="w-3.5 h-3.5" />
          </button>
        </div>
      </header>

      <div className="docs-layout">
        <aside className="docs-sidebar" aria-label="Documentation sections">
          <label className="docs-search">
            <Search className="w-4 h-4" />
            <input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Search docs…" aria-label="Search documentation" />
          </label>
          <nav>
            {filtered.map((s) => (
              <div key={s.group} className="docs-nav-group">
                <p>{s.group}</p>
                {s.items.map((i) => (
                  <a key={i.id} href={`#${i.id}`} className={active === i.id ? "active" : ""}>
                    {i.title}
                  </a>
                ))}
              </div>
            ))}
            {filtered.length === 0 && <p className="docs-empty">No sections match “{query}”.</p>}
          </nav>
        </aside>

        <main className="docs-content">
          <div className="docs-hero">
            <p className="docs-eyebrow">User guide</p>
            <h1>Bastion documentation</h1>
            <p className="docs-lead">
              Everything you need to audit your servers, firewalls and switches with Bastion — from your first sign-in
              to exporting a signed compliance report.
            </p>
          </div>

          <Section id="introduction" eyebrow="Getting started" title="Introduction">
            <p>
              Bastion is a self-hosted compliance and hardening auditor. It collects real configuration evidence from your
              infrastructure, evaluates it against versioned security policies, and shows you exactly what passed, what
              failed, and what it couldn't verify.
            </p>
            <div className="docs-cards">
              <div><b>Read-only</b><span>Bastion inspects configuration. It never changes your devices.</span></div>
              <div><b>Deterministic</b><span>The same evidence and policy always produce the same verdict.</span></div>
              <div><b>Offline-capable</b><span>Runs inside your network with zero external telemetry.</span></div>
            </div>
            <p>
              Supported platforms: Windows Server 2019/2022 and Windows 11, Ubuntu 20.04/22.04 LTS, Cisco IOS-XE
              routers and Catalyst switches, and Fortinet FortiGate firewalls.
            </p>
          </Section>

          <Section id="signing-in" title="Signing in">
            <p>Bastion protects every workspace with a password and a second factor (MFA).</p>
            <Steps>
              <li>Open the Bastion console in your browser and choose <b>Sign in</b>.</li>
              <li>Enter your <b>Organization</b> (your workspace ID, e.g. <code>northwind</code>), your <b>Username</b> and <b>Password</b>.</li>
              <li>Select <b>Enter Console</b>.</li>
              <li>Enter the six-digit code from your authenticator app (Google Authenticator, 1Password, Authy, etc.).</li>
            </Steps>
            <Callout title="Lost your authenticator?">
              Choose <b>Use a recovery code</b> on the verification screen and enter one of the 20-character recovery
              codes you saved when MFA was set up. Each code works only once.
            </Callout>
            <p>To end your session, choose <b>Sign out</b> in the top bar of the console.</p>
          </Section>

          <Section id="roles" title="Roles & permissions">
            <p>What you can see and do depends on the roles your administrator assigned to you.</p>
            <div className="docs-table-wrap">
              <table className="docs-table">
                <thead><tr><th>Role</th><th>Can do</th></tr></thead>
                <tbody>
                  <tr><td><b>Viewer</b></td><td>Browse dashboards, assets and findings (read-only).</td></tr>
                  <tr><td><b>Analyst</b></td><td>Investigate findings, request exceptions and generate reports.</td></tr>
                  <tr><td><b>Scan operator</b></td><td>Submit evidence, launch assessments and manage schedules.</td></tr>
                  <tr><td><b>Auditor</b></td><td>Review evidence and generate signed reports.</td></tr>
                  <tr><td><b>Policy author / approver</b></td><td>Draft tailored policies / approve them for publishing (two different people).</td></tr>
                  <tr><td><b>Risk approver</b></td><td>Approve, reject or revoke risk exceptions requested by others.</td></tr>
                  <tr><td><b>Platform admin</b></td><td>Full workspace administration, including assets, users and schedules.</td></tr>
                </tbody>
              </table>
            </div>
            <p>If a page shows <i>Read-only access</i>, your role doesn't include that action — ask an administrator.</p>
          </Section>

          <Section id="navigating" title="Finding your way around">
            <p>The left sidebar takes you to each area of the console:</p>
            <ul className="docs-list">
              <li><b>Overview</b> — fleet compliance at a glance, open findings by severity and drift over time.</li>
              <li><b>Assets</b> — every server, firewall and switch Bastion audits.</li>
              <li><b>Assessments</b> — each audit run, from request to result.</li>
              <li><b>Findings</b> — individual failed or unresolved controls with remediation.</li>
              <li><b>Exceptions</b> — time-boxed risk acceptances.</li>
              <li><b>Schedules</b> — recurring audits.</li>
              <li><b>Reports</b> — signed exports for auditors.</li>
              <li><b>Policies</b> — the baselines your assets are checked against.</li>
            </ul>
            <Callout title="Keyboard shortcut">
              Press <Kbd>Ctrl</Kbd> + <Kbd>K</Kbd> (<Kbd>⌘</Kbd> + <Kbd>K</Kbd> on Mac) anywhere in the console to open
              the command palette and jump to any page or action. You can also switch between light and dark theme from there.
            </Callout>
          </Section>

          <Section id="verdicts" eyebrow="Core concepts" title="Verdicts">
            <p>Every control on every asset receives exactly one of six verdicts. Bastion never guesses — missing data stays visible.</p>
            <div className="docs-verdicts">
              {verdicts.map((v) => (
                <div key={v.name}>
                  <span className={`docs-verdict ${v.cls}`}>{v.name}</span>
                  <p>{v.text}</p>
                </div>
              ))}
            </div>
          </Section>

          <Section id="scores" title="Compliance & completeness">
            <p>The Overview shows two numbers side by side, so gaps can never masquerade as passing checks:</p>
            <ul className="docs-list">
              <li><b>Compliance</b> — of the controls Bastion could evaluate, the share that passed.</li>
              <li><b>Completeness</b> — the share of applicable controls that produced a definite PASS or FAIL. Low completeness means many results are UNKNOWN or ERROR.</li>
            </ul>
            <Callout tone="warn" title="Read both numbers together">
              A 100% compliance score with 40% completeness means most controls weren't verified. Fix collection
              errors first, then remediate failures.
            </Callout>
          </Section>

          <Section id="evidence" title="Evidence & integrity">
            <p>
              Every result links back to the exact configuration text it was based on. Open any finding to see the
              evidence pointer (the source file and line), the expected value, and the observed value.
            </p>
            <p>
              Raw collected output is hashed with SHA-256, and each assessment is chained to the previous one. If stored
              results were ever altered, the chain breaks and the change is detectable. Secrets such as passwords are
              redacted before evidence is stored.
            </p>
          </Section>

          <Section id="assets" eyebrow="Using the console" title="Managing assets">
            <p>An asset is any device Bastion audits. Open <b>Assets</b> to see your fleet, its platforms and last assessment.</p>
            <h3>Importing many assets with CSV</h3>
            <Steps>
              <li>Go to <b>Assets</b> and choose <b>Import CSV</b>.</li>
              <li>Paste your CSV, or choose <b>Insert Sample Template</b> to see the expected columns.</li>
              <li>Choose <b>Validate CSV</b>. Each row is checked — platform, port and address — and you get a dry-run preview.</li>
              <li>Fix any rows flagged with errors, then choose <b>Commit Import</b>. All rows are saved together, or none are.</li>
            </Steps>
            <h3>Connecting a live device</h3>
            <Steps>
              <li>Add the asset with a live adapter (Linux, Cisco IOS-XE or FortiGate over SSH), or choose <b>Windows · this machine</b>.</li>
              <li>For SSH devices, choose <b>Connect</b>. Bastion reads the device's SSH host key and shows its fingerprint.</li>
              <li>Compare the fingerprint with the device console, enter a read-only audit account, and choose <b>Trust this key &amp; connect</b>.</li>
              <li>The asset now shows <b>Pinned</b> and a <b>Scan</b> action.</li>
            </Steps>
            <Callout title="Host keys">
              Bastion pins each device's host key. If a device later presents a different key, collection is refused
              instead of trusting an unknown host.
            </Callout>
          </Section>

          <Section id="assessments" title="Running assessments">
            <p>An assessment collects evidence from an asset and evaluates it against the active policy.</p>
            <Steps>
              <li>Go to <b>Assessments</b>.</li>
              <li>Under <b>Live scan</b>, tick the devices to audit and choose <b>Scan now</b> — results arrive in seconds. You can also use <b>Scan</b> on any ready asset.</li>
              <li>For air-gapped networks, use <b>Offline import</b> to upload an evidence bundle instead.</li>
              <li>The run appears in <b>Recent assessments</b> and refreshes automatically until it completes.</li>
            </Steps>
            <p>Open a completed run to see its verdicts and the SHA-256 digest of the evidence it used.</p>
          </Section>

          <Section id="findings" title="Reviewing findings">
            <p>A finding is a control that failed or could not be verified. Open <b>Findings</b> and filter by severity, asset or state.</p>
            <p>Selecting a finding opens its detail panel with:</p>
            <ul className="docs-list">
              <li>the control reference (e.g. <i>CIS Cisco IOS 1.1.2 — Exec Timeout</i>),</li>
              <li><b>Expected</b> vs. <b>Observed</b> values,</li>
              <li>the evidence pointer to the exact configuration line,</li>
              <li>a ready-to-review remediation command for your platform.</li>
            </ul>
            <Callout tone="warn" title="Remediation is never applied automatically">
              Bastion generates the fix; your team reviews and applies it through your normal change process.
            </Callout>
          </Section>

          <Section id="policies" title="Policies & impact preview">
            <p>
              Policies are published, immutable baselines. Open <b>Policies</b> to browse each revision and the controls it
              evaluates.
            </p>
            <h3>Tailoring a policy</h3>
            <Steps>
              <li>Choose <b>New draft</b> and select the controls to exclude, with a reason for each.</li>
              <li>Choose <b>Preview Impact</b> to see how many assets are affected and which controls would flip from PASS to FAIL — before anything is published.</li>
              <li>Submit the draft. A <b>second person</b> must approve it before it's published.</li>
            </Steps>
            <p>Excluded controls stay visible in coverage, and a tailored score is never labeled as unmodified benchmark compliance.</p>
          </Section>

          <Section id="exceptions" title="Risk exceptions">
            <p>
              Sometimes a failing control can't be fixed right away. An exception records that the risk is accepted for a
              limited time — it never changes the technical result.
            </p>
            <Steps>
              <li>Open the finding and choose <b>Request Exception</b>.</li>
              <li>Enter a business justification, the compensating controls in place, and an expiration date.</li>
              <li>A <b>different</b> user with the Risk approver role reviews it in <b>Exceptions</b> and approves or rejects it.</li>
            </Steps>
            <Callout title="Dual custody">
              You can't approve your own request — self-approval is blocked by the server. When an exception expires, the
              finding becomes actionable again automatically.
            </Callout>
          </Section>

          <Section id="schedules" title="Schedules">
            <p>Schedules run live collection on a recurring basis so drift is caught early.</p>
            <Steps>
              <li>Go to <b>Schedules</b> and choose <b>New schedule</b>.</li>
              <li>Give it a name (e.g. <i>Nightly HQ audit</i>) and the site to cover.</li>
              <li>Enter a cron expression (minute, hour, day, month, weekday) — for example <code>0 2 * * *</code> for 2:00 every night.</li>
              <li>Set the time zone (e.g. <code>Europe/Berlin</code>) and save.</li>
            </Steps>
            <p>Each occurrence runs exactly once. Offline-import assets are skipped and recorded as skipped.</p>
          </Section>

          <Section id="reports" title="Reports">
            <p>Reports are frozen exports for auditors and stakeholders. Each records its scope, cutoff time and a SHA-256 digest of the file.</p>
            <Steps>
              <li>Go to <b>Reports</b> and open <b>New report</b>.</li>
              <li>Choose a format: <b>HTML</b>, <b>PDF</b>, <b>CSV</b> or <b>JSON</b>.</li>
              <li>Choose the evidence level — a summary of failures only, or full detail.</li>
              <li>Generate, then download from <b>Generated reports</b>.</li>
            </Steps>
          </Section>

          <Section id="security" eyebrow="Reference" title="Security & privacy">
            <ul className="docs-list">
              <li><b>Read-only collection.</b> Bastion runs inspection commands only — it never writes to your devices.</li>
              <li><b>Stays in your network.</b> No cloud services and no telemetry; it works fully air-gapped.</li>
              <li><b>Tenant isolation.</b> Each organization's data is isolated at the database level.</li>
              <li><b>Tamper evidence.</b> Hash-chained results make any later modification detectable.</li>
              <li><b>Strong sign-in.</b> Mandatory MFA, role-based access and two-person approval for sensitive actions.</li>
            </ul>
          </Section>

          <Section id="limits" title="What Bastion won't do">
            <ul className="docs-list">
              <li><b>Change your configuration.</b> It generates reviewed remediation, but never applies it.</li>
              <li><b>Claim official CIS certification.</b> Rules are independently authored baselines mapped to the CIS layout.</li>
              <li><b>Turn missing data into a pass.</b> Missing commands or unparsed output stay UNKNOWN.</li>
            </ul>
          </Section>

          <Section id="faq" title="FAQ">
            <div className="docs-faq">
              <details>
                <summary>Does Bastion use AI to decide results?</summary>
                <p>No. Verdicts come from deterministic rules, so the same configuration gives the same answer every time — which is what auditors require.</p>
              </details>
              <details>
                <summary>Can Bastion break or modify my servers?</summary>
                <p>No. It only runs read-only inspection commands such as <code>show running-config</code> or <code>auditpol /get</code>.</p>
              </details>
              <details>
                <summary>Why do I see UNKNOWN instead of PASS?</summary>
                <p>Bastion couldn't prove the setting — often because a command wasn't permitted or the output format wasn't recognized. Check the asset's credentials and permissions, then re-run the assessment.</p>
              </details>
              <details>
                <summary>How do I prove a report wasn't altered?</summary>
                <p>Every report stores a SHA-256 digest of its exact bytes. Recompute the hash of the file you received and compare it with the digest shown in Reports.</p>
              </details>
            </div>
          </Section>

          <nav className="docs-pager" aria-label="Pagination">
            {prev ? (
              <a href={`#${prev.id}`}><span><ArrowLeft className="w-3.5 h-3.5" /> Previous</span><b>{prev.title}</b></a>
            ) : <span />}
            {next && (
              <a href={`#${next.id}`} className="next"><span>Next <ArrowRight className="w-3.5 h-3.5" /></span><b>{next.title}</b></a>
            )}
          </nav>
        </main>
      </div>
    </div>
  );
}

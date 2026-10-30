import { useEffect, useRef, useState, type MouseEvent as ReactMouseEvent, type ReactNode } from "react";
import { useNavigate } from "react-router-dom";
import gsap from "gsap";
import { ScrollTrigger } from "gsap/ScrollTrigger";
import Lenis from "lenis";
import {
  Activity,
  ArrowRight,
  BookOpen,
  Check,
  CheckCircle2,
  FileText,
  Fingerprint,
  GitBranch,
  HardDrive,
  LayoutDashboard,
  Lock,
  Monitor,
  Network,
  Router,
  Server,
  Sparkles,
  Terminal,
  TriangleAlert,
  Users,
  Wrench,
} from "lucide-react";
import { Logo, LogoMark } from "../components/Logo";
import { CountUp } from "../components/reactbits/CountUp";
import { Magnet } from "../components/reactbits/Magnet";

gsap.registerPlugin(ScrollTrigger);

interface LandingProps {
  onEnterApp: () => void;
}

/* ==========================================================================
   Small building blocks
   ========================================================================== */

const heroWords = ["server", "firewall", "switch", "control"];

/** Cycles words in place; every word shares one grid cell so the layout never jumps. */
function RotatingWord({ words, interval = 2200 }: { words: string[]; interval?: number }) {
  const [index, setIndex] = useState(0);
  useEffect(() => {
    if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;
    const id = window.setInterval(() => setIndex((i) => (i + 1) % words.length), interval);
    return () => window.clearInterval(id);
  }, [words.length, interval]);
  return (
    <span className="lp-rotator" aria-live="polite">
      {words.map((w, i) => (
        <span
          key={w}
          aria-hidden={i !== index}
          className={i === index ? "is-active" : i === (index - 1 + words.length) % words.length ? "is-leaving" : ""}
        >
          {w}.
        </span>
      ))}
    </span>
  );
}

function Eyebrow({ children, tone = "light" }: { children: ReactNode; tone?: "light" | "dark" }) {
  return <span className={`lp-eyebrow ${tone === "dark" ? "on-dark" : ""}`}>{children}</span>;
}

function SectionHead({ eyebrow, title, lead }: { eyebrow: string; title: ReactNode; lead?: ReactNode }) {
  return (
    <div className="lp-section-head" data-animate>
      <Eyebrow>{eyebrow}</Eyebrow>
      <h2>{title}</h2>
      {lead && <p>{lead}</p>}
    </div>
  );
}

/** Card with a soft mint spotlight that follows the cursor. */
function GlowCard({ className = "", children }: { className?: string; children: ReactNode }) {
  const onMove = (e: ReactMouseEvent<HTMLDivElement>) => {
    const r = e.currentTarget.getBoundingClientRect();
    e.currentTarget.style.setProperty("--mx", `${e.clientX - r.left}px`);
    e.currentTarget.style.setProperty("--my", `${e.clientY - r.top}px`);
  };
  return (
    <div className={`lp-glow-card ${className}`} onMouseMove={onMove} data-animate>
      {children}
    </div>
  );
}

function Pill({ tone, children }: { tone: "pass" | "fail" | "unknown" | "error" | "manual" | "na"; children: ReactNode }) {
  return <span className={`lp-pill ${tone}`}>{children}</span>;
}

/* ==========================================================================
   Hero dashboard preview — mirrors the real console
   ========================================================================== */

const liveStages = [
  { label: "Collecting evidence…", tone: "running" },
  { label: "Evaluating 50 controls…", tone: "running" },
  { label: "48 PASS · 2 FAIL", tone: "done" },
] as const;

function DashboardPreview() {
  const [stage, setStage] = useState(0);
  useEffect(() => {
    if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
      setStage(2);
      return;
    }
    const id = window.setInterval(() => setStage((s) => (s + 1) % liveStages.length), 1900);
    return () => window.clearInterval(id);
  }, []);
  const live = liveStages[stage];

  const nav = [
    { icon: LayoutDashboard, label: "Overview", active: true },
    { icon: Server, label: "Assets" },
    { icon: Activity, label: "Assessments" },
    { icon: TriangleAlert, label: "Findings", badge: "18" },
    { icon: GitBranch, label: "Exceptions" },
    { icon: FileText, label: "Reports" },
  ];

  const severities = [
    { label: "Critical", value: 2, max: 10, color: "#B91C1C" },
    { label: "High", value: 6, max: 10, color: "#EA580C" },
    { label: "Medium", value: 8, max: 10, color: "#D97706" },
    { label: "Low", value: 2, max: 10, color: "#2563EB" },
  ];

  return (
    <div className="lp-preview-stage" data-hero-showcase>
      {/* Floating context cards */}
      <div className="lp-float lp-float-a" aria-hidden="true">
        <span className="lp-float-icon mint"><Fingerprint className="w-4 h-4" /></span>
        <div>
          <b>Host key verified</b>
          <span>fw-edge-02 · SHA256:d48e…b91a</span>
        </div>
      </div>
      <div className="lp-float lp-float-b" aria-hidden="true">
        <span className="lp-float-icon ink"><Lock className="w-4 h-4" /></span>
        <div>
          <b>Evidence sealed</b>
          <span className="font-mono">sha256:449f8a…02ff</span>
        </div>
      </div>
      <div className="lp-float lp-float-c" aria-hidden="true">
        <div className="lp-float-code">
          <span className="text-[#7CF7D4]"># Remediation ready</span>
          <span>line vty 0 4</span>
          <span>&nbsp;exec-timeout 5 0</span>
        </div>
      </div>

      <div className="lp-window" role="img" aria-label="Preview of the Bastion posture dashboard">
        <div className="lp-window-bar">
          <span className="lp-dots"><i /><i /><i /></span>
          <span className="lp-url"><Lock className="w-3 h-3" /> bastion.local/overview</span>
          <span className="w-12" />
        </div>

        <div className="lp-window-body">
          <aside className="lp-mini-side">
            <div className="lp-mini-brand"><LogoMark size={18} /> <span>bastion</span></div>
            <p>Workspace</p>
            {nav.map(({ icon: Icon, label, active, badge }) => (
              <div key={label} className={`lp-mini-nav ${active ? "active" : ""}`}>
                <Icon className="w-3.5 h-3.5" />
                <span>{label}</span>
                {badge && <em>{badge}</em>}
              </div>
            ))}
            <div className="lp-mini-status"><i /> API connected</div>
          </aside>

          <div className="lp-mini-main">
            <div className="lp-mini-head">
              <div>
                <span className="lp-mini-eyebrow">Honest scorecard</span>
                <h4>Fleet posture</h4>
              </div>
              <span className="lp-live"><i /> Live</span>
            </div>

            <div className="lp-kpis">
              <div className="lp-kpi">
                <span>Compliance</span>
                <b><CountUp to={92.4} decimals={1} suffix="%" /></b>
                <svg viewBox="0 0 80 24" className="lp-spark" aria-hidden="true">
                  <path d="M0 18 L12 16 L24 17 L36 12 L48 13 L60 8 L72 6 L80 4" />
                </svg>
              </div>
              <div className="lp-kpi">
                <span>Completeness</span>
                <b><CountUp to={98.1} decimals={1} suffix="%" /></b>
                <div className="lp-kpi-bar"><i style={{ width: "98%" }} /></div>
              </div>
              <div className="lp-kpi">
                <span>Open findings</span>
                <b><CountUp to={18} /></b>
                <em className="good">↓ 6 this week</em>
              </div>
              <div className="lp-kpi">
                <span>Assets</span>
                <b><CountUp to={42} /></b>
                <em>4 platforms</em>
              </div>
            </div>

            <div className="lp-mini-grid">
              <div className="lp-mini-card">
                <div className="lp-mini-card-head"><b>Posture over time</b><span>30 days</span></div>
                <svg viewBox="0 0 300 110" className="lp-chart" preserveAspectRatio="none" aria-hidden="true">
                  <defs>
                    <linearGradient id="lp-area" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0" stopColor="#00D4A0" stopOpacity=".28" />
                      <stop offset="1" stopColor="#00D4A0" stopOpacity="0" />
                    </linearGradient>
                  </defs>
                  {[22, 52, 82].map((y) => <line key={y} x1="0" x2="300" y1={y} y2={y} className="lp-grid-line" />)}
                  <path className="lp-area" d="M0 88 C30 84 45 80 70 74 S120 70 150 56 S210 40 240 30 S285 18 300 14 L300 110 L0 110 Z" fill="url(#lp-area)" />
                  <path className="lp-line" d="M0 88 C30 84 45 80 70 74 S120 70 150 56 S210 40 240 30 S285 18 300 14" />
                  <circle className="lp-dot" cx="300" cy="14" r="4" />
                </svg>
              </div>
              <div className="lp-mini-card">
                <div className="lp-mini-card-head"><b>Findings by severity</b><span>18 open</span></div>
                <div className="lp-sev">
                  {severities.map((s, i) => (
                    <div key={s.label} className="lp-sev-row">
                      <span>{s.label}</span>
                      <div className="lp-sev-track">
                        <i style={{ width: `${(s.value / s.max) * 100}%`, background: s.color, animationDelay: `${1.1 + i * 0.12}s` }} />
                      </div>
                      <b>{s.value}</b>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            <div className="lp-mini-card lp-runs">
              <div className="lp-mini-card-head"><b>Recent assessments</b><span>auto-refreshing</span></div>
              <div className="lp-run">
                <span className="lp-run-icon"><Router className="w-3.5 h-3.5" /></span>
                <div className="lp-run-name"><b>core-sw-01</b><span>Cisco IOS-XE</span></div>
                <span className={`lp-run-status ${live.tone}`} key={stage}>
                  {live.tone === "running" ? <i className="lp-spinner" /> : <Check className="w-3 h-3" />}
                  {live.label}
                </span>
              </div>
              <div className="lp-run">
                <span className="lp-run-icon"><Monitor className="w-3.5 h-3.5" /></span>
                <div className="lp-run-name"><b>dc-win-02</b><span>Windows Server 2022</span></div>
                <span className="lp-run-pills"><Pill tone="pass">PASS 61</Pill><Pill tone="fail">FAIL 3</Pill></span>
              </div>
              <div className="lp-run">
                <span className="lp-run-icon"><Terminal className="w-3.5 h-3.5" /></span>
                <div className="lp-run-name"><b>web-ubu-07</b><span>Ubuntu 22.04 LTS</span></div>
                <span className="lp-run-pills"><Pill tone="pass">PASS 74</Pill><Pill tone="unknown">UNKNOWN 1</Pill></span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

/* ==========================================================================
   How it works — auto-advancing steps
   ========================================================================== */

const steps = [
  {
    key: "collect",
    icon: Fingerprint,
    title: "Collect",
    text: "Agentless, read-only adapters over SSH, WinRM HTTPS and vendor APIs. Host fingerprints are verified before the first command runs.",
    code: (
      <>
        <span className="c-muted"># Transport handshake</span>
        <span className="c-ok">✓ Verified SSH fingerprint SHA256:d48e…b91a</span>
        <span><span className="c-accent">$</span> ssh audituser@10.20.1.11 'cat /etc/os-release'</span>
        <span className="c-dim">Ubuntu 22.04.4 LTS (Jammy Jellyfish)</span>
        <span className="c-ok">✓ 6 reader outputs hashed with SHA-256</span>
      </>
    ),
  },
  {
    key: "evaluate",
    icon: Sparkles,
    title: "Evaluate",
    text: "Typed rules evaluated as syntax trees with six exhaustive verdicts. The same evidence and policy give the same answer, every single run.",
    code: (
      <>
        <span className="c-muted"># Deterministic rule</span>
        <span>rule = {"{"}</span>
        <span>&nbsp;&nbsp;op: <span className="c-str">"eq"</span>,</span>
        <span>&nbsp;&nbsp;fact: <span className="c-str">"windows.registry.smbv1_disabled"</span>,</span>
        <span>&nbsp;&nbsp;value: <span className="c-accent">true</span></span>
        <span>{"}"}</span>
        <span className="c-ok">observed: true → verdict: PASS</span>
      </>
    ),
  },
  {
    key: "remediate",
    icon: Wrench,
    title: "Remediate",
    text: "Version-matched fixes with authority context, validation steps and rollback — ready for your team to review and apply.",
    code: (
      <>
        <span className="c-muted"># Remediation plan · Cisco IOS-XE</span>
        <span>configure terminal</span>
        <span>&nbsp;line vty 0 4</span>
        <span>&nbsp;&nbsp;exec-timeout <span className="c-accent">5 0</span></span>
        <span>&nbsp;exit</span>
        <span className="c-ok">✓ Idempotent · validation test included</span>
      </>
    ),
  },
];

function HowItWorks() {
  const [active, setActive] = useState(0);
  const [paused, setPaused] = useState(false);
  useEffect(() => {
    if (paused || window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;
    const id = window.setTimeout(() => setActive((a) => (a + 1) % steps.length), 6000);
    return () => window.clearTimeout(id);
  }, [active, paused]);

  return (
    <div className="lp-how" onMouseEnter={() => setPaused(true)} onMouseLeave={() => setPaused(false)}>
      <div className="lp-how-steps" role="tablist" aria-label="How Bastion works">
        {steps.map((s, i) => (
          <button
            key={s.key}
            role="tab"
            aria-selected={active === i}
            className={`lp-how-step ${active === i ? "active" : ""}`}
            onClick={() => setActive(i)}
            data-animate
          >
            <span className="lp-how-num">{String(i + 1).padStart(2, "0")}</span>
            <div>
              <b><s.icon className="w-4 h-4" /> {s.title}</b>
              <p>{s.text}</p>
            </div>
            <span className="lp-how-progress">
              <i key={`${active}-${paused}`} className={active === i && !paused ? "run" : active === i ? "full" : ""} />
            </span>
          </button>
        ))}
      </div>
      <div className="lp-code-window" data-animate>
        <div className="lp-code-bar">
          <span className="lp-dots"><i /><i /><i /></span>
          <span>{steps[active].title.toLowerCase()}.log</span>
        </div>
        <pre key={active} className="lp-code">{steps[active].code}</pre>
      </div>
    </div>
  );
}

/* ==========================================================================
   Page
   ========================================================================== */

const platforms = [
  { icon: Monitor, name: "Windows Server 2019 / 2022" },
  { icon: Monitor, name: "Windows 11" },
  { icon: Terminal, name: "Ubuntu 20.04 / 22.04 LTS" },
  { icon: Router, name: "Cisco IOS-XE routers" },
  { icon: Network, name: "Cisco Catalyst switches" },
  { icon: HardDrive, name: "Fortinet FortiGate" },
];

export default function Landing({ onEnterApp }: LandingProps) {
  const navigate = useNavigate();
  const rootRef = useRef<HTMLDivElement>(null);
  const lenisRef = useRef<Lenis | null>(null);

  const goDocs = (e?: { preventDefault: () => void }) => {
    e?.preventDefault();
    navigate("/docs");
  };
  const scrollTo = (id: string) => (e: { preventDefault: () => void }) => {
    e.preventDefault();
    const el = document.getElementById(id);
    if (!el) return;
    if (lenisRef.current) lenisRef.current.scrollTo(el, { offset: -72 });
    else el.scrollIntoView({ behavior: "smooth" });
  };

  useEffect(() => {
    if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
      rootRef.current?.classList.add("lp-reduced");
      return;
    }

    const lenis = new Lenis({ duration: 1.15, easing: (t) => Math.min(1, 1.001 - Math.pow(2, -10 * t)) });
    lenisRef.current = lenis;
    lenis.on("scroll", ScrollTrigger.update);
    const tick = (time: number) => lenis.raf(time * 1000);
    gsap.ticker.add(tick);
    gsap.ticker.lagSmoothing(0);

    const ctx = gsap.context(() => {
      gsap.to(".lp-progress", { scaleX: 1, ease: "none", scrollTrigger: { start: 0, end: "max", scrub: 0.3 } });
      ScrollTrigger.create({ start: 24, end: "max", toggleClass: { targets: ".lp-nav", className: "is-scrolled" } });

      // Hero intro
      const intro = gsap.timeline({ defaults: { ease: "power3.out" } });
      intro
        .from(".lp-hero-pill", { opacity: 0, y: 16, duration: 0.6 })
        .from(".lp-hero-title > span", { opacity: 0, y: 40, filter: "blur(8px)", duration: 1, stagger: 0.14 }, "-=0.3")
        .from(".lp-underline path", { strokeDashoffset: 400, duration: 1.1, ease: "power2.inOut" }, "-=0.4")
        .from(".lp-hero-lead, .lp-hero-ctas, .lp-hero-trust", { opacity: 0, y: 20, duration: 0.8, stagger: 0.1 }, "-=0.8")
        .from(".lp-window", { opacity: 0, y: 70, scale: 0.96, duration: 1.2 }, "-=0.6")
        .from(".lp-float", { opacity: 0, scale: 0.85, y: 20, duration: 0.8, stagger: 0.15, ease: "back.out(1.6)" }, "-=0.5");

      // Preview settles flat as it scrolls into view
      gsap.fromTo(
        ".lp-window",
        { rotateX: 10, transformPerspective: 1600, transformOrigin: "50% 0%" },
        { rotateX: 0, ease: "none", scrollTrigger: { trigger: ".lp-preview-stage", start: "top 90%", end: "top 30%", scrub: 0.6 } }
      );

      // Generic reveal: everything tagged data-animate (outside the hero) eases up in small batches
      const targets = gsap.utils.toArray<HTMLElement>("[data-animate]");
      gsap.set(targets, { opacity: 0, y: 36 });
      ScrollTrigger.batch(targets, {
        start: "top 88%",
        once: true,
        onEnter: (batch) => gsap.to(batch, { opacity: 1, y: 0, duration: 0.9, stagger: 0.09, ease: "power3.out", overwrite: true }),
      });

      // Dark panels open up like a window
      gsap.utils.toArray<HTMLElement>("[data-panel]").forEach((panel) => {
        gsap.fromTo(
          panel,
          { clipPath: "inset(6% 4% 6% 4% round 40px)" },
          { clipPath: "inset(0% 0% 0% 0% round 28px)", ease: "none", scrollTrigger: { trigger: panel, start: "top 95%", end: "top 45%", scrub: 0.6 } }
        );
      });

      // Replay grid fills dot by dot
      gsap.from(".lp-replay i", {
        scale: 0, opacity: 0, duration: 0.35, stagger: { each: 0.025, from: "start" }, ease: "back.out(2)",
        scrollTrigger: { trigger: ".lp-replay", start: "top 85%", once: true },
      });

      // Trust diagram nodes pop in
      gsap.from(".lp-node", {
        scale: 0.4, opacity: 0, duration: 0.7, stagger: 0.12, ease: "back.out(2)",
        scrollTrigger: { trigger: ".lp-diagram", start: "top 80%", once: true },
      });
    }, rootRef);

    return () => {
      ctx.revert();
      lenis.destroy();
      lenisRef.current = null;
      gsap.ticker.remove(tick);
    };
  }, []);

  return (
    <div ref={rootRef} className="lp-root">
      <div className="lp-progress" aria-hidden="true" />

      {/* ---------- Navbar ---------- */}
      <header className="lp-nav">
        <div className="lp-nav-inner">
          <a href="#top" onClick={scrollTo("top")} className="lp-nav-logo" aria-label="Bastion home">
            <Logo size={26} />
          </a>
          <nav className="lp-nav-links" aria-label="Primary">
            <a href="#features" onClick={scrollTo("features")}>Features</a>
            <a href="#how" onClick={scrollTo("how")}>How it works</a>
            <a href="#security" onClick={scrollTo("security")}>Security</a>
            <a href="/docs" onClick={goDocs}>Docs</a>
          </nav>
          <div className="lp-nav-actions">
            <button type="button" className="lp-btn ghost sm" onClick={onEnterApp}>Sign in</button>
            <button type="button" className="lp-btn primary sm" onClick={onEnterApp}>
              Open console <ArrowRight className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      </header>

      {/* ---------- Hero ---------- */}
      <section id="top" className="lp-hero">
        <div className="lp-hero-bg" aria-hidden="true">
          <div className="lp-aurora a" />
          <div className="lp-aurora b" />
          <div className="lp-aurora c" />
          <div className="lp-grid" />
        </div>

        <div className="lp-hero-copy">
          <a href="#how" onClick={scrollTo("how")} className="lp-hero-pill">
            <span className="lp-pill-new">New</span>
            Live audits for Cisco, FortiGate, Windows &amp; Linux
            <ArrowRight className="w-3.5 h-3.5" />
          </a>

          <h1 className="lp-hero-title">
            <span>Every <RotatingWord words={heroWords} /></span>
            <span className="lp-verified">
              Verified.
              <svg className="lp-underline" viewBox="0 0 300 20" preserveAspectRatio="none" aria-hidden="true">
                <path d="M4 14 C 60 4, 140 4, 200 10 S 280 16, 296 6" />
              </svg>
            </span>
          </h1>

          <p className="lp-hero-lead">
            Bastion collects real configuration evidence from your servers, firewalls and switches,
            evaluates it against versioned policies, and shows exactly what passed, what failed,
            and what it couldn’t verify.
          </p>

          <div className="lp-hero-ctas">
            <Magnet strength={0.2}>
              <button type="button" className="lp-btn primary lg" onClick={onEnterApp}>
                Open the console <ArrowRight className="w-4 h-4" />
              </button>
            </Magnet>
            <button type="button" className="lp-btn secondary lg" onClick={() => goDocs()}>
              <BookOpen className="w-4 h-4" /> Read the docs
            </button>
          </div>

          <div className="lp-hero-trust">
            <span><Check className="w-3.5 h-3.5" /> Self-hosted</span>
            <span><Check className="w-3.5 h-3.5" /> Works offline</span>
            <span><Check className="w-3.5 h-3.5" /> Read-only by design</span>
          </div>
        </div>

        <DashboardPreview />
      </section>

      {/* ---------- Platforms ---------- */}
      <section className="lp-platforms" aria-label="Supported platforms">
        <p>Audits the infrastructure you actually run</p>
        <div className="lp-marquee">
          <div className="lp-marquee-track">
            {[...platforms, ...platforms].map((p, i) => (
              <span key={i} className="lp-marquee-item" aria-hidden={i >= platforms.length}>
                <p.icon className="w-4 h-4" /> {p.name}
              </span>
            ))}
          </div>
        </div>
      </section>

      {/* ---------- Why Bastion (bento) ---------- */}
      <section id="features" className="lp-section">
        <SectionHead
          eyebrow="Why Bastion"
          title={<>Engineered for defensibility,<br className="hidden md:block" /> not guesswork.</>}
          lead="In compliance, a result is only as good as the proof behind it. Bastion gives you proof for every verdict."
        />

        <div className="lp-bento">
          <GlowCard className="span-2">
            <div className="lp-card-copy">
              <span className="lp-card-icon mint"><CheckCircle2 className="w-5 h-5" /></span>
              <h3>A defensible answer.</h3>
              <p>Every result shows the expected value, the observed value and the exact configuration line it came from.</p>
            </div>
            <div className="lp-visual lp-diff">
              <div className="lp-diff-head">
                <span>CIS Cisco IOS 1.1.2 — Exec Timeout</span>
                <Pill tone="fail">FAIL</Pill>
              </div>
              <div className="lp-diff-rows">
                <div><span>Expected</span><code className="ok">≤ 300 seconds</code></div>
                <div><span>Observed</span><code className="bad">0 (disabled)</code></div>
                <div><span>Evidence</span><code>running-config · line 42–45</code></div>
              </div>
            </div>
          </GlowCard>

          <GlowCard>
            <div className="lp-card-copy">
              <span className="lp-card-icon peach"><TriangleAlert className="w-5 h-5" /></span>
              <h3>No false greens.</h3>
              <p>Missing data never becomes a pass. Uncertainty is reported clearly.</p>
            </div>
            <div className="lp-visual lp-verdict-cloud">
              <Pill tone="pass">PASS</Pill>
              <Pill tone="fail">FAIL</Pill>
              <Pill tone="unknown">UNKNOWN</Pill>
              <Pill tone="error">ERROR</Pill>
              <Pill tone="manual">MANUAL</Pill>
              <Pill tone="na">N/A</Pill>
            </div>
          </GlowCard>

          <GlowCard>
            <div className="lp-card-copy">
              <span className="lp-card-icon lavender"><Activity className="w-5 h-5" /></span>
              <h3>Deterministic by design.</h3>
              <p>Same evidence, same policy, same verdict — across every replay.</p>
            </div>
            <div className="lp-visual lp-replay-wrap">
              <div className="lp-replay" aria-hidden="true">
                {Array.from({ length: 40 }, (_, i) => <i key={i} />)}
              </div>
              <span className="lp-replay-label"><b>100 / 100</b> identical replays</span>
            </div>
          </GlowCard>

          <GlowCard className="span-2">
            <div className="lp-card-copy">
              <span className="lp-card-icon ink"><Lock className="w-5 h-5" /></span>
              <h3>Self-hosted and offline-capable.</h3>
              <p>Your configurations never leave your network. Bastion runs on private infrastructure with zero external telemetry.</p>
            </div>
            <div className="lp-visual lp-boundary">
              <span className="lp-boundary-label">Your network</span>
              <div className="lp-boundary-row">
                <span className="lp-chip"><Server className="w-3.5 h-3.5" /> Servers</span>
                <span className="lp-flow" />
                <span className="lp-chip core"><LogoMark size={16} inverted /> Bastion</span>
                <span className="lp-flow reverse" />
                <span className="lp-chip"><Network className="w-3.5 h-3.5" /> Switches</span>
              </div>
              <span className="lp-egress"><Check className="w-3 h-3" /> 0 bytes egress</span>
            </div>
          </GlowCard>
        </div>
      </section>

      {/* ---------- How it works ---------- */}
      <section id="how" className="lp-section lp-tint">
        <SectionHead
          eyebrow="How it works"
          title="From raw config to reviewed fix."
          lead="Three steps, fully traceable. Hover to pause, click to explore."
        />
        <HowItWorks />
      </section>

      {/* ---------- Audit lifecycle ---------- */}
      <section className="lp-section">
        <SectionHead eyebrow="Lifecycle" title="Everything an audit needs." />
        <div className="lp-feature-grid">
          {[
            {
              icon: Lock, tone: "mint", title: "Hash-chained evidence",
              text: "Evidence is redacted, canonicalised and sealed into a SHA-256 chain so history can’t be rewritten.",
              meta: <><span>Status</span><b className="text-[#07684D]">STORED_SEALED</b></>,
            },
            {
              icon: GitBranch, tone: "peach", title: "Policy impact preview",
              text: "See exactly which assets and controls a policy change affects — before anything is published.",
              meta: <><span>Hardening v2.4</span><b>4 assets in scope</b></>,
            },
            {
              icon: Users, tone: "lavender", title: "Dual-custody exceptions",
              text: "Time-boxed risk acceptances with compensating controls, approved by a second person.",
              meta: <><span>rowan.diaz</span><b className="text-[#07684D]">Approved · 58 days</b></>,
            },
            {
              icon: FileText, tone: "ink", title: "Frozen reports",
              text: "Signed exports for every audience: PDF for executives, JSON for SIEMs, CSV and offline HTML.",
              meta: <><span>Formats</span><b>PDF · JSON · CSV · HTML</b></>,
            },
          ].map((f) => (
            <GlowCard key={f.title} className="lp-feature">
              <span className={`lp-card-icon ${f.tone}`}><f.icon className="w-5 h-5" /></span>
              <h3>{f.title}</h3>
              <p>{f.text}</p>
              <div className="lp-feature-meta">{f.meta}</div>
            </GlowCard>
          ))}
        </div>
      </section>

      {/* ---------- Trust panel ---------- */}
      <section id="security" className="lp-section">
        <div className="lp-dark-panel" data-panel>
          <div className="lp-dark-grid">
            <div data-animate>
              <Eyebrow tone="dark">Built to be trusted</Eyebrow>
              <h2>Forensic-grade evidence,<br />from the first byte.</h2>
              <p className="lp-dark-lead">
                Bastion is engineered to withstand formal audit scrutiny — every verdict is reproducible,
                every artifact is sealed, and every action is accountable.
              </p>
              <ul className="lp-checks">
                <li><Check className="w-3.5 h-3.5" /> Evidence replay from immutable, signed verification bundles</li>
                <li><Check className="w-3.5 h-3.5" /> Tamper-evident SHA-256 hash chains with database-level isolation</li>
                <li><Check className="w-3.5 h-3.5" /> Role-based access control with mandatory MFA</li>
                <li><Check className="w-3.5 h-3.5" /> Runs fully air-gapped with zero external callbacks</li>
              </ul>
            </div>

            <div className="lp-diagram" aria-hidden="true">
              <svg viewBox="0 0 340 340" className="lp-diagram-svg">
                <circle cx="170" cy="170" r="140" className="lp-orbit" />
                <circle cx="170" cy="170" r="92" className="lp-orbit inner" />
                {[
                  "M170 30 L170 170",
                  "M310 170 L170 170",
                  "M170 310 L170 170",
                  "M30 170 L170 170",
                ].map((d, i) => (
                  <g key={d}>
                    <path d={d} className="lp-spoke" />
                    <circle r="3.5" className="lp-packet">
                      <animateMotion dur="2.4s" begin={`${i * 0.6}s`} repeatCount="indefinite" path={d} />
                    </circle>
                  </g>
                ))}
              </svg>
              <div className="lp-core"><LogoMark size={34} inverted /><span>BASTION</span></div>
              <span className="lp-node" style={{ top: 0, left: "50%" }} title="Linux"><Terminal className="w-5 h-5" /></span>
              <span className="lp-node" style={{ top: "50%", left: "100%" }} title="Cisco"><Network className="w-5 h-5" /></span>
              <span className="lp-node" style={{ top: "100%", left: "50%" }} title="Firewalls"><HardDrive className="w-5 h-5" /></span>
              <span className="lp-node" style={{ top: "50%", left: 0 }} title="Windows"><Monitor className="w-5 h-5" /></span>
            </div>
          </div>
        </div>
      </section>

      {/* ---------- Stakeholders ---------- */}
      <section className="lp-section">
        <SectionHead eyebrow="Collaboration" title="Built for every stakeholder." />
        <div className="lp-roles">
          {[
            {
              tag: "Security analysts", tone: "mint", title: "Prioritised worklists",
              text: "Explainable findings with exact failure causes and severity scoring — easy to defend in any meeting.",
            },
            {
              tag: "System & network admins", tone: "peach", title: "Authority-aware fixes",
              text: "Know where each fix belongs: Group Policy, local policy, Panorama or Ansible — so changes stick.",
            },
            {
              tag: "Compliance auditors", tone: "lavender", title: "Reproducible reports",
              text: "Signed reports and dual-custody exception logs, ready for SOC 2, ISO 27001 and PCI-DSS reviews.",
            },
          ].map((r) => (
            <div key={r.title} className="lp-role" data-animate>
              <span className={`lp-role-tag ${r.tone}`}>{r.tag}</span>
              <h3>{r.title}</h3>
              <p>{r.text}</p>
            </div>
          ))}
        </div>

        <div className="lp-stats" data-animate>
          <div><b><CountUp to={100} suffix="/100" /></b><span>Identical replays</span></div>
          <div><b><CountUp to={6} /></b><span>Exhaustive verdict types</span></div>
          <div><b><CountUp to={4} /></b><span>Export formats</span></div>
          <div><b>&lt; <CountUp to={4} suffix="s" /></b><span>Average audit time</span></div>
        </div>
      </section>

      {/* ---------- Final CTA ---------- */}
      <section className="lp-section">
        <div className="lp-cta" data-panel>
          <div className="lp-cta-glow" aria-hidden="true" />
          <div className="lp-cta-inner" data-animate>
            <LogoMark size={44} inverted />
            <h2>Every control. <span>Verified.</span></h2>
            <p>Deploy Bastion inside your network in minutes and verify your baseline without a single byte leaving your firewall.</p>
            <div className="lp-cta-actions">
              <Magnet strength={0.25}>
                <button type="button" className="lp-btn primary lg" onClick={onEnterApp}>
                  Open the console <ArrowRight className="w-4 h-4" />
                </button>
              </Magnet>
              <button type="button" className="lp-btn on-dark lg" onClick={() => goDocs()}>
                <BookOpen className="w-4 h-4" /> Read the docs
              </button>
            </div>
          </div>
        </div>
      </section>

      {/* ---------- Footer ---------- */}
      <footer className="lp-footer">
        <div className="lp-footer-inner">
          <div className="lp-footer-brand">
            <Logo size={24} />
            <p>Self-hosted compliance and hardening auditor. Deterministic evaluation with cryptographic proof.</p>
          </div>
          <div className="lp-footer-cols">
            <div>
              <b>Product</b>
              <a href="#features" onClick={scrollTo("features")}>Features</a>
              <a href="#how" onClick={scrollTo("how")}>How it works</a>
              <a href="#security" onClick={scrollTo("security")}>Security</a>
            </div>
            <div>
              <b>Resources</b>
              <a href="/docs" onClick={goDocs}>Documentation</a>
              <a href="/login" onClick={(e) => { e.preventDefault(); onEnterApp(); }}>Sign in</a>
            </div>
            <div>
              <b>Platforms</b>
              <span>Windows &amp; Linux</span>
              <span>Cisco IOS-XE routers &amp; switches</span>
              <span>Fortinet FortiGate</span>
            </div>
          </div>
        </div>
        <div className="lp-footer-bottom">
          <span>© 2026 Bastion. All rights reserved.</span>
          <span>Every control. Verified.</span>
        </div>
      </footer>
    </div>
  );
}

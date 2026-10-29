import { createContext, useCallback, useContext, useEffect, useId, useRef, useState, type ReactNode } from "react";
import { createPortal } from "react-dom";
import { ApiError } from "../lib/api";
import { label } from "../lib/format";

/* ---------- icons (inline, stroke-based) ---------- */
const paths: Record<string, string> = {
  overview: "M3 13h8V3H3zM13 21h8v-8h-8zM13 3v6h8V3zM3 21h8v-6H3z",
  assets: "M4 6h16M4 12h16M4 18h16M7 6v.01M7 12v.01M7 18v.01",
  scans: "M12 3v4M12 17v4M3 12h4M17 12h4M5.6 5.6l2.8 2.8M15.6 15.6l2.8 2.8M18.4 5.6l-2.8 2.8M8.4 15.6l-2.8 2.8",
  findings: "M12 3 3 20h18zM12 10v4M12 17v.01",
  exceptions: "M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6zM9 12l2 2 4-4",
  reports: "M7 3h8l4 4v14H7zM14 3v5h5M10 13h6M10 17h6",
  policies: "M5 4h14v16H5zM9 8h6M9 12h6M9 16h3",
  shield: "M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z",
  lock: "M6 11h12v9H6zM8 11V8a4 4 0 0 1 8 0v3",
  eye: "M2 12s4-7 10-7 10 7 10 7-4 7-10 7S2 12 2 12zM12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6z",
  check: "M5 12l5 5 9-10",
  x: "M6 6l12 12M18 6 6 18",
  copy: "M9 9h11v11H9zM5 15H4V4h11v1",
  download: "M12 3v12M7 10l5 5 5-5M5 21h14",
  upload: "M12 16V4M7 9l5-5 5 5M5 20h14",
  sun: "M12 17a5 5 0 1 0 0-10 5 5 0 0 0 0 10zM12 1v2M12 21v2M4.2 4.2l1.4 1.4M18.4 18.4l1.4 1.4M1 12h2M21 12h2M4.2 19.8l1.4-1.4M18.4 5.6l1.4-1.4",
  moon: "M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z",
  plus: "M12 5v14M5 12h14",
  clock: "M12 7v5l3 2M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18z",
  inbox: "M3 13l3-8h12l3 8v6H3zM3 13h5l1 3h6l1-3h5",
};

export function Icon({ name }: { name: keyof typeof paths | string }) {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d={paths[name] ?? paths.shield} />
    </svg>
  );
}

/* ---------- chips ---------- */
export function Chip({ tone, children, icon }: { tone: string; children?: ReactNode; icon?: string }) {
  return <span className={`chip ${tone}`}>{icon && <Icon name={icon} />}{children ?? label(tone)}</span>;
}

export function SeverityChip({ severity }: { severity: string }) {
  return <Chip tone={severity}>{label(severity)}</Chip>;
}

export function StateChip({ state }: { state: string }) {
  const icon = state === "RESOLVED" || state === "COMPLETED" || state === "APPROVED" ? "check" : state === "OPEN" || state === "FAILED" ? "x" : "clock";
  return <Chip tone={state} icon={icon}>{label(state)}</Chip>;
}

/* ---------- charts ---------- */
export function Ring({ value, caption }: { value: number | null; caption: string }) {
  const id = useId();
  const radius = 70;
  const circumference = 2 * Math.PI * radius;
  const shown = value ?? 0;
  const tone = value === null ? "muted" : value >= 85 ? "#34d399" : value >= 60 ? "#fbbf24" : "#ff5d73";
  return (
    <div className="ring" role="img" aria-label={value === null ? `${caption}: not measured` : `${caption}: ${value.toFixed(0)} percent`}>
      <svg viewBox="0 0 168 168">
        <defs>
          <linearGradient id={id} x1="0" y1="0" x2="1" y2="1"><stop offset="0%" stopColor="#5eead4" /><stop offset="100%" stopColor={tone === "muted" ? "#818cf8" : tone} /></linearGradient>
        </defs>
        <circle className="ring-track" cx="84" cy="84" r={radius} fill="none" strokeWidth="13" />
        <circle cx="84" cy="84" r={radius} fill="none" stroke={`url(#${id})`} strokeWidth="13" strokeLinecap="round"
          strokeDasharray={circumference} strokeDashoffset={circumference * (1 - shown / 100)} style={{ transition: "stroke-dashoffset 1s cubic-bezier(.2,.8,.2,1)" }} />
      </svg>
      <div className="ring-value"><b>{value === null ? "—" : `${value.toFixed(0)}%`}</b><span>{caption}</span></div>
    </div>
  );
}

export function Meter({ label: text, value, tone }: { label: string; value: number | null; tone?: "pass" | "warn" | "fail" }) {
  return (
    <div className="meter">
      <div className="meter-top"><span>{text}</span><b>{value === null ? "—" : `${value.toFixed(0)}%`}</b></div>
      <div className={`bar ${tone ? `tone-${tone}` : ""}`}><i style={{ width: `${value ?? 0}%` }} /></div>
    </div>
  );
}

export function Trend({ points }: { points: Array<number | null> }) {
  const id = useId();
  const data = points.map((p) => p ?? 0);
  if (data.length < 2) return <p className="quiet">Trend appears after two or more assessments.</p>;
  const w = 480, h = 120, pad = 8;
  const lo = Math.max(0, Math.min(...data) - 10), hi = Math.min(100, Math.max(...data) + 10);
  const x = (i: number) => pad + (i * (w - pad * 2)) / (data.length - 1);
  const y = (v: number) => h - pad - ((v - lo) / Math.max(1, hi - lo)) * (h - pad * 2);
  const line = data.map((v, i) => `${i === 0 ? "M" : "L"}${x(i).toFixed(1)},${y(v).toFixed(1)}`).join(" ");
  const area = `${line} L${x(data.length - 1)},${h} L${x(0)},${h} Z`;
  return (
    <svg className="trend" viewBox={`0 0 ${w} ${h}`} preserveAspectRatio="none" role="img" aria-label={`Compliance trend from ${data[0]!.toFixed(0)} to ${data.at(-1)!.toFixed(0)} percent`}>
      <defs>
        <linearGradient id={`${id}-fill`} x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#5eead4" stopOpacity=".35" /><stop offset="100%" stopColor="#5eead4" stopOpacity="0" /></linearGradient>
        <linearGradient id="trend-grad" x1="0" y1="0" x2="1" y2="0"><stop offset="0%" stopColor="#5eead4" /><stop offset="100%" stopColor="#818cf8" /></linearGradient>
      </defs>
      <path d={area} fill={`url(#${id}-fill)`} />
      <path className="line" d={line} vectorEffect="non-scaling-stroke" />
      <circle cx={x(data.length - 1)} cy={y(data.at(-1)!)} r="4" fill="#5eead4" />
    </svg>
  );
}

export function Stacked({ parts }: { parts: Array<{ label: string; value: number; color: string }> }) {
  const total = parts.reduce((sum, p) => sum + p.value, 0);
  return (
    <div>
      <div className="stacked" role="img" aria-label={parts.map((p) => `${p.value} ${p.label}`).join(", ")}>
        {total === 0 ? null : parts.filter((p) => p.value > 0).map((p) => <i key={p.label} style={{ width: `${(p.value / total) * 100}%`, background: p.color }} />)}
      </div>
      <div className="legend">{parts.map((p) => <span key={p.label}><i style={{ background: p.color }} />{p.label} <b>{p.value}</b></span>)}</div>
    </div>
  );
}

/* ---------- states ---------- */
export function Empty({ icon = "inbox", title, children }: { icon?: string; title: string; children?: ReactNode }) {
  return <div className="empty"><Icon name={icon} /><h3>{title}</h3>{children && <p>{children}</p>}</div>;
}

export function Skeleton({ rows = 4 }: { rows?: number }) {
  return <div role="status" aria-label="Loading" style={{ display: "grid", gap: 12 }}>{Array.from({ length: rows }, (_, i) => <div key={i} className="skeleton" style={{ width: `${95 - i * 9}%` }} />)}</div>;
}

export function ErrorNotice({ error }: { error: unknown }) {
  const message = error instanceof Error ? error.message : "Something went wrong.";
  return (
    <div className="notice error" role="alert">
      <div><strong>The request could not be completed</strong>{message}{error instanceof ApiError && <div className="quiet">Reference: {error.requestId}</div>}</div>
    </div>
  );
}

export function PageHeading({ title, description, actions }: { title: string; description: string; actions?: ReactNode }) {
  return (
    <div className="page-heading">
      <div><p className="eyebrow">BaselineGuard</p><h1>{title}</h1><p className="page-description">{description}</p></div>
      {actions && <div className="top-actions">{actions}</div>}
    </div>
  );
}

/* ---------- drawer ---------- */
export function Drawer({ title, onClose, children, meta }: { title: string; onClose: () => void; children: ReactNode; meta?: ReactNode }) {
  const closeRef = useRef<HTMLButtonElement>(null);
  useEffect(() => {
    const previous = document.activeElement as HTMLElement | null;
    closeRef.current?.focus();
    const onKey = (event: KeyboardEvent) => { if (event.key === "Escape") onClose(); };
    document.addEventListener("keydown", onKey);
    return () => { document.removeEventListener("keydown", onKey); previous?.focus(); };
  }, [onClose]);
  return createPortal(
    <>
      <div className="scrim" onClick={onClose} />
      <aside className="drawer" role="dialog" aria-modal="true" aria-label={title}>
        <header className="drawer-head">
          <div style={{ display: "grid", gap: 10 }}>{meta}<h2>{title}</h2></div>
          <button ref={closeRef} className="btn icon-btn" onClick={onClose} aria-label="Close details"><Icon name="x" /></button>
        </header>
        <div className="drawer-body">{children}</div>
      </aside>
    </>,
    document.body,
  );
}

/* ---------- copyable command ---------- */
export function CodeBlock({ lines }: { lines: string[] }) {
  const [copied, setCopied] = useState(false);
  const text = lines.join("\n");
  return (
    <div className="codeblock">
      <button className="btn sm copy" onClick={() => { void navigator.clipboard?.writeText(text); setCopied(true); setTimeout(() => setCopied(false), 1500); }} aria-label="Copy commands">
        <Icon name={copied ? "check" : "copy"} />{copied ? "Copied" : "Copy"}
      </button>
      <pre>{lines.map((line, i) => <div key={i}><span className="prompt">$ </span>{line}</div>)}</pre>
    </div>
  );
}

/* ---------- toasts ---------- */
interface Toast { id: number; kind: "ok" | "err"; text: string }
const ToastContext = createContext<(kind: Toast["kind"], text: string) => void>(() => undefined);
export const useToast = () => useContext(ToastContext);

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);
  const push = useCallback((kind: Toast["kind"], text: string) => {
    const id = Date.now() + Math.random();
    setToasts((current) => [...current, { id, kind, text }]);
    setTimeout(() => setToasts((current) => current.filter((t) => t.id !== id)), 4200);
  }, []);
  return (
    <ToastContext.Provider value={push}>
      {children}
      <div className="toasts" role="status" aria-live="polite">{toasts.map((t) => <div key={t.id} className={`toast ${t.kind}`}>{t.text}</div>)}</div>
    </ToastContext.Provider>
  );
}

import { useEffect, useRef, useState, type ClipboardEvent, type FormEvent, type KeyboardEvent } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ArrowLeft, ArrowRight, Building2, Eye, EyeOff, KeyRound, Lock, ShieldCheck, User, Zap } from "lucide-react";
import { apiGet, apiWrite, setCsrfToken } from "./lib/api";
import { Logo, LogoMark } from "./components/Logo";

/* ---------- live audit stream shown on the brand panel ---------- */

const streamLines = [
  { tone: "muted", text: "$ bastion assess --site hq" },
  { tone: "ok", text: "✓ fw-edge-02   host key verified" },
  { tone: "ok", text: "✓ core-sw-01   48 PASS · 2 FAIL" },
  { tone: "ok", text: "✓ dc-win-02    evidence sealed sha256:449f…02ff" },
  { tone: "ok", text: "✓ web-ubu-07   74 PASS · 1 UNKNOWN" },
  { tone: "accent", text: "→ chain intact · 42 assets verified" },
];

function AuditStream() {
  const [count, setCount] = useState(1);
  useEffect(() => {
    if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
      setCount(streamLines.length);
      return;
    }
    const id = window.setInterval(() => setCount((c) => (c >= streamLines.length + 3 ? 1 : c + 1)), 900);
    return () => window.clearInterval(id);
  }, []);
  return (
    <div className="si-stream" aria-hidden="true">
      <div className="si-stream-bar"><span className="lp-dots"><i /><i /><i /></span><span>audit.log</span></div>
      <div className="si-stream-body">
        {streamLines.slice(0, Math.min(count, streamLines.length)).map((l, i) => (
          <span key={i} className={`si-line ${l.tone}`}>{l.text}</span>
        ))}
        <span className="si-caret" />
      </div>
    </div>
  );
}

/* ---------- six-box one-time code input ---------- */

function CodeInput({ length = 6, disabled, fill, onComplete }: { length?: number; disabled?: boolean; fill?: string; onComplete: (code: string) => void }) {
  const [digits, setDigits] = useState<string[]>(() => Array(length).fill(""));
  const refs = useRef<(HTMLInputElement | null)[]>([]);
  const completeRef = useRef(onComplete);
  completeRef.current = onComplete;

  useEffect(() => { refs.current[0]?.focus(); }, []);

  // Demo auto-fill: type the supplied code digit by digit so the audience sees it, then submit
  useEffect(() => {
    if (!fill || fill.length !== length) return;
    const timers = fill.split("").map((_, i) =>
      window.setTimeout(() => {
        setDigits(Array.from({ length }, (_, j) => (j <= i ? fill[j] : "")));
        refs.current[Math.min(i + 1, length - 1)]?.focus();
        if (i === length - 1) completeRef.current(fill);
      }, 110 * (i + 1))
    );
    return () => timers.forEach((t) => window.clearTimeout(t));
  }, [fill, length]);

  const update = (next: string[]) => {
    setDigits(next);
    if (next.every((d) => d !== "")) onComplete(next.join(""));
  };
  const onChange = (i: number, value: string) => {
    const d = value.replace(/\D/g, "").slice(-1);
    const next = [...digits];
    next[i] = d;
    update(next);
    if (d && i < length - 1) refs.current[i + 1]?.focus();
  };
  const onKeyDown = (i: number, e: KeyboardEvent<HTMLInputElement>) => {
    if (e.key === "Backspace" && !digits[i] && i > 0) refs.current[i - 1]?.focus();
    if (e.key === "ArrowLeft" && i > 0) refs.current[i - 1]?.focus();
    if (e.key === "ArrowRight" && i < length - 1) refs.current[i + 1]?.focus();
  };
  const onPaste = (e: ClipboardEvent<HTMLInputElement>) => {
    const pasted = e.clipboardData.getData("text").replace(/\D/g, "").slice(0, length);
    if (!pasted) return;
    e.preventDefault();
    const next = Array.from({ length }, (_, i) => pasted[i] ?? "");
    update(next);
    refs.current[Math.min(pasted.length, length - 1)]?.focus();
  };

  return (
    <div className="si-otp" role="group" aria-label="Six-digit authenticator code">
      {digits.map((d, i) => (
        <input
          key={i}
          ref={(el) => { refs.current[i] = el; }}
          value={d}
          onChange={(e) => onChange(i, e.target.value)}
          onKeyDown={(e) => onKeyDown(i, e)}
          onPaste={onPaste}
          inputMode="numeric"
          autoComplete={i === 0 ? "one-time-code" : "off"}
          maxLength={1}
          disabled={disabled}
          aria-label={`Digit ${i + 1}`}
          className={d ? "filled" : ""}
        />
      ))}
    </div>
  );
}

/* ---------- sign-in panel ---------- */

const demoAccounts = [
  { username: "ava", name: "Ava", role: "Admin & auditor" },
  { username: "rowan", name: "Rowan", role: "Risk approver" },
];

export function SignInPanel({ onBackToLanding }: { onBackToLanding?: () => void }) {
  const cache = useQueryClient();
  const [challenge, setChallenge] = useState<string | null>(null);
  const [recovery, setRecovery] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  const [attempt, setAttempt] = useState(0);
  const [demoCode, setDemoCode] = useState<string | undefined>();
  const [creds, setCreds] = useState({ organization: "northwind", username: "ava", password: "BaselineGuard-Demo-2026" });

  const options = useQuery({
    queryKey: ["auth-options"],
    queryFn: ({ signal }) => apiGet<{ demo_login: boolean }>("/api/v1/auth/options", signal),
    retry: 0,
    staleTime: 60_000,
  });
  const demoEnabled = options.data?.demo_login === true;

  const finish = async (data: { csrf_token: string }) => {
    setCsrfToken(data.csrf_token);
    await cache.invalidateQueries();
  };
  const login = useMutation({
    mutationFn: (body: typeof creds) => apiWrite<{ challenge: string }>("/api/v1/auth/login", body),
    onSuccess: (data) => setChallenge(data.challenge),
  });
  const verify = useMutation({
    mutationFn: (body: { challenge: string; code?: string; recovery_code?: string }) =>
      apiWrite<{ csrf_token: string }>("/api/v1/auth/mfa/verify", body),
    onSuccess: finish,
    onError: () => { setAttempt((a) => a + 1); setDemoCode(undefined); },
  });
  const demo = useMutation({
    mutationFn: (body: typeof creds) => apiWrite<{ csrf_token: string }>("/api/v1/auth/demo-login", body),
    onSuccess: finish,
  });

  const fillCode = useMutation({
    mutationFn: (body: { challenge: string }) => apiWrite<{ code: string }>("/api/v1/auth/demo-code", body),
    onSuccess: (data) => setDemoCode(data.code),
  });

  const busy = login.isPending || verify.isPending || demo.isPending || fillCode.isPending;
  const error = demo.error ?? fillCode.error ?? (challenge ? verify.error : login.error);

  function submitCredentials(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    demo.reset();
    login.mutate(creds);
  }
  function submitRecovery(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const code = String(new FormData(event.currentTarget).get("code") ?? "");
    if (challenge) verify.mutate({ challenge, recovery_code: code });
  }
  function startAgain() {
    setChallenge(null);
    setRecovery(false);
    setDemoCode(undefined);
    fillCode.reset();
    verify.reset();
    login.reset();
  }
  function demoSignIn(username: string) {
    login.reset();
    const body = { ...creds, username };
    setCreds(body);
    demo.mutate(body);
  }

  return (
    <div className="si-root">
      <a className="skip-link" href="#signin-form">Skip to sign in</a>

      {/* ---------- brand panel ---------- */}
      <section className="si-brand" aria-labelledby="si-brand-title">
        <div className="si-aurora a" aria-hidden="true" />
        <div className="si-aurora b" aria-hidden="true" />
        <div className="si-grid" aria-hidden="true" />

        <div className="si-brand-top">
          <Logo size={28} inverted />
        </div>

        <div className="si-brand-mid">
          <h1 id="si-brand-title">
            Proof for every control,<br /><span>in one place.</span>
          </h1>
          <p>Sign in to review evidence, resolve findings and export signed reports for your fleet.</p>
          <AuditStream />
        </div>

        <ul className="si-brand-points">
          <li><ShieldCheck className="w-4 h-4" /> Deterministic verdicts</li>
          <li><Lock className="w-4 h-4" /> Hash-chained evidence</li>
          <li><KeyRound className="w-4 h-4" /> MFA &amp; role-based access</li>
        </ul>
      </section>

      {/* ---------- form panel ---------- */}
      <section className="si-form-side">
        {onBackToLanding && (
          <button type="button" className="si-back" onClick={onBackToLanding}>
            <ArrowLeft className="w-4 h-4" /> Back to home
          </button>
        )}

        <div className="si-card" aria-busy={busy}>
          <div className="si-mark"><LogoMark size={40} /></div>

          <ol className="si-steps" aria-label="Sign-in progress">
            <li className={challenge ? "done" : "current"}><span>1</span> Credentials</li>
            <li className="si-step-line" aria-hidden="true" />
            <li className={challenge ? "current" : ""}><span>2</span> Verify</li>
          </ol>

          {!challenge ? (
            <form id="signin-form" onSubmit={submitCredentials} className="si-form" key="credentials">
              <div className="si-head">
                <h2>Welcome back</h2>
                <p>Sign in to your Bastion workspace.</p>
              </div>

              <label className="si-field">
                <span>Organization</span>
                <div className="si-input">
                  <Building2 className="w-4 h-4" />
                  <input name="organization" value={creds.organization} onChange={(e) => setCreds({ ...creds, organization: e.target.value })}
                    required maxLength={100} pattern="[a-z0-9\-]+" autoComplete="organization" placeholder="northwind" disabled={busy} />
                </div>
              </label>
              <label className="si-field">
                <span>Username</span>
                <div className="si-input">
                  <User className="w-4 h-4" />
                  <input name="username" value={creds.username} onChange={(e) => setCreds({ ...creds, username: e.target.value })}
                    autoComplete="username" required maxLength={255} placeholder="ava" disabled={busy} />
                </div>
              </label>
              <label className="si-field">
                <span>Password</span>
                <div className="si-input">
                  <Lock className="w-4 h-4" />
                  <input name="password" value={creds.password} onChange={(e) => setCreds({ ...creds, password: e.target.value })}
                    type={showPassword ? "text" : "password"} autoComplete="current-password" required maxLength={1024} disabled={busy} />
                  <button type="button" className="si-eye" onClick={() => setShowPassword((v) => !v)} aria-label={showPassword ? "Hide password" : "Show password"}>
                    {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                  </button>
                </div>
              </label>

              {error && <p className="si-error" role="alert">{error.message}</p>}

              <button className="lp-btn primary lg si-submit" type="submit" disabled={busy}>
                {login.isPending ? <><i className="si-spin" /> Checking…</> : <>Continue <ArrowRight className="w-4 h-4" /></>}
              </button>

              {demoEnabled && (
                <div className="si-demo">
                  <div className="si-divider"><span>Quick demo access</span></div>
                  <div className="si-demo-grid">
                    {demoAccounts.map((a) => (
                      <button key={a.username} type="button" className="si-demo-btn" onClick={() => demoSignIn(a.username)} disabled={busy}>
                        <span className="si-avatar">{a.name[0]}</span>
                        <span className="si-demo-text"><b>{a.name}</b><small>{a.role}</small></span>
                        {demo.isPending && creds.username === a.username ? <i className="si-spin dark" /> : <Zap className="w-4 h-4" />}
                      </button>
                    ))}
                  </div>
                  <p className="si-note">Demo mode skips MFA. Every demo sign-in is recorded in the audit log.</p>
                </div>
              )}
            </form>
          ) : (
            <div className="si-form" key="verify">
              <div className="si-head">
                <h2>{recovery ? "Use a recovery code" : "Verify it’s you"}</h2>
                <p>
                  {recovery
                    ? "Enter one unused 20-character recovery code. It is consumed when you sign in."
                    : <>Enter the 6-digit code from your authenticator app for <b>{creds.username}</b>.</>}
                </p>
              </div>

              {recovery ? (
                <form id="signin-form" onSubmit={submitRecovery} className="si-form">
                  <label className="si-field">
                    <span>Recovery code</span>
                    <div className="si-input">
                      <KeyRound className="w-4 h-4" />
                      <input name="code" required minLength={20} maxLength={20} pattern="[A-Fa-f0-9]{20}" autoComplete="one-time-code"
                        autoFocus disabled={busy} className="font-mono" placeholder="20 hex characters" />
                    </div>
                  </label>
                  {error && <p className="si-error" role="alert">{error.message}</p>}
                  <button className="lp-btn primary lg si-submit" type="submit" disabled={busy}>
                    {verify.isPending ? <><i className="si-spin" /> Verifying…</> : <>Verify and sign in <ArrowRight className="w-4 h-4" /></>}
                  </button>
                </form>
              ) : (
                <div id="signin-form" className="si-form">
                  <CodeInput
                    key={attempt}
                    disabled={busy}
                    fill={demoCode}
                    onComplete={(code) => challenge && verify.mutate({ challenge, code })}
                  />
                  {demoEnabled && (
                    <button
                      type="button"
                      className="si-demo-fill"
                      disabled={busy || !!demoCode}
                      onClick={() => challenge && fillCode.mutate({ challenge })}
                    >
                      {fillCode.isPending ? <i className="si-spin dark" /> : <Zap className="w-4 h-4" />}
                      Auto-fill demo code
                    </button>
                  )}
                  {verify.isPending && <p className="si-status"><i className="si-spin dark" /> Verifying code…</p>}
                  {error && <p className="si-error" role="alert">{error.message}</p>}
                </div>
              )}

              <div className="si-links">
                <button type="button" className="si-link" disabled={busy} onClick={() => { setRecovery(!recovery); verify.reset(); }}>
                  {recovery ? "Use authenticator app" : "Use a recovery code"}
                </button>
                <span className="si-sep" aria-hidden="true">·</span>
                <button type="button" className="si-link" disabled={busy} onClick={startAgain}>
                  Start again
                </button>
              </div>
            </div>
          )}
        </div>

        <p className="si-foot">Protected by MFA · Sessions expire after 12 hours</p>
      </section>
    </div>
  );
}

export function SignOutButton() {
  const cache = useQueryClient();
  const logout = useMutation({
    mutationFn: () => apiWrite("/api/v1/auth/logout", {}),
    onSuccess: async () => { setCsrfToken(null); await cache.invalidateQueries(); },
  });
  return (
    <button className="btn sm ghost" onClick={() => logout.mutate()} disabled={logout.isPending} title="End active session">
      {logout.isPending ? "Signing out…" : "Sign out"}
    </button>
  );
}

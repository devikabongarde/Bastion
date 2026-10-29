import { useState, type FormEvent } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { apiWrite, setCsrfToken } from "./lib/api";
import { Icon } from "./components/ui";

export function SignInPanel() {
  const cache = useQueryClient();
  const [challenge, setChallenge] = useState<string | null>(null);
  const [recovery, setRecovery] = useState(false);
  const login = useMutation({
    mutationFn: (body: { organization: string; username: string; password: string }) => apiWrite<{ challenge: string }>("/api/v1/auth/login", body),
    onSuccess: (data) => setChallenge(data.challenge),
  });
  const verify = useMutation({
    mutationFn: (body: { challenge: string; code?: string; recovery_code?: string }) => apiWrite<{ csrf_token: string }>("/api/v1/auth/mfa/verify", body),
    onSuccess: async (data) => { setCsrfToken(data.csrf_token); await cache.invalidateQueries(); },
  });
  const busy = login.isPending || verify.isPending;
  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    if (challenge) {
      verify.mutate({ challenge, ...(recovery ? { recovery_code: String(form.get("code")) } : { code: String(form.get("code")) }) });
    } else {
      login.mutate({ organization: String(form.get("organization")), username: String(form.get("username")), password: String(form.get("password")) });
    }
  }
  const error = challenge ? verify.error : login.error;
  return (
    <div className="signin">
      <a className="skip-link" href="#signin-form">Skip to sign in</a>
      <section className="signin-hero" aria-labelledby="access-heading">
        <div className="brand"><span className="brand-mark"><Icon name="shield" /></span><span>BaselineGuard<small>Configuration assurance</small></span></div>
        <div>
          <p className="eyebrow">Private workspace</p>
          <h1 id="access-heading">Sign-in is required.<br /><em>Defensible answers, visible limits.</em></h1>
        </div>
        <div className="signin-points">
          <div><span className="ico"><Icon name="check" /></span><p><b>Evidence-backed results</b><span>Every finding shows expected value, observed value and the evidence behind it.</span></p></div>
          <div><span className="ico"><Icon name="eye" /></span><p><b>Honest scoring</b><span>Compliance is always shown beside completeness, so gaps never hide behind a green number.</span></p></div>
          <div><span className="ico"><Icon name="lock" /></span><p><b>Deterministic and private</b><span>No AI, no paid APIs. Your data stays on this installation.</span></p></div>
        </div>
      </section>
      <div className="signin-card-wrap">
        <form id="signin-form" className="signin-card" onSubmit={submit} aria-busy={busy}>
          <h2>{challenge ? "Verify your identity" : "Open your workspace"}</h2>
          {challenge ? (
            <>
              <p className="quiet">{recovery ? "Enter one unused recovery code. It is consumed when you sign in." : "Enter the six-digit code from your authenticator."}</p>
              <label className="field">{recovery ? "Recovery code" : "Authenticator code"}
                <input name="code" key={recovery ? "recovery" : "totp"} inputMode={recovery ? "text" : "numeric"} autoComplete="one-time-code" required minLength={recovery ? 20 : 6} maxLength={recovery ? 20 : 6} pattern={recovery ? "[A-Fa-f0-9]{20}" : "[0-9]{6}"} autoFocus disabled={busy} />
              </label>
            </>
          ) : (
            <>
              <label className="field">Organization<input name="organization" required maxLength={100} pattern="[a-z0-9\-]+" autoComplete="organization" placeholder="your-organization" disabled={busy} /></label>
              <label className="field">Username<input name="username" autoComplete="username" required maxLength={255} disabled={busy} /></label>
              <label className="field">Password<input name="password" type="password" autoComplete="current-password" required maxLength={1024} disabled={busy} /></label>
            </>
          )}
          {error && <p className="form-error" role="alert">{error.message}</p>}
          <button className="btn primary" type="submit" disabled={busy}>{busy ? "Verifying…" : challenge ? "Verify and sign in" : "Continue"}</button>
          {challenge ? (
            <div className="row-between">
              <button type="button" className="link" disabled={busy} onClick={() => { setRecovery(!recovery); verify.reset(); }}>{recovery ? "Use an authenticator" : "Use a recovery code"}</button>
              <button type="button" className="link" disabled={busy} onClick={() => { setChallenge(null); verify.reset(); login.reset(); }}>Start again</button>
            </div>
          ) : <p className="quiet">Need an account? Ask your workspace administrator to enroll you.</p>}
        </form>
      </div>
    </div>
  );
}

export function SignOutButton() {
  const cache = useQueryClient();
  const signOut = useMutation({ mutationFn: () => apiWrite<void>("/api/v1/auth/logout"), onSuccess: () => { setCsrfToken(null); cache.clear(); } });
  return <button type="button" className="btn sm ghost" onClick={() => signOut.mutate()} disabled={signOut.isPending}>{signOut.isPending ? "Signing out…" : "Sign out"}</button>;
}

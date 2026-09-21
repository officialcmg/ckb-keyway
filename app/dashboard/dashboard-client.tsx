"use client";

import { useEffect, useState, type FormEvent } from "react";

const API_URL = "https://keyway-api-production.up.railway.app";
const SESSION_KEY = "ckb-keyway.developer-session";

type ApplicationOrigin = { origin: string; environment: "development" | "production" };
type DeveloperApplication = {
  appId: string;
  name: string;
  disabled: boolean;
  otpLoginTemplateId?: string;
  otpSignupTemplateId?: string;
  otpLimitPerMinute: number;
  origins: ApplicationOrigin[];
  usage: { sent24h: number; failed24h: number; rateLimited24h: number };
  createdAt: string;
  updatedAt: string;
};

export function DeveloperDashboard() {
  const [token, setToken] = useState<string>();
  const [ready, setReady] = useState(false);
  const [applications, setApplications] = useState<DeveloperApplication[]>([]);
  const [error, setError] = useState<string>();

  useEffect(() => {
    const stored = localStorage.getItem(SESSION_KEY) ?? undefined;
    if (!stored) return setReady(true);
    void session(stored).then(() => {
      setToken(stored);
      return loadApplications(stored);
    }).catch(() => localStorage.removeItem(SESSION_KEY)).finally(() => setReady(true));
  }, []);

  async function loadApplications(authToken = token) {
    if (!authToken) return;
    const result = await developerRequest<{ applications: DeveloperApplication[] }>(authToken, { operation: "list" });
    setApplications(result.applications);
  }

  async function authenticated(authToken: string) {
    localStorage.setItem(SESSION_KEY, authToken);
    setToken(authToken);
    setReady(true);
    await loadApplications(authToken);
  }

  async function logout() {
    if (token) await apiRequest("/api/keyway/auth/logout", {}, token).catch(() => undefined);
    localStorage.removeItem(SESSION_KEY);
    setToken(undefined);
    setApplications([]);
  }

  if (!ready) return <p className="dashboard-loading">Loading developer console...</p>;
  if (!token) return <DeveloperLogin onAuthenticated={authenticated} />;

  return (
    <section className="dashboard-content">
      <div className="dashboard-hero">
        <div><p className="eyebrow">Developer console</p><h1>Build with KeyWay.</h1><p>Register your application, authorize its browser origins, and monitor email authentication.</p></div>
        <button type="button" className="quiet-button" onClick={() => void logout()}>Log out</button>
      </div>
      <CreateApplication onCreated={(application) => setApplications((current) => [application, ...current])} token={token} />
      {error ? <p className="error">{error}</p> : null}
      <div className="application-list">
        {applications.map((application) => (
          <ApplicationCard
            key={application.appId}
            application={application}
            token={token}
            onChange={(next) => setApplications((current) => current.map((app) => app.appId === next.appId ? next : app))}
            onError={setError}
          />
        ))}
        {!applications.length ? <div className="empty-apps"><strong>No applications yet.</strong><span>Create one above to get a public app ID.</span></div> : null}
      </div>
    </section>
  );
}

function DeveloperLogin({ onAuthenticated }: { onAuthenticated: (token: string) => Promise<void> }) {
  const [email, setEmail] = useState("");
  const [methodId, setMethodId] = useState<string>();
  const [code, setCode] = useState("");
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string>();

  async function submit(event: FormEvent) {
    event.preventDefault();
    setPending(true);
    setError(undefined);
    try {
      if (!methodId) {
        const result = await apiRequest<{ methodId: string }>("/api/keyway/auth/send-code", { email });
        setMethodId(result.methodId);
      } else {
        const result = await apiRequest<{ sessionToken: string }>("/api/keyway/auth/verify-code", { methodId, code });
        await onAuthenticated(result.sessionToken);
      }
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Could not log in");
    } finally {
      setPending(false);
    }
  }

  return (
    <section className="developer-login">
      <div><p className="eyebrow">Developer console</p><h1>Ship a Fiber wallet.</h1><p>Create an application and connect it to the managed KeyWay API without handling server credentials.</p></div>
      <form onSubmit={submit}>
        <p className="step-label">{methodId ? "Check your inbox" : "Email login"}</p>
        <h2>{methodId ? "Enter your code" : "Continue with email"}</h2>
        {!methodId ? (
          <label>Email address<input required autoFocus type="email" autoComplete="email" value={email} onChange={(event) => setEmail(event.target.value)} placeholder="developer@example.com" /></label>
        ) : (
          <label>Six-digit code<input required autoFocus inputMode="numeric" autoComplete="one-time-code" pattern="[0-9]{6}" maxLength={6} value={code} onChange={(event) => setCode(event.target.value.replace(/\D/g, "").slice(0, 6))} placeholder="000000" /></label>
        )}
        {error ? <p className="error">{error}</p> : null}
        <button disabled={pending || (methodId ? code.length !== 6 : !email)}>{pending ? "Please wait..." : methodId ? "Verify code" : "Send code"}</button>
        {methodId ? <button type="button" className="text-button" onClick={() => { setMethodId(undefined); setCode(""); setError(undefined); }}>Use another email</button> : null}
      </form>
    </section>
  );
}

function CreateApplication({ token, onCreated }: {
  token: string;
  onCreated: (application: DeveloperApplication) => void;
}) {
  const [name, setName] = useState("");
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string>();

  async function create(event: FormEvent) {
    event.preventDefault();
    setPending(true);
    setError(undefined);
    try {
      const application = await developerRequest<DeveloperApplication>(token, { operation: "create", name });
      onCreated(application);
      setName("");
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Could not create application");
    } finally {
      setPending(false);
    }
  }

  return (
    <form className="create-application" onSubmit={create}>
      <div><p className="step-label">New integration</p><h2>Create an application</h2></div>
      <label>Application name<input required maxLength={80} value={name} onChange={(event) => setName(event.target.value)} placeholder="CadencePay" /></label>
      <button disabled={pending || !name.trim()}>{pending ? "Creating..." : "Create app"}</button>
      {error ? <p className="error">{error}</p> : null}
    </form>
  );
}

function ApplicationCard({ application, token, onChange, onError }: {
  application: DeveloperApplication;
  token: string;
  onChange: (application: DeveloperApplication) => void;
  onError: (message?: string) => void;
}) {
  const [name, setName] = useState(application.name);
  const [loginTemplate, setLoginTemplate] = useState(application.otpLoginTemplateId ?? "");
  const [signupTemplate, setSignupTemplate] = useState(application.otpSignupTemplateId ?? "");
  const [otpLimit, setOtpLimit] = useState(String(application.otpLimitPerMinute));
  const [origin, setOrigin] = useState("");
  const [environment, setEnvironment] = useState<ApplicationOrigin["environment"]>("development");
  const [pending, setPending] = useState(false);

  async function act(body: Record<string, unknown>) {
    setPending(true);
    onError(undefined);
    try {
      const next = await developerRequest<DeveloperApplication>(token, { ...body, appId: application.appId });
      onChange(next);
      return next;
    } catch (cause) {
      onError(cause instanceof Error ? cause.message : "Application update failed");
    } finally {
      setPending(false);
    }
  }

  async function save(event: FormEvent) {
    event.preventDefault();
    await act({
      operation: "update",
      name,
      otpLoginTemplateId: loginTemplate || null,
      otpSignupTemplateId: signupTemplate || null,
      otpLimitPerMinute: Number(otpLimit),
    });
  }

  async function addOrigin(event: FormEvent) {
    event.preventDefault();
    const next = await act({ operation: "add-origin", origin, environment });
    if (next) setOrigin("");
  }

  return (
    <article className={`application-card${application.disabled ? " disabled" : ""}`}>
      <header>
        <div><p className="step-label">{application.disabled ? "Disabled" : "Active application"}</p><h2>{application.name}</h2></div>
        <button type="button" className={application.disabled ? "" : "danger-button"} disabled={pending} onClick={() => void act({ operation: "update", disabled: !application.disabled })}>{application.disabled ? "Enable" : "Disable"}</button>
      </header>
      <div className="app-id-row"><code>{application.appId}</code><button type="button" className="quiet-button" onClick={() => void navigator.clipboard.writeText(application.appId)}>Copy app ID</button></div>
      <div className="usage-grid">
        <div><strong>{application.usage.sent24h}</strong><span>Codes sent · 24h</span></div>
        <div><strong>{application.usage.failed24h}</strong><span>Failed checks · 24h</span></div>
        <div><strong>{application.usage.rateLimited24h}</strong><span>Blocked · 24h</span></div>
      </div>
      <form className="application-settings" onSubmit={save}>
        <label>Display name<input required maxLength={80} value={name} onChange={(event) => setName(event.target.value)} /></label>
        <label>OTP requests per minute<input required type="number" min={1} max={120} value={otpLimit} onChange={(event) => setOtpLimit(event.target.value)} /></label>
        <label>Stytch login template ID<input value={loginTemplate} onChange={(event) => setLoginTemplate(event.target.value)} placeholder="Optional" /></label>
        <label>Stytch signup template ID<input value={signupTemplate} onChange={(event) => setSignupTemplate(event.target.value)} placeholder="Optional" /></label>
        <button disabled={pending}>Save settings</button>
      </form>
      <section className="origin-settings">
        <div><p className="step-label">Allowed browser origins</p><p>Requests carrying this app ID must come from one of these exact origins.</p></div>
        <div className="origin-list">
          {application.origins.map((item) => (
            <div key={item.origin}><code>{item.origin}</code><span>{item.environment}</span><button type="button" className="text-button" disabled={pending} onClick={() => void act({ operation: "remove-origin", origin: item.origin })}>Remove</button></div>
          ))}
          {!application.origins.length ? <p className="empty-origin">No origins registered. SDK requests will be rejected.</p> : null}
        </div>
        <form onSubmit={addOrigin}>
          <input required type="url" value={origin} onChange={(event) => setOrigin(event.target.value)} placeholder="https://your-app.com" />
          <select value={environment} onChange={(event) => setEnvironment(event.target.value as ApplicationOrigin["environment"])}><option value="development">Development</option><option value="production">Production</option></select>
          <button disabled={pending || !origin}>Add origin</button>
        </form>
      </section>
    </article>
  );
}

async function session(token: string): Promise<void> {
  await apiRequest("/api/keyway/auth/session", {}, token);
}

function developerRequest<T>(token: string, body: Record<string, unknown>): Promise<T> {
  return apiRequest("/api/keyway/developer/apps", body, token);
}

async function apiRequest<T>(path: string, body: unknown, token?: string): Promise<T> {
  const response = await fetch(`${API_URL}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json", ...(token ? { Authorization: `Bearer ${token}` } : {}) },
    body: JSON.stringify(body),
  });
  const result = response.status === 204 ? undefined : await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(result?.error ?? "KeyWay request failed");
  return result as T;
}

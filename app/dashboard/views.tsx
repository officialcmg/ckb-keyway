"use client";

import Link from "next/link";
import { useEffect, useRef, useState, type FormEvent } from "react";
import { createOtpEmailTemplate } from "../../src/server/email-template";
import { CopyButton } from "../_components/copy-button";
import { AlertIcon, ChevronDown, LogoMark, PlusIcon, SpinnerIcon } from "../_components/icons";
import { QUICKSTART_URL, TROUBLESHOOTING_URL } from "../_components/links";
import { APP_NAME_MAX, checkOrigin, type ApplicationOrigin, type DeveloperApplication } from "./api";

/* Sign in */

export function SignInCard({ onSendCode, onVerify }: {
  onSendCode: (email: string) => Promise<string>;
  onVerify: (email: string, challengeId: string, code: string) => Promise<void>;
}) {
  const [email, setEmail] = useState("");
  const [challengeId, setChallengeId] = useState<string>();
  const [code, setCode] = useState("");
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string>();

  async function submit(event: FormEvent) {
    event.preventDefault();
    setPending(true);
    setError(undefined);
    try {
      if (!challengeId) setChallengeId(await onSendCode(email.trim()));
      else await onVerify(email.trim(), challengeId, code);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Something went wrong. Try again.");
    } finally {
      setPending(false);
    }
  }

  return (
    <form className="dash-signin" onSubmit={submit}>
      <LogoMark size={40} />
      {!challengeId ? (
        <>
          <div className="dash-signin__copy"><h1>Sign in to your dashboard</h1><p>Register apps, manage allowed origins and see sign-in activity. We&apos;ll email you a six-digit code.</p></div>
          <label htmlFor="dash-email" className="field">Work email<input id="dash-email" className="input dash-signin__input" type="email" required autoComplete="email" placeholder="you@company.com" value={email} onChange={(event) => setEmail(event.target.value)} /></label>
          {error && <p className="field-error"><AlertIcon />{error}</p>}
          <button type="submit" className={`btn btn--route btn--lg dash-signin__button${pending ? " btn--busy" : ""}`} disabled={pending}>{pending ? "Sending…" : "Email me a code"}</button>
          <p className="dash-signin__note">Your dashboard account is separate from any wallet. Signing in here never creates a CKB account.</p>
        </>
      ) : (
        <>
          <div className="dash-signin__copy"><h1>Check your email</h1><p>We sent a six-digit code to <strong>{email}</strong>. It expires in 10 minutes.</p></div>
          <label htmlFor="dash-code" className="field">Code<input id="dash-code" className="input dash-signin__input dash-signin__code" required autoFocus inputMode="numeric" autoComplete="one-time-code" pattern="[0-9]{6}" maxLength={6} placeholder="000000" value={code} onChange={(event) => setCode(event.target.value.replace(/\D/g, "").slice(0, 6))} /></label>
          {error && <p className="field-error"><AlertIcon />{error}</p>}
          <button type="submit" className={`btn btn--route btn--lg dash-signin__button${pending ? " btn--busy" : ""}`} disabled={pending || code.length !== 6}>{pending ? "Verifying…" : "Verify and sign in"}</button>
          <button type="button" className="dash-textlink" onClick={() => { setChallengeId(undefined); setCode(""); setError(undefined); }}>Use a different email</button>
        </>
      )}
    </form>
  );
}

/* Applications list */

export function ApplicationsHeader({ email, onSignOut, onCreate }: { email?: string; onSignOut: () => void; onCreate: () => void }) {
  return (
    <div className="dash-list-head">
      <div className="dash-list-head__copy">
        <p>{email && <>{email} · </>}<a href="#" onClick={(event) => { event.preventDefault(); onSignOut(); }}>Sign out</a></p>
        <h1>Applications</h1>
      </div>
      <button type="button" className="btn btn--route dash-new" onClick={onCreate}><PlusIcon />New application</button>
    </div>
  );
}

export function ListLoading({ label = "Loading your applications…" }: { label?: string }) {
  return <section aria-busy="true" className="card dash-loading"><SpinnerIcon size={20} className="dash-spinner" />{label}</section>;
}

export function ListEmpty({ onCreate }: { onCreate: () => void }) {
  return (
    <section className="card dash-empty">
      <h2>Create your first application</h2>
      <p>An application gives you an app ID for <code>KeyWayProvider</code> and a list of origins allowed to use it. Its name appears in your users&apos; sign-in emails.</p>
      <button type="button" className="btn btn--route dash-empty__button" onClick={onCreate}>New application</button>
    </section>
  );
}

export function ListError({ title = "Couldn't load your applications", body = "The KeyWay API didn't respond. Your apps and users are unaffected. Try again in a moment.", onRetry }: { title?: string; body?: string; onRetry: () => void }) {
  return (
    <section role="alert" className="card dash-error">
      <AlertIcon size={24} className="dash-error__icon" />
      <div className="dash-error__copy"><h2>{title}</h2><p>{body}</p></div>
      <div className="dash-error__actions"><button type="button" className="btn btn--route dash-error__retry" onClick={onRetry}>Try again</button><a className="btn btn--outline dash-error__link" href={TROUBLESHOOTING_URL}>Troubleshooting</a></div>
    </section>
  );
}

export function ApplicationRows({ applications }: { applications: DeveloperApplication[] }) {
  return (
    <section aria-label="Your applications" className="card dash-rows">
      {applications.map((app) => (
        <Link key={app.appId} href={`/dashboard/${app.appId}`} className="dash-row">
          <span className="dash-row__name">{app.name}</span>
          <span className="dash-row__id">{app.appId}</span>
          <span className="dash-row__meta">{app.origins.length} {app.origins.length === 1 ? "origin" : "origins"}</span>
          <EnabledStatus disabled={app.disabled} className="dash-row__status" />
        </Link>
      ))}
    </section>
  );
}

function EnabledStatus({ disabled, className = "" }: { disabled: boolean; className?: string }) {
  return disabled
    ? <span className={`status status--muted ${className}`}><span className="status__ring" />Disabled</span>
    : <span className={`status status--success ${className}`}><span className="status__dot" />Enabled</span>;
}

export function CreateDialog({ initialName = "", onCancel, onCreate }: { initialName?: string; onCancel: () => void; onCreate: (name: string) => Promise<void> }) {
  const [name, setName] = useState(initialName);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string>();
  useEffect(() => {
    const onKey = (event: KeyboardEvent) => { if (event.key === "Escape") onCancel(); };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onCancel]);

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (!name.trim()) return setError("Enter an application name.");
    setPending(true);
    setError(undefined);
    try { await onCreate(name.trim()); } catch (cause) { setError(cause instanceof Error ? cause.message : "The application could not be created"); setPending(false); }
  }

  return (
    <div className="scrim dash-scrim" role="presentation" onMouseDown={(event) => { if (event.target === event.currentTarget) onCancel(); }}>
      <form role="dialog" aria-modal="true" aria-labelledby="create-title" className="dialog dash-dialog" onSubmit={submit}>
        <div className="dash-dialog__head"><h2 id="create-title" className="dialog__title">New application</h2><p>You&apos;ll get an app ID right away. Add allowed origins on the next screen.</p></div>
        <label htmlFor="create-name" className="field">Application name<input id="create-name" className="input" type="text" autoFocus required maxLength={APP_NAME_MAX} value={name} onChange={(event) => setName(event.target.value)} /><span className="field__hint">Your users see this in the sign-in modal and email.</span></label>
        {error && <p className="field-error"><AlertIcon />{error}</p>}
        <div className="dash-dialog__actions"><button type="button" className="btn btn--outline" onClick={onCancel}>Cancel</button><button type="submit" className={`btn btn--route${pending ? " btn--busy" : ""}`} disabled={pending}>{pending ? "Creating…" : "Create application"}</button></div>
      </form>
    </div>
  );
}

/* Application detail */

export type DetailActions = {
  update: (changes: { name?: string; disabled?: boolean }) => Promise<void>;
  addOrigin: (origin: string, environment: ApplicationOrigin["environment"]) => Promise<void>;
  removeOrigin: (origin: string) => Promise<void>;
};

const createdFormat = new Intl.DateTimeFormat("en-US", { month: "short", day: "numeric", year: "numeric" });

export function ApplicationDetail({ app, actions, initialOrigin }: { app: DeveloperApplication; actions: DetailActions; initialOrigin?: string }) {
  return (
    <>
      <nav aria-label="Breadcrumb" className="dash-crumbs"><Link href="/dashboard">Applications</Link> <span aria-hidden="true">/</span> <span className="dash-crumbs__current">{app.name}</span></nav>
      <div className="dash-detail-head">
        <div className="dash-detail-head__copy">
          <div className="dash-detail-head__title"><h1>{app.name}</h1>{app.disabled
            ? <span className="dash-pill dash-pill--muted"><span className="status__ring" />Disabled</span>
            : <span className="dash-pill dash-pill--success"><span className="status__dot" />Enabled</span>}</div>
          <div className="dash-detail-head__meta">App ID<span className="dash-chip"><span>{app.appId}</span><CopyButton value={app.appId} label="Copy app ID" className="icon-button dash-chip__copy" /></span><span>Created {createdFormat.format(new Date(app.createdAt))}</span></div>
        </div>
      </div>

      {app.disabled && <DisabledBanner onEnable={() => actions.update({ disabled: false })} />}

      <div className="dash-detail">
        <div className="dash-detail__main">
          <Quickstart app={app} />
          <Origins app={app} actions={actions} initialOrigin={initialOrigin} />
          <section className="card dash-card">
            <div className="dash-card__head dash-card__head--split"><div className="dash-card__titles"><h2>Sign-in email</h2><p>What your users receive. The app name comes from this application, never from the browser.</p></div><span className="dash-card__aside">From login@auth.ckbkeyway.dev</span></div>
            <EmailPreview name={app.name} />
          </section>
        </div>
        <aside className="dash-detail__side">
          <section className="card dash-card dash-card--12">
            <h2 className="dash-card__h">Last 24 hours</h2>
            <dl className="dash-stats">
              <div><dt>Codes sent</dt><dd className="dash-stats__big">{app.usage.sent24h}</dd></div>
              <div><dt>Failed to send or verify</dt><dd>{app.usage.failed24h}</dd></div>
              <div><dt>Rate limited</dt><dd>{app.usage.rateLimited24h}</dd></div>
            </dl>
          </section>
          <Settings app={app} actions={actions} />
        </aside>
      </div>
    </>
  );
}

function DisabledBanner({ onEnable }: { onEnable: () => Promise<void> }) {
  const [pending, setPending] = useState(false);
  return (
    <section role="status" className="dash-banner">
      <AlertIcon size={20} className="dash-banner__icon" />
      <p><strong>This application is disabled.</strong> New sign-ins from its origins are rejected. Users keep their accounts and can sign in again once you enable it.</p>
      <button type="button" className={`btn btn--route btn--sm${pending ? " btn--busy" : ""}`} disabled={pending} onClick={() => { setPending(true); void onEnable().finally(() => setPending(false)); }}>{pending ? "Enabling…" : "Enable application"}</button>
    </section>
  );
}

function Quickstart({ app }: { app: DeveloperApplication }) {
  const name = JSON.stringify(app.name);
  const source = `"use client";\n\nimport { KeyWayProvider } from "@ckb-keyway/react";\n\nexport function Providers({ children }) {\n  return (\n    <KeyWayProvider\n      appId="${app.appId}"\n      appName=${name}\n    >\n      {children}\n    </KeyWayProvider>\n  );\n}`;
  return (
    <section className="card dash-card">
      <div className="dash-card__titles"><h2>Quickstart</h2><p>Install the SDK and wrap your app. This app&apos;s ID is already filled in.</p></div>
      <div className="dash-install"><span className="dash-install__prompt">$</span><span className="dash-install__cmd">npm i @ckb-keyway/react</span><CopyButton value="npm i @ckb-keyway/react" label="Copy install command" /></div>
      <figure className="code-panel dash-code">
        <figcaption className="dash-code__bar"><span>app/providers.tsx</span><CopyButton value={source} label="Copy code" /></figcaption>
        <pre><code><span className="tk-s">&quot;use client&quot;</span>{";\n\n"}<span className="tk-k">import</span>{" { KeyWayProvider } "}<span className="tk-k">from</span> <span className="tk-s">&quot;@ckb-keyway/react&quot;</span>{";\n\n"}<span className="tk-k">export function</span>{" Providers({ children }) {\n  "}<span className="tk-k">return</span>{" (\n    <"}<span className="tk-c">KeyWayProvider</span>{"\n      appId="}<span className="tk-s">&quot;{app.appId}&quot;</span>{"\n      appName="}<span className="tk-s">{name}</span>{"\n    >\n      {children}\n    </"}<span className="tk-c">KeyWayProvider</span>{">\n  );\n}"}</code></pre>
      </figure>
      <a className="link dash-card__link" href={QUICKSTART_URL}>Read the full quickstart</a>
    </section>
  );
}

function useConfirm(): [string | undefined, (key?: string) => void] {
  const [key, setKey] = useState<string>();
  useEffect(() => {
    if (!key) return;
    const timer = window.setTimeout(() => setKey(undefined), 5000);
    return () => window.clearTimeout(timer);
  }, [key]);
  return [key, setKey];
}

function Origins({ app, actions, initialOrigin }: { app: DeveloperApplication; actions: DetailActions; initialOrigin?: string }) {
  const [origin, setOrigin] = useState(initialOrigin ?? "");
  const [environment, setEnvironment] = useState<ApplicationOrigin["environment"]>("production");
  const [error, setError] = useState(initialOrigin ? checkOrigin(initialOrigin).error : undefined);
  const [pending, setPending] = useState(false);
  const [confirming, setConfirming] = useConfirm();
  const [removing, setRemoving] = useState<string>();
  const groups = (["production", "development"] as const).map((env) => ({ env, items: app.origins.filter((item) => item.environment === env) })).filter(({ items }) => items.length);

  async function add(event: FormEvent) {
    event.preventDefault();
    const checked = checkOrigin(origin);
    if (!checked.origin) return setError(checked.error);
    setPending(true);
    setError(undefined);
    try { await actions.addOrigin(checked.origin, environment); setOrigin(""); } catch (cause) { setError(cause instanceof Error ? cause.message : "The origin could not be added"); } finally { setPending(false); }
  }

  async function remove(value: string) {
    setConfirming(undefined);
    setRemoving(value);
    setError(undefined);
    try { await actions.removeOrigin(value); } catch (cause) { setError(cause instanceof Error ? cause.message : "The origin could not be removed"); } finally { setRemoving(undefined); }
  }

  return (
    <section className="card dash-card">
      <div className="dash-card__titles"><h2>Allowed origins</h2><p>Only these exact origins can sign users in with this app ID. Use the scheme and host, without a path.</p></div>
      <div className="dash-origins">
        {groups.map(({ env, items }, index) => (
          <div key={env} className="dash-origins__group">
            <p className={`eyebrow dash-origins__label${index ? " dash-origins__label--next" : ""}`}>{env === "production" ? "Production" : "Development"}</p>
            {items.map((item) => (
              <div key={item.origin} className="dash-origin">
                <span>{item.origin}</span>
                {confirming === item.origin ? (
                  <span className="dash-origin__confirm">
                    <button type="button" className="dash-origin__remove dash-origin__remove--danger" onClick={() => void remove(item.origin)}>Confirm remove</button>
                    <button type="button" className="dash-origin__remove" onClick={() => setConfirming(undefined)}>Cancel</button>
                  </span>
                ) : (
                  <button type="button" aria-label={`Remove ${item.origin}`} className="dash-origin__remove" disabled={removing === item.origin} onClick={() => setConfirming(item.origin)}>{removing === item.origin ? "Removing…" : "Remove"}</button>
                )}
              </div>
            ))}
          </div>
        ))}
        {!groups.length && <p className="dash-origins__none">No origins yet. Sign-ins with this app ID are rejected until you add one.</p>}
      </div>
      <form className="dash-add" onSubmit={add}>
        <label htmlFor="new-origin" className="field dash-add__origin">Add an origin
          <input id="new-origin" className="input dash-mono-input" type="url" placeholder="https://staging.acmepay.xyz" value={origin} onChange={(event) => { setOrigin(event.target.value); setError(undefined); }} aria-invalid={Boolean(error) || undefined} aria-describedby={error ? "origin-error" : undefined} />
        </label>
        <label htmlFor="new-origin-env" className="field dash-add__env">Environment
          <span className="dash-select">
            <select id="new-origin-env" value={environment} onChange={(event) => setEnvironment(event.target.value as ApplicationOrigin["environment"])}><option value="production">Production</option><option value="development">Development</option></select>
            <ChevronDown />
          </span>
        </label>
        <button type="submit" className={`btn btn--outline dash-add__button${pending ? " btn--busy" : ""}`} disabled={pending}>{pending ? "Adding…" : "Add origin"}</button>
      </form>
      {error && <p id="origin-error" className="field-error dash-add__error"><AlertIcon />{error}</p>}
    </section>
  );
}

function Settings({ app, actions }: { app: DeveloperApplication; actions: DetailActions }) {
  const [name, setName] = useState(app.name);
  const [pending, setPending] = useState(false);
  const [saved, setSaved] = useState(false);
  const [error, setError] = useState<string>();
  const [confirming, setConfirming] = useConfirm();
  const [disabling, setDisabling] = useState(false);

  useEffect(() => { setName(app.name); }, [app.name]);
  useEffect(() => {
    if (!saved) return;
    const timer = window.setTimeout(() => setSaved(false), 3000);
    return () => window.clearTimeout(timer);
  }, [saved]);

  async function save(event: FormEvent) {
    event.preventDefault();
    if (!name.trim()) return setError("Enter an application name.");
    setPending(true);
    setError(undefined);
    try { await actions.update({ name: name.trim() }); setSaved(true); } catch (cause) { setError(cause instanceof Error ? cause.message : "Your changes could not be saved"); } finally { setPending(false); }
  }

  async function disable() {
    setConfirming(undefined);
    setDisabling(true);
    setError(undefined);
    try { await actions.update({ disabled: true }); } catch (cause) { setError(cause instanceof Error ? cause.message : "The application could not be disabled"); } finally { setDisabling(false); }
  }

  return (
    <form className="card dash-card" onSubmit={save}>
      <h2 className="dash-card__h">Settings</h2>
      <label htmlFor="app-name" className="field">Application name<input id="app-name" className="input" type="text" required maxLength={APP_NAME_MAX} value={name} onChange={(event) => setName(event.target.value)} /><span className="field__hint">Shown in the sign-in modal and email. Up to 80 characters.</span></label>
      {error && <p className="field-error"><AlertIcon />{error}</p>}
      <div className="dash-save"><button type="submit" className={`btn btn--ink${pending ? " btn--busy" : ""}`} disabled={pending}>{pending ? "Saving…" : "Save changes"}</button>{saved && <span className="dash-saved" role="status">Saved</span>}</div>
      {!app.disabled && (
        <div className="dash-disable">
          <h3>Disable application</h3>
          <p>Rejects new sign-ins from every origin right away. Users keep their accounts.</p>
          {confirming ? (
            <span className="dash-disable__confirm">
              <button type="button" className="btn btn--danger-fill btn--sm" onClick={() => void disable()}>Confirm disable</button>
              <button type="button" className="btn btn--outline btn--sm" onClick={() => setConfirming(undefined)}>Cancel</button>
            </span>
          ) : (
            <button type="button" className={`btn btn--danger btn--sm dash-disable__button${disabling ? " btn--busy" : ""}`} disabled={disabling} onClick={() => setConfirming("disable")}>{disabling ? "Disabling…" : "Disable application"}</button>
          )}
        </div>
      )}
    </form>
  );
}

/* Email preview: the real template from src/server/email-template.ts, scaled into the board's frame. */

const PREVIEW_CODE = "481027";

/** The preview is scaled so the frame keeps the board's proportions: a little smaller on wide cards, nearly full size on phones. */
function previewScale(frameWidth: number): number {
  return frameWidth < 480 ? 0.95 : 0.91;
}

export function EmailPreview({ name }: { name: string }) {
  const template = createOtpEmailTemplate(name, PREVIEW_CODE);
  const box = useRef<HTMLDivElement>(null);
  const frame = useRef<HTMLIFrameElement>(null);
  const [layout, setLayout] = useState({ scale: 0.91, height: 502 });

  const measure = () => {
    const width = box.current?.clientWidth;
    const body = frame.current?.contentDocument?.body;
    if (!width || !body) return;
    const scale = previewScale(width);
    frame.current!.style.width = `${width / scale}px`;
    setLayout({ scale, height: Math.round(body.offsetHeight * scale) });
  };

  useEffect(() => {
    const observer = new ResizeObserver(() => measure());
    if (box.current) observer.observe(box.current);
    return () => observer.disconnect();
  });

  return (
    <div className="dash-email">
      <div className="dash-email__subject">Subject: <span>{template.subject}</span></div>
      <div ref={box} className="dash-email__frame" style={{ height: layout.height }}>
        <iframe
          ref={frame}
          title={`Email preview: Log in to ${name}, your login code is ${PREVIEW_CODE}`}
          sandbox="allow-same-origin"
          srcDoc={template.html}
          onLoad={measure}
          style={{ height: layout.height / layout.scale, transform: `scale(${layout.scale})` }}
        />
      </div>
    </div>
  );
}

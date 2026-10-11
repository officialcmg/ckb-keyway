"use client";

import dynamic from "next/dynamic";
import Link from "next/link";
import { useEffect } from "react";
import { type DeveloperApplication } from "../api";
import { useDashboard } from "../session";
import { ApplicationDetail, ListError, ListLoading, SignInCard, type DetailActions } from "../views";

/** Development-only state previews (`/dashboard/<appId>?screen=…`); never bundled in production. */
const DevDetail = process.env.NODE_ENV !== "production"
  ? dynamic(() => import("../dev-screens").then((module) => module.DevDetail), { ssr: false })
  : () => null;

export function ApplicationPage({ appId, devScreen }: { appId: string; devScreen?: string }) {
  if (process.env.NODE_ENV !== "production" && devScreen) return <DevDetail screen={devScreen} />;
  return <LiveApplication appId={appId} />;
}

function LiveApplication({ appId }: { appId: string }) {
  const session = useDashboard();
  const app = session.applications.find((item) => item.appId === appId);

  useEffect(() => {
    if (app) document.title = `${app.name} · Dashboard · CKB KeyWay`;
  }, [app]);

  if (session.status === "checking") return null;
  if (session.status === "signedOut") return <SignInCard onSendCode={session.sendCode} onVerify={session.verifyCode} />;
  if (session.listState === "loading" || session.listState === "idle") return <><Breadcrumb /><ListLoading label="Loading your application…" /></>;
  if (session.listState === "error") return <><Breadcrumb /><ListError title="Couldn't load this application" onRetry={() => void session.reload()} /></>;
  if (!app) {
    return (
      <>
        <Breadcrumb />
        <section className="card dash-empty">
          <h2>Application not found</h2>
          <p>There's no application with this app ID in your account. It may belong to another dashboard account.</p>
          <Link className="btn btn--route dash-empty__button" href="/dashboard">Back to applications</Link>
        </section>
      </>
    );
  }

  const run = async (body: Record<string, unknown>) => {
    session.replace(await session.request<DeveloperApplication>({ ...body, appId }));
  };
  const actions: DetailActions = {
    update: (changes) => run({ operation: "update", ...changes }),
    addOrigin: (origin, environment) => run({ operation: "add-origin", origin, environment }),
    removeOrigin: (origin) => run({ operation: "remove-origin", origin }),
  };
  return <ApplicationDetail key={app.appId} app={app} actions={actions} />;
}

function Breadcrumb() {
  return <nav aria-label="Breadcrumb" className="dash-crumbs"><Link href="/dashboard">Applications</Link></nav>;
}

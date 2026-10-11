"use client";

import dynamic from "next/dynamic";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { type DeveloperApplication } from "./api";
import { useDashboard } from "./session";
import { ApplicationRows, ApplicationsHeader, CreateDialog, ListEmpty, ListError, ListLoading, SignInCard } from "./views";

/** Development-only state previews (`/dashboard?screen=…`); never bundled in production. */
const DevHome = process.env.NODE_ENV !== "production"
  ? dynamic(() => import("./dev-screens").then((module) => module.DevHome), { ssr: false })
  : () => null;

export function DashboardHome({ devScreen }: { devScreen?: string }) {
  if (process.env.NODE_ENV !== "production" && devScreen) return <DevHome screen={devScreen} />;
  return <LiveHome />;
}

function LiveHome() {
  const session = useDashboard();
  const router = useRouter();
  const [creating, setCreating] = useState(false);
  if (session.status === "checking") return null;
  if (session.status === "signedOut") return <SignInCard onSendCode={session.sendCode} onVerify={session.verifyCode} />;

  async function create(name: string, otpLimitPerMinute: number) {
    const app = await session.request<DeveloperApplication>({ operation: "create", name, otpLimitPerMinute });
    session.replace(app);
    router.push(`/dashboard/${app.appId}`);
  }

  const loading = session.listState === "loading" || session.listState === "idle";
  return (
    <>
      <ApplicationsHeader email={session.email} onSignOut={() => void session.signOut()} onCreate={() => setCreating(true)} />
      {loading ? <ListLoading />
        : session.listState === "error" ? <ListError onRetry={() => void session.reload()} />
        : session.applications.length ? <ApplicationRows applications={session.applications} />
        : <ListEmpty onCreate={() => setCreating(true)} />}
      {creating && <CreateDialog onCancel={() => setCreating(false)} onCreate={create} />}
    </>
  );
}

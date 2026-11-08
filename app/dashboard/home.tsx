"use client";

import dynamic from "next/dynamic";
import { useRouter } from "next/navigation";
import { useRef, useState } from "react";
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
  const [signOutError, setSignOutError] = useState<string>();
  const signingOut = useRef(false);
  if (session.status === "checking") return null;
  if (session.status === "signedOut") return <SignInCard onSendCode={session.sendCode} onVerify={session.verifyCode} />;

  async function create(name: string) {
    const app = await session.request<DeveloperApplication>({ operation: "create", name });
    session.replace(app);
    router.push(`/dashboard/${app.appId}`);
  }

  async function signOut() {
    // A second click while the first sign-out is still waiting does nothing.
    if (signingOut.current) return;
    signingOut.current = true;
    setSignOutError(undefined);
    try {
      await session.signOut();
    } catch {
      setSignOutError("Sign-out didn't go through, so you're still signed in. Try again in a moment.");
    } finally {
      signingOut.current = false;
    }
  }

  const loading = session.listState === "loading" || session.listState === "idle";
  return (
    <>
      <ApplicationsHeader email={session.email} signOutError={signOutError} onSignOut={() => void signOut()} onCreate={() => setCreating(true)} />
      {loading ? <ListLoading />
        : session.listState === "error" ? <ListError onRetry={() => void session.reload()} />
        : session.applications.length ? <ApplicationRows applications={session.applications} />
        : <ListEmpty onCreate={() => setCreating(true)} />}
      {creating && <CreateDialog onCancel={() => setCreating(false)} onCreate={create} />}
    </>
  );
}

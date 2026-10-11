"use client";

import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { apiRequest, DashboardApiError, developerRequest, type DeveloperApplication } from "./api";

const SESSION_KEY = "ckb-keyway.developer-session.v2";
const EMAIL_KEY = "ckb-keyway.developer-email.v1";

export type ListState = "idle" | "loading" | "ready" | "error";

type DashboardSession = {
  /** "checking" while a stored session is verified on load. */
  status: "checking" | "signedOut" | "signedIn";
  email?: string;
  token?: string;
  applications: DeveloperApplication[];
  listState: ListState;
  reload: () => Promise<void>;
  sendCode: (email: string) => Promise<string>;
  verifyCode: (email: string, challengeId: string, code: string) => Promise<void>;
  signOut: () => Promise<void>;
  request: <T>(body: Record<string, unknown>) => Promise<T>;
  replace: (application: DeveloperApplication) => void;
};

const Context = createContext<DashboardSession | undefined>(undefined);

export function DashboardProvider({ children }: { children: ReactNode }) {
  const [status, setStatus] = useState<DashboardSession["status"]>("checking");
  const [token, setToken] = useState<string>();
  const [email, setEmail] = useState<string>();
  const [applications, setApplications] = useState<DeveloperApplication[]>([]);
  const [listState, setListState] = useState<ListState>("idle");

  const clear = useCallback(() => {
    localStorage.removeItem(SESSION_KEY);
    localStorage.removeItem(EMAIL_KEY);
    setToken(undefined);
    setEmail(undefined);
    setApplications([]);
    setListState("idle");
    setStatus("signedOut");
  }, []);

  const load = useCallback(async (authToken: string) => {
    setListState("loading");
    try {
      const result = await developerRequest<{ applications: DeveloperApplication[] }>(authToken, { operation: "list" });
      setApplications(result.applications);
      setListState("ready");
    } catch (cause) {
      if (cause instanceof DashboardApiError && cause.status === 401) return clear();
      setListState("error");
    }
  }, [clear]);

  useEffect(() => {
    const stored = localStorage.getItem(SESSION_KEY) ?? undefined;
    if (!stored) { setStatus("signedOut"); return; }
    setToken(stored);
    setEmail(localStorage.getItem(EMAIL_KEY) ?? undefined);
    setStatus("signedIn");
    void load(stored);
  }, [load]);

  // Drop the session as soon as the API stops accepting it.
  useEffect(() => {
    if (!token) return;
    const check = () => void apiRequest("/api/keyway/auth/session", {}, token).catch((cause) => {
      if (cause instanceof DashboardApiError && cause.status === 401) clear();
    });
    const interval = window.setInterval(check, 15 * 60_000);
    window.addEventListener("focus", check);
    return () => { window.clearInterval(interval); window.removeEventListener("focus", check); };
  }, [token, clear]);

  const value = useMemo<DashboardSession>(() => ({
    status,
    email,
    token,
    applications,
    listState,
    reload: () => token ? load(token) : Promise.resolve(),
    sendCode: async (address) => (await apiRequest<{ challengeId: string }>("/api/keyway/auth/send-code", { email: address })).challengeId,
    verifyCode: async (address, challengeId, code) => {
      const { sessionToken } = await apiRequest<{ sessionToken: string }>("/api/keyway/auth/verify-code", { challengeId, code });
      localStorage.setItem(SESSION_KEY, sessionToken);
      localStorage.setItem(EMAIL_KEY, address);
      setToken(sessionToken);
      setEmail(address);
      setStatus("signedIn");
      await load(sessionToken);
    },
    signOut: async () => {
      if (token) await apiRequest("/api/keyway/auth/logout", {}, token).catch(() => undefined);
      clear();
    },
    request: async <T,>(body: Record<string, unknown>) => {
      if (!token) throw new Error("Sign in again to continue");
      try {
        return await developerRequest<T>(token, body);
      } catch (cause) {
        if (cause instanceof DashboardApiError && cause.status === 401) clear();
        throw cause;
      }
    },
    replace: (application) => setApplications((current) => current.some(({ appId }) => appId === application.appId)
      ? current.map((app) => app.appId === application.appId ? application : app)
      : [application, ...current]),
  }), [status, email, token, applications, listState, load, clear]);

  return <Context.Provider value={value}>{children}</Context.Provider>;
}

export function useDashboard(): DashboardSession {
  const value = useContext(Context);
  if (!value) throw new Error("useDashboard must be used inside DashboardProvider");
  return value;
}

"use client";

import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
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
  // Bumped whenever the session changes. A reply to a request from an older session is dropped,
  // so a slow answer for the previous account can't fill in or sign out the next one.
  const generation = useRef(0);

  // Signs this tab out without touching storage, which another tab may already have changed.
  const reset = useCallback(() => {
    generation.current += 1;
    setToken(undefined);
    setEmail(undefined);
    setApplications([]);
    setListState("idle");
    setStatus("signedOut");
  }, []);

  const clear = useCallback(() => {
    localStorage.removeItem(SESSION_KEY);
    localStorage.removeItem(EMAIL_KEY);
    reset();
  }, [reset]);

  const load = useCallback(async (authToken: string) => {
    const started = generation.current;
    setListState("loading");
    try {
      const result = await developerRequest<{ applications: DeveloperApplication[] }>(authToken, { operation: "list" });
      if (started !== generation.current) return;
      setApplications(result.applications);
      setListState("ready");
    } catch (cause) {
      if (started !== generation.current) return;
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
    const check = () => {
      const started = generation.current;
      void apiRequest("/api/keyway/auth/session", {}, token).catch((cause) => {
        if (started === generation.current && cause instanceof DashboardApiError && cause.status === 401) clear();
      });
    };
    // Another tab signed out or in: drop this tab's session rather than keep using one that ended.
    const sync = (event: StorageEvent) => {
      if ((event.key === SESSION_KEY || event.key === null) && localStorage.getItem(SESSION_KEY) !== token) reset();
    };
    const interval = window.setInterval(check, 15 * 60_000);
    window.addEventListener("focus", check);
    window.addEventListener("storage", sync);
    return () => { window.clearInterval(interval); window.removeEventListener("focus", check); window.removeEventListener("storage", sync); };
  }, [token, clear, reset]);

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
      generation.current += 1;
      setToken(sessionToken);
      setEmail(address);
      setStatus("signedIn");
      await load(sessionToken);
    },
    signOut: async () => {
      // Only look signed out once the server has ended the session (a 401 means it already had).
      // Otherwise keep it, so the caller can say sign-out failed. If the session changed while
      // waiting, this sign-out is already done and its reply must not touch the next account.
      const started = generation.current;
      if (token) await apiRequest("/api/keyway/auth/logout", {}, token).catch((cause) => {
        if (started !== generation.current) return;
        if (!(cause instanceof DashboardApiError && cause.status === 401)) throw cause;
      });
      if (started === generation.current) clear();
    },
    request: async <T,>(body: Record<string, unknown>) => {
      if (!token) throw new Error("Sign in again to continue");
      const started = generation.current;
      try {
        const result = await developerRequest<T>(token, body);
        if (started !== generation.current) throw new Error("You signed out before this finished");
        return result;
      } catch (cause) {
        if (started === generation.current && cause instanceof DashboardApiError && cause.status === 401) clear();
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

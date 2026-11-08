import assert from "node:assert/strict";
import test from "node:test";
import { act, createElement } from "react";
import { createRoot, type Root } from "react-dom/client";

// The dashboard session provider runs in a browser. These are the few browser pieces it touches:
// one window for events, one localStorage shared by every "tab", and a node to render into.
class FakeNode {
  nodeType = 1;
  nodeName = "DIV";
  tagName = "DIV";
  namespaceURI = "http://www.w3.org/1999/xhtml";
  childNodes: unknown[] = [];
  style = {};
  ownerDocument: unknown = globalThis.document;
  get firstChild() { return this.childNodes[0] ?? null; }
  appendChild(child: unknown) { this.childNodes.push(child); return child; }
  removeChild(child: unknown) { this.childNodes = this.childNodes.filter((item) => item !== child); return child; }
  addEventListener() {}
  removeEventListener() {}
  setAttribute() {}
  removeAttribute() {}
  getAttribute() { return null; }
}
const events = new EventTarget();
const stored = new Map<string, string>();
class FakeStorageEvent extends Event {
  constructor(type: string, readonly init: { key: string | null }) { super(type); }
  get key() { return this.init.key; }
}
const browser = {
  window: globalThis,
  addEventListener: events.addEventListener.bind(events),
  removeEventListener: events.removeEventListener.bind(events),
  dispatchEvent: events.dispatchEvent.bind(events),
  document: { nodeType: 9, defaultView: globalThis, activeElement: null, documentElement: null, createElement: () => new FakeNode(), addEventListener() {}, removeEventListener() {} },
  localStorage: { getItem: (key: string) => stored.get(key) ?? null, setItem: (key: string, value: string) => void stored.set(key, String(value)), removeItem: (key: string) => void stored.delete(key), clear: () => stored.clear() },
  StorageEvent: FakeStorageEvent,
  HTMLIFrameElement: class {},
  IS_REACT_ACT_ENVIRONMENT: true,
};
for (const [name, value] of Object.entries(browser)) Object.defineProperty(globalThis, name, { value, writable: true, configurable: true });

const { DashboardProvider, useDashboard, useSignOut } = await import("../app/dashboard/session.tsx");
type Session = ReturnType<typeof useDashboard>;
type SignOutButton = ReturnType<typeof useSignOut>;

// Every request waits until the test answers it; nothing leaves the process.
type Call = { path: string; auth?: string; body: Record<string, unknown>; resolve: (response: Response) => void; reject: (error: Error) => void; done: boolean };
let calls: Call[] = [];
globalThis.fetch = (async (url: string, init: RequestInit) => new Promise<Response>((resolve, reject) => {
  const headers = init.headers as Record<string, string>;
  calls.push({ path: new URL(url).pathname, auth: headers.Authorization, body: JSON.parse(String(init.body)), resolve, reject, done: false });
})) as typeof fetch;
function take(path: string, token?: string, operation?: string): Call {
  const call = calls.find((item) => !item.done && item.path === path && (token === undefined || item.auth === `Bearer ${token}`) && (operation === undefined || item.body.operation === operation));
  assert.ok(call, `expected a pending ${path} ${operation ?? ""} request with token ${token}`);
  call.done = true;
  return call;
}
const json = (status: number, body?: unknown) => new Response(body === undefined ? null : JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
const flush = async () => { for (let i = 0; i < 5; i++) await new Promise((resolve) => setTimeout(resolve, 0)); };
const settle = (answer: () => void) => act(async () => { answer(); await flush(); });

const SESSION_KEY = "ckb-keyway.developer-session.v2";
const TOKEN_A = "token-account-a";
const TOKEN_B = "token-account-b";
const app = (appId: string, name: string) => ({ appId, name, disabled: false, otpLimitPerMinute: 5, origins: [], usage: { sent24h: 0, failed24h: 0, rateLimited24h: 0 }, createdAt: "2026-01-01T00:00:00Z", updatedAt: "2026-01-01T00:00:00Z" });
const APP_A = app("app_a", "Account A's app");
const APP_B = app("app_b", "Account B's app");

/** Mounts a dashboard "tab". Tabs share localStorage and window events, as tabs of one origin do. */
const open: Root[] = [];
async function openTab() {
  const tab: { session?: Session; signOutButton?: SignOutButton; root?: Root } = {};
  const Probe = () => { tab.session = useDashboard(); tab.signOutButton = useSignOut(); return null; };
  tab.root = createRoot(new FakeNode() as unknown as Element);
  open.push(tab.root);
  await act(async () => { tab.root!.render(createElement(DashboardProvider, null, createElement(Probe))); });
  return tab as { session: Session; signOutButton: SignOutButton; root: Root };
}
async function fresh(token?: string) {
  calls = [];
  stored.clear();
  if (token) stored.set(SESSION_KEY, token);
  return openTab();
}
const close = (tab: { root: Root }) => act(async () => { open.splice(open.indexOf(tab.root), 1); tab.root.unmount(); });
// A failed assertion skips close(); unmount what's left so the session check timer stops.
test.afterEach(async () => { for (const root of open.splice(0)) await act(async () => root.unmount()); });

async function signInAsA() {
  const tab = await fresh(TOKEN_A);
  await settle(() => take("/api/keyway/developer/apps", TOKEN_A, "list").resolve(json(200, { applications: [APP_A] })));
  return tab;
}

/** A signs out, then B signs in with an email code in the same tab and B's list loads. */
async function switchToB(tab: { session: Session }) {
  let signedOut!: Promise<void>;
  await act(async () => { signedOut = tab.session.signOut(); });
  await settle(() => take("/api/keyway/auth/logout", TOKEN_A).resolve(json(204)));
  await act(async () => { await signedOut; });
  assert.equal(tab.session.status, "signedOut");
  let verified!: Promise<void>;
  await act(async () => { verified = tab.session.verifyCode("b@example.test", "challenge-b", "000000"); });
  await settle(() => take("/api/keyway/auth/verify-code").resolve(json(200, { sessionToken: TOKEN_B })));
  await settle(() => take("/api/keyway/developer/apps", TOKEN_B, "list").resolve(json(200, { applications: [APP_B] })));
  await act(async () => { await verified; });
}
function assertOnlyB(session: Session) {
  assert.equal(session.status, "signedIn");
  assert.equal(session.token, TOKEN_B);
  assert.equal(stored.get(SESSION_KEY), TOKEN_B);
  assert.deepEqual(session.applications.map(({ appId }) => appId), [APP_B.appId]);
}

test("a failed sign-out reports the failure and keeps the session", async () => {
  for (const fail of [(call: Call) => call.resolve(json(503, { error: "Service unavailable" })), (call: Call) => call.reject(new TypeError("fetch failed"))]) {
    const tab = await signInAsA();
    let signedOut!: Promise<void>;
    await act(async () => { signedOut = tab.session.signOut(); signedOut.catch(() => undefined); });
    await settle(() => fail(take("/api/keyway/auth/logout", TOKEN_A)));
    await assert.rejects(signedOut);
    // The server session is still live, so the dashboard must not look signed out.
    assert.equal(tab.session.status, "signedIn");
    assert.equal(tab.session.token, TOKEN_A);
    assert.equal(stored.get(SESSION_KEY), TOKEN_A);
    await close(tab);
  }
});

test("a sign-out the server already treats as signed out still clears", async () => {
  const tab = await signInAsA();
  let signedOut!: Promise<void>;
  await act(async () => { signedOut = tab.session.signOut(); });
  await settle(() => take("/api/keyway/auth/logout", TOKEN_A).resolve(json(401, { error: "Session expired" })));
  await act(async () => { await signedOut; });
  assert.equal(tab.session.status, "signedOut");
  assert.equal(stored.get(SESSION_KEY), undefined);
  await close(tab);
});

test("signing out in one tab signs out every other open tab", async () => {
  const first = await signInAsA();
  const second = await openTab();
  await settle(() => take("/api/keyway/developer/apps", TOKEN_A, "list").resolve(json(200, { applications: [APP_A] })));
  assert.equal(second.session.status, "signedIn");
  let signedOut!: Promise<void>;
  await act(async () => { signedOut = first.session.signOut(); });
  await settle(() => take("/api/keyway/auth/logout", TOKEN_A).resolve(json(204)));
  await act(async () => { await signedOut; });
  // The browser tells the other tabs that the stored session changed.
  await act(async () => { window.dispatchEvent(new StorageEvent("storage", { key: SESSION_KEY })); });
  assert.equal(second.session.status, "signedOut");
  assert.equal(second.session.token, undefined);
  assert.deepEqual(second.session.applications, []);
  await assert.rejects(second.session.request({ operation: "update", appId: APP_A.appId, name: "Changed" }), /Sign in again/);
  await close(first);
  await close(second);
});

test("A's late app list doesn't land in B's dashboard", async () => {
  const tab = await fresh(TOKEN_A);
  const listA = take("/api/keyway/developer/apps", TOKEN_A, "list");
  await switchToB(tab);
  await settle(() => listA.resolve(json(200, { applications: [APP_A] })));
  assertOnlyB(tab.session);
  await close(tab);
});

test("A's late 401 on the app list doesn't sign B out", async () => {
  const tab = await fresh(TOKEN_A);
  const listA = take("/api/keyway/developer/apps", TOKEN_A, "list");
  await switchToB(tab);
  await settle(() => listA.resolve(json(401, { error: "Session expired" })));
  assertOnlyB(tab.session);
  await close(tab);
});

test("A's late 401 on the session check doesn't sign B out", async () => {
  const tab = await signInAsA();
  await act(async () => { window.dispatchEvent(new Event("focus")); });
  const checkA = take("/api/keyway/auth/session", TOKEN_A);
  await switchToB(tab);
  await settle(() => checkA.resolve(json(401, { error: "Session revoked" })));
  assertOnlyB(tab.session);
  await close(tab);
});

test("A's late change, or its 401, doesn't reach B's dashboard", async () => {
  for (const answer of [json(200, { ...APP_A, name: "Renamed by A" }), json(401, { error: "Session revoked" })]) {
    const tab = await signInAsA();
    const sessionA = tab.session;
    // The same shape as the app page: replace(await request(...)).
    const change = (async () => sessionA.replace(await sessionA.request<typeof APP_A>({ operation: "update", appId: APP_A.appId, name: "Renamed by A" })))();
    change.catch(() => undefined);
    const updateA = take("/api/keyway/developer/apps", TOKEN_A, "update");
    await switchToB(tab);
    await settle(() => updateA.resolve(answer));
    await act(async () => { await change.catch(() => undefined); });
    await assert.rejects(change);
    assertOnlyB(tab.session);
    await close(tab);
  }
});

test("A's late reply to a second sign-out doesn't sign B out", async () => {
  for (const late of [json(401, { error: "Session expired" }), json(503, { error: "Service unavailable" })]) {
    const tab = await signInAsA();
    // Sign out clicked twice: both requests carry A's token.
    let first!: Promise<void>;
    let second!: Promise<void>;
    await act(async () => { first = tab.session.signOut(); second = tab.session.signOut(); second.catch(() => undefined); });
    await settle(() => take("/api/keyway/auth/logout", TOKEN_A).resolve(json(204)));
    await act(async () => { await first; });
    let verified!: Promise<void>;
    await act(async () => { verified = tab.session.verifyCode("b@example.test", "challenge-b", "000000"); });
    await settle(() => take("/api/keyway/auth/verify-code").resolve(json(200, { sessionToken: TOKEN_B })));
    await settle(() => take("/api/keyway/developer/apps", TOKEN_B, "list").resolve(json(200, { applications: [APP_B] })));
    await act(async () => { await verified; });
    await settle(() => take("/api/keyway/auth/logout", TOKEN_A).resolve(late));
    // A's session had already ended, so the late reply is neither a sign-out of B nor a failure.
    await act(async () => { await second; });
    assertOnlyB(tab.session);
    await close(tab);
  }
});

test("A's late sign-out in one tab doesn't sign B out in another", async () => {
  const first = await signInAsA();
  const second = await openTab();
  await settle(() => take("/api/keyway/developer/apps", TOKEN_A, "list").resolve(json(200, { applications: [APP_A] })));
  let slow!: Promise<void>;
  await act(async () => { slow = first.session.signOut(); slow.catch(() => undefined); });
  const slowLogout = take("/api/keyway/auth/logout", TOKEN_A);
  await switchToB(second);
  // The browser tells the first tab that the stored session changed.
  await act(async () => { window.dispatchEvent(new StorageEvent("storage", { key: SESSION_KEY })); });
  await settle(() => slowLogout.resolve(json(401, { error: "Session expired" })));
  await act(async () => { await slow; });
  assertOnlyB(second.session);
  await close(first);
  await close(second);
});

test("a failed sign-out's message doesn't carry over to the next sign-in", async () => {
  const tab = await signInAsA();
  let clicked!: Promise<void>;
  await act(async () => { clicked = tab.signOutButton.run(); });
  await settle(() => take("/api/keyway/auth/logout", TOKEN_A).resolve(json(503, { error: "Service unavailable" })));
  await act(async () => { await clicked; });
  assert.match(tab.signOutButton.error ?? "", /still signed in/);
  // The session then ends some other way: here the server stops accepting it.
  await act(async () => { window.dispatchEvent(new Event("focus")); });
  await settle(() => take("/api/keyway/auth/session", TOKEN_A).resolve(json(401, { error: "Session revoked" })));
  assert.equal(tab.session.status, "signedOut");
  let verified!: Promise<void>;
  await act(async () => { verified = tab.session.verifyCode("b@example.test", "challenge-b", "000000"); });
  await settle(() => take("/api/keyway/auth/verify-code").resolve(json(200, { sessionToken: TOKEN_B })));
  await settle(() => take("/api/keyway/developer/apps", TOKEN_B, "list").resolve(json(200, { applications: [APP_B] })));
  await act(async () => { await verified; });
  assertOnlyB(tab.session);
  assert.equal(tab.signOutButton.error, undefined);
  await close(tab);
});

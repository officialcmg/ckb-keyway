"use client";

/**
 * DEVELOPMENT ONLY. Renders the dashboard in each designed state with the boards' example data so it can
 * be compared with the design canvas (`/dashboard?screen=list`, `/dashboard/<appId>?screen=detail`).
 * It is loaded only when NODE_ENV is not "production", so none of this reaches the deployed site.
 */
import type { DeveloperApplication } from "./api";
import { ApplicationDetail, ApplicationRows, ApplicationsHeader, CreateDialog, ListEmpty, ListError, ListLoading, SignInCard, type DetailActions } from "./views";

const app = (appId: string, name: string, origins: DeveloperApplication["origins"], sent: number, disabled = false): DeveloperApplication => ({
  appId, name, disabled, otpLimitPerMinute: 30, origins,
  usage: { sent24h: sent, failed24h: 3, rateLimited24h: 0 },
  createdAt: "2026-10-07T09:00:00.000Z", updatedAt: "2026-10-11T09:00:00.000Z",
});

const ACME = app("keyway_8fK2mQ7xL1pVn4sR9tYc0bWd", "Acme Pay", [
  { origin: "https://acmepay.xyz", environment: "production" },
  { origin: "https://www.acmepay.xyz", environment: "production" },
  { origin: "http://localhost:3000", environment: "development" },
], 142);

const APPS = [
  ACME,
  app("keyway_Qm3tZ0vK9pLx7RcN2sYw5bHe", "Bottle Café POS", [{ origin: "https://pos.bottle.cafe", environment: "production" }], 18),
  app("keyway_a7Hc2Wq9Nn4Ef1Rt8Lk3Vy6P", "Hackathon prototype", [{ origin: "https://a.example", environment: "production" }, { origin: "http://localhost:5173", environment: "development" }], 0, true),
];

const noop = async () => undefined;
const never = () => new Promise<never>(() => undefined);

export function DevHome({ screen }: { screen: string }) {
  if (screen === "signedout") return <SignInCard onSendCode={async () => "dev"} onVerify={noop} />;
  return (
    <>
      <ApplicationsHeader email="dev@acmepay.xyz" onSignOut={() => undefined} onCreate={() => undefined} />
      {screen === "loading" ? <ListLoading />
        : screen === "empty" ? <ListEmpty onCreate={() => undefined} />
        : screen === "error" ? <ListError onRetry={() => undefined} />
        : <ApplicationRows applications={APPS} />}
      {screen === "create" && <CreateDialog initialName="Bottle Café POS" onCancel={() => undefined} onCreate={never} />}
    </>
  );
}

export function DevDetail({ screen }: { screen: string }) {
  const actions: DetailActions = { update: noop, addOrigin: noop, removeOrigin: noop };
  return <ApplicationDetail app={{ ...ACME, disabled: screen === "disabled" }} actions={actions} initialOrigin={screen === "originError" ? "https://acmepay.xyz/checkout" : undefined} />;
}

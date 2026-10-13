import { createRoot } from "react-dom/client";
import * as ccc from "@ckb-ccc/core";
import { KeyWayProvider, useKeyWay, useCkbWallet, useFiber } from "../../src/sdk/react/index";

function Probe() {
  const auth = useKeyWay();
  const account = useCkbWallet();
  const fiber = useFiber();
  Object.assign(window, { probe: { auth, account, fiber } });
  return <pre>{JSON.stringify({ auth: auth.authenticated, wallet: account.status, fiber: fiber.status })}</pre>;
}
const params = new URLSearchParams(location.search);
const root = createRoot(document.getElementById("root")!);
Object.assign(window, { unmount: () => root.unmount(), ccc });
// `?approve` adds an app-side payment confirmation that tests control through window.allowPayments.
const approvals: unknown[] = [];
Object.assign(window, { paymentApprovals: approvals, allowPayments: true });
const approveFiberPayment = params.has("approve")
  ? (preview: unknown) => { approvals.push(preview); return (window as unknown as { allowPayments: boolean }).allowPayments; }
  : undefined;
root.render(<KeyWayProvider appId={params.get("app") ?? undefined} fiberNode={params.has("browser") ? "browser" : "hosted"} autoStartFiber={params.has("auto")} approveFiberPayment={approveFiberPayment}><Probe /></KeyWayProvider>);

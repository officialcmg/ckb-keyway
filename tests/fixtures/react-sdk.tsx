import { createRoot } from "react-dom/client";
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
Object.assign(window, { unmount: () => root.unmount() });
root.render(<KeyWayProvider nodeMode={params.has("browser") ? "browser" : "managed"} autoConnect={params.has("auto")}><Probe /></KeyWayProvider>);

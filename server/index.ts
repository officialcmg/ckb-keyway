import { createServer } from "node:http";
import { nodeRequestHandler } from "../src/server/node-server.ts";
import { startWatchtower } from "../src/server/watchtower.ts";

const port = Number(process.env.PORT ?? 3001);
const server = createServer(nodeRequestHandler());

server.listen(port, "0.0.0.0", () => console.log(`CKB KeyWay API listening on ${port}`));
// The browser-node watchtower (src/server/watchtower.ts) runs here when its fee key is configured.
const stopWatchtower = startWatchtower();
for (const signal of ["SIGTERM", "SIGINT"] as const) {
  process.once(signal, () => {
    server.close();
    void stopWatchtower().finally(() => process.exit(0));
  });
}

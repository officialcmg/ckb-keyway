// Live testnet proof harness for KeyWay's browser-node watchtower (see README.md in this folder).
//
//   DATABASE_URL=postgres://… KEYWAY_WATCHTOWER_FEE_KEY=0x… EVIDENCE=… node --import tsx research/browser-watchtower/relay-and-watch.ts
//
// 1. A JSON-RPC endpoint (127.0.0.1:18300) stands in for the browser page: the victim's FNN 0.9.1 node is started
//    with `--fiber-disable-built-in-watchtower --fiber-standalone-watchtower-rpc-url http://127.0.0.1:18300`, so it
//    sends exactly the calls fiber-wasm sends the in-page bridge (both use fiber-lib's `forward_event_to_client`).
//    Each call goes through the SDK's own filter (`remoteWatchUpdate`, src/sdk/browser/watchtower-remote.ts) and
//    then the API's own parser and store (`parseWatchtowerRequest`/`watchtowerRequest`, src/server/watchtower.ts),
//    for one test user. Only field names are logged, never values.
// 2. The watchtower itself (`startWatchtower`) runs in the same process every KEYWAY_WATCHTOWER_INTERVAL_SECONDS.
import { appendFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { randomUUID } from "node:crypto";
import { remoteWatchUpdate } from "../../src/sdk/browser/watchtower-remote.ts";
import { WATCHTOWER_METHODS, type WatchtowerCall } from "../../src/sdk/browser/watchtower-bridge.ts";
import { parseWatchtowerRequest, startWatchtower, watchtowerRequest } from "../../src/server/watchtower.ts";

const evidence = process.env.EVIDENCE ?? new URL("./.evidence", import.meta.url).pathname;
mkdirSync(evidence, { recursive: true, mode: 0o700 });
const userFile = `${evidence}/user-id`;
if (!existsSync(userFile)) writeFileSync(userFile, randomUUID());
const user = { id: readFileSync(userFile, "utf8").trim() };
const log = (line: string) => {
  const stamped = `${new Date().toISOString().replace("T", " ").slice(0, 19)} ${line}`;
  console.log(stamped);
  appendFileSync(`${evidence}/relay.log`, stamped + "\n");
};

const server = createServer(async (request, response) => {
  const chunks: Buffer[] = [];
  for await (const chunk of request) chunks.push(chunk as Buffer);
  if (request.url === "/sdk") return sdkRequest(request.method ?? "", Buffer.concat(chunks).toString("utf8"), response);
  let body: { id?: unknown; method?: string; params?: unknown } | Array<{ id?: unknown; method?: string; params?: unknown }>;
  try {
    body = JSON.parse(Buffer.concat(chunks).toString("utf8"));
  } catch {
    response.writeHead(400).end();
    return;
  }
  const requests = Array.isArray(body) ? body : [body];
  const replies = [];
  for (const item of requests) {
    const params = (Array.isArray(item.params) ? item.params[0] : item.params) as Record<string, unknown> ?? {};
    try {
      if (!(WATCHTOWER_METHODS as readonly string[]).includes(String(item.method))) throw new Error(`unknown method ${item.method}`);
      const call = { method: item.method, params } as WatchtowerCall;
      const update = remoteWatchUpdate(call);
      const received = Object.keys(params).sort().join(",");
      if (!update) {
        log(`node -> page: ${item.method} {${received}}  (stays on the device; nothing sent to KeyWay)`);
      } else {
        const sent = Object.keys(update).filter((key) => key !== "operation").sort().join(",");
        const result = await watchtowerRequest(user, parseWatchtowerRequest(update as unknown as Record<string, unknown>)) as { channel?: { channelId: string; commitmentNumber: string | null }; stored?: boolean };
        log(`node -> page: ${item.method} {${received}}  -> KeyWay ${update.operation} {${sent}} channel=${result.channel?.channelId} commitment=${result.channel?.commitmentNumber ?? "-"}${result.stored === false ? " (older, ignored)" : ""}`);
      }
      replies.push({ jsonrpc: "2.0", id: item.id, result: null });
    } catch (error) {
      log(`node -> page: ${item.method} FAILED ${error instanceof Error ? error.message : error}`);
      replies.push({ jsonrpc: "2.0", id: item.id, error: { code: -32000, message: String(error) } });
    }
  }
  response.writeHead(200, { "content-type": "application/json" });
  response.end(JSON.stringify(Array.isArray(body) ? replies : replies[0]));
});
/**
 * `/sdk` takes what the browser SDK sends KeyWay's API (`RemoteWatchUpdate`, from browser-page.ts) and handles it
 * with the API's own parser and store. Stands in for POST /api/v1/keyway/watchtower without the session check.
 */
async function sdkRequest(method: string, text: string, response: import("node:http").ServerResponse) {
  const cors = { "access-control-allow-origin": "*", "access-control-allow-headers": "content-type", "cross-origin-resource-policy": "cross-origin" };
  if (method === "OPTIONS") return void response.writeHead(204, cors).end();
  try {
    const update = JSON.parse(text) as Record<string, unknown>;
    const result = await watchtowerRequest(user, parseWatchtowerRequest(update)) as { channel?: { channelId: string; commitmentNumber: string | null }; stored?: boolean };
    const fields = Object.keys(update).filter((key) => key !== "operation").sort().join(",");
    log(`browser SDK -> KeyWay ${update.operation} {${fields}} channel=${result.channel?.channelId} commitment=${result.channel?.commitmentNumber ?? "-"}${result.stored === false ? " (older, ignored)" : ""}`);
    response.writeHead(200, { ...cors, "content-type": "application/json" }).end(JSON.stringify(result));
  } catch (error) {
    log(`browser SDK -> KeyWay FAILED ${error instanceof Error ? error.message : error}`);
    response.writeHead(400, { ...cors, "content-type": "application/json" }).end(JSON.stringify({ error: String(error) }));
  }
}

server.listen(Number(process.env.RELAY_PORT ?? 18300), "127.0.0.1", () => log(`relay listening; test user ${user.id}`));

const stop = startWatchtower();
process.on("SIGTERM", () => { server.close(); void stop().finally(() => process.exit(0)); });

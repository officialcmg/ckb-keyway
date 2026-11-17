import type { IncomingMessage, ServerResponse } from "node:http";
import { isIP } from "node:net";
import { errorCode, handleKeyWayRequest } from "./http.ts";

const BODY_TOO_LARGE = "Request body is too large";

/**
 * Serves KeyWay's web handler from Node's HTTP server. An error that escapes the handler (a request body that can't
 * be read, a header Node accepts and Fetch doesn't) gets a fixed message: its own text can name internal hosts.
 */
export function nodeRequestHandler(handle: (request: Request) => Promise<Response> = handleKeyWayRequest) {
  return async (incoming: IncomingMessage, outgoing: ServerResponse): Promise<void> => {
    const startedAt = Date.now();
    try {
      const request = await webRequest(incoming);
      const response = await handle(request);
      outgoing.writeHead(response.status, Object.fromEntries(response.headers));
      outgoing.end(Buffer.from(await response.arrayBuffer()));
      console.log(`${request.method} ${new URL(request.url).pathname} ${response.status} ${Date.now() - startedAt}ms`);
    } catch (error) {
      const tooLarge = error instanceof Error && error.message === BODY_TOO_LARGE;
      if (!tooLarge) console.error("[keyway] request failed outside the API handler", { code: errorCode(error) });
      if (outgoing.headersSent) { outgoing.destroy(); return; }
      outgoing.writeHead(tooLarge ? 413 : 500, { "Content-Type": "application/json", "Cache-Control": "no-store" });
      outgoing.end(JSON.stringify({ error: tooLarge ? BODY_TOO_LARGE : "KeyWay request failed" }));
    }
  };
}

async function webRequest(incoming: IncomingMessage): Promise<Request> {
  const protocol = incoming.headers["x-forwarded-proto"] ?? "http";
  const host = incoming.headers.host ?? "localhost";
  const headers = new Headers();
  for (const [name, value] of Object.entries(incoming.headers)) {
    if (Array.isArray(value)) value.forEach((item) => headers.append(name, item));
    else if (value !== undefined) headers.set(name, value);
  }
  headers.delete("x-keyway-client-ip");
  const socketIp = incoming.socket.remoteAddress ?? "unknown";
  // Enable only behind Railway's edge. Railway replaces any browser-supplied X-Forwarded-For and sets
  // X-Real-IP to the connecting client; the rightmost forwarded entry is Railway's own edge (verified 2026-10-12).
  const forwarded = headers.get("x-real-ip")?.trim();
  headers.set("x-keyway-client-ip", process.env.KEYWAY_TRUST_PROXY === "railway" && forwarded && isIP(forwarded) ? forwarded : socketIp);
  const method = incoming.method ?? "GET";
  const pathname = incoming.url?.split("?", 1)[0] ?? "/";
  const body = method === "GET" || method === "HEAD" ? undefined : await readBody(
    incoming,
    pathname.endsWith("/keyway/node-backup/save") ? 16_000_000 : pathname.includes("/keyway/auth/") ? 8_192 : 2_000_000,
  );
  return new Request(`${protocol}://${host}${incoming.url ?? "/"}`, { method, headers, body });
}

async function readBody(incoming: IncomingMessage, maximumBytes: number): Promise<ArrayBuffer> {
  const chunks: Buffer[] = [];
  let length = 0;
  for await (const chunk of incoming) {
    const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    length += bytes.length;
    if (length > maximumBytes) throw new Error(BODY_TOO_LARGE);
    chunks.push(bytes);
  }
  const bytes = Buffer.concat(chunks);
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
}

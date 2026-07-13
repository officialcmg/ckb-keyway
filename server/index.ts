import { createServer, type IncomingMessage } from "node:http";
import { handleKeyWayRequest } from "../src/server/http.ts";

const port = Number(process.env.PORT ?? 3001);
const server = createServer(async (incoming, outgoing) => {
  const startedAt = Date.now();
  try {
    const request = await webRequest(incoming);
    const response = await handleKeyWayRequest(request);
    outgoing.writeHead(response.status, Object.fromEntries(response.headers));
    outgoing.end(Buffer.from(await response.arrayBuffer()));
    console.log(`${request.method} ${new URL(request.url).pathname} ${response.status} ${Date.now() - startedAt}ms`);
  } catch (error) {
    const message = error instanceof Error ? error.message : "Request failed";
    outgoing.writeHead(/too large/i.test(message) ? 413 : 500, { "Content-Type": "application/json" });
    outgoing.end(JSON.stringify({ error: message }));
  }
});

server.listen(port, "0.0.0.0", () => console.log(`CKB KeyWay API listening on ${port}`));

async function webRequest(incoming: IncomingMessage): Promise<Request> {
  const protocol = incoming.headers["x-forwarded-proto"] ?? "http";
  const host = incoming.headers.host ?? "localhost";
  const headers = new Headers();
  for (const [name, value] of Object.entries(incoming.headers)) {
    if (Array.isArray(value)) value.forEach((item) => headers.append(name, item));
    else if (value !== undefined) headers.set(name, value);
  }
  const method = incoming.method ?? "GET";
  const body = method === "GET" || method === "HEAD" ? undefined : await readBody(incoming);
  return new Request(`${protocol}://${host}${incoming.url ?? "/"}`, { method, headers, body });
}

async function readBody(incoming: IncomingMessage): Promise<ArrayBuffer> {
  const chunks: Buffer[] = [];
  let length = 0;
  for await (const chunk of incoming) {
    const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    length += bytes.length;
    if (length > 2_000_000) throw new Error("Request body is too large");
    chunks.push(bytes);
  }
  const bytes = Buffer.concat(chunks);
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
}

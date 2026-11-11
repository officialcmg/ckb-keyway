import assert from "node:assert/strict";
import { createServer, connect, type Server, type Socket } from "node:net";
import test from "node:test";
import { database } from "../src/server/database.ts";

// The database client is created once per process, so this file has one of its own.
const target = process.env.KEYWAY_AUTH_TEST_DATABASE_URL;

test("a failed first database connection is tried again on the next call", { skip: !target }, async (t) => {
  Object.assign(process.env, { NODE_ENV: "test" });
  const upstream = new URL(target!);
  // A port with nothing listening yet, as when the API starts before its database; a proxy to the test database
  // listens on it once the database is "up".
  const port = await new Promise<number>((resolve) => {
    const probe = createServer().listen(0, "127.0.0.1", () => {
      const { port } = probe.address() as { port: number };
      probe.close(() => resolve(port));
    });
  });
  const sockets = new Set<Socket>();
  let proxy: Server | undefined;
  t.after(async () => {
    for (const socket of sockets) socket.destroy();
    if (proxy) await new Promise((resolve) => proxy!.close(resolve));
  });
  const url = new URL(target!);
  url.hostname = "127.0.0.1";
  url.port = String(port);
  process.env.DATABASE_URL = url.toString();

  await assert.rejects(database(), /ECONNREFUSED/);
  proxy = createServer((client) => {
    const server = connect(Number(upstream.port || 5432), upstream.hostname);
    for (const socket of [client, server]) {
      sockets.add(socket);
      socket.on("close", () => sockets.delete(socket));
    }
    client.pipe(server).pipe(client);
    client.on("error", () => server.destroy());
    server.on("error", () => client.destroy());
  });
  await new Promise<void>((resolve) => proxy!.listen(port, "127.0.0.1", resolve));
  const sql = await database();
  const [row] = await sql<Array<{ one: number }>>`select 1 as one`;
  assert.equal(row.one, 1);
  await sql.end({ timeout: 0 });
});

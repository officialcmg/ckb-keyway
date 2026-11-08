import assert from "node:assert/strict";
import test from "node:test";
import { backUpBeforeLogout, createStoppedNodes, restoreBeforeStart, stopBeforeLogout } from "../src/sdk/browser/node-migration.ts";
import { createRemoteWatchtower } from "../src/sdk/browser/watchtower-remote.ts";

const payload = {
  formatVersion: 1 as const,
  databasePrefix: "/wasm-wallet",
  salt: "salt",
  iv: "iv",
  ciphertext: "ciphertext",
  digest: "ab".repeat(32),
};

test("backs up before releasing ownership and clears temporary key bytes", async () => {
  const order: string[] = [];
  const key = new Uint8Array(32).fill(7);
  await backUpBeforeLogout({
    loadFiberKey: async () => key,
    stopNode: async () => { order.push("stop"); },
    createBackup: async () => { order.push("encrypt"); return payload; },
    saveBackup: async () => { order.push("upload"); return { digest: payload.digest }; },
    releaseOwnership: async () => { order.push("release"); },
  });
  assert.deepEqual(order, ["stop", "encrypt", "upload", "release"]);
  assert.deepEqual(key, new Uint8Array(32));
});

test("does not release ownership when backup upload fails", async () => {
  let released = false;
  const key = new Uint8Array(32).fill(7);
  await assert.rejects(backUpBeforeLogout({
    loadFiberKey: async () => key,
    stopNode: async () => undefined,
    createBackup: async () => payload,
    saveBackup: async () => { throw new Error("upload failed"); },
    releaseOwnership: async () => { released = true; },
  }), /upload failed/);
  assert.equal(released, false);
  assert.deepEqual(key, new Uint8Array(32));
});

for (const failure of ["fails", "hangs"] as const) {
  test(`does not back up or release ownership while a revocation that ${failure === "fails" ? "failed to send" : "is stuck"} hasn't reached KeyWay's watchtower`, async () => {
    let reachable = false;
    const remote = createRemoteWatchtower({
      send: async () => {
        if (reachable) return;
        if (failure === "hangs") await new Promise(() => undefined);
        throw Object.assign(new Error("KeyWay request failed"), { status: 500 });
      },
      retryMs: 60_000,
      sendTimeoutMs: 100,
      log: { info: () => undefined, warn: () => undefined },
    });
    const order: string[] = [];
    const key = new Uint8Array(32).fill(7);
    const logout = () => backUpBeforeLogout({
      loadFiberKey: async () => key,
      stopNode: async () => {
        order.push("stop");
        // The drained bridge hands over the peer's last revocation.
        remote.enqueue({ operation: "revoke", channelId: `0x${"ab".repeat(32)}`, revocation: { commitment_number: "0x5", aggregated_signature: "0x", output: "0x", output_data: "0x" } });
      },
      flushWatchtower: () => remote.deliver(500),
      createBackup: async () => { order.push("encrypt"); return payload; },
      saveBackup: async () => { order.push("upload"); return { digest: payload.digest }; },
      releaseOwnership: async () => { order.push("release"); },
    });
    try {
      await assert.rejects(logout(), /watchtower/);
      assert.deepEqual(order, ["stop"], "no backup and the device is kept");
      assert.deepEqual(key, new Uint8Array(32));
      reachable = true;
      order.length = 0;
      await logout();
      assert.deepEqual(order, ["stop", "encrypt", "upload", "release"]);
      assert.equal(remote.pending(), 0);
    } finally {
      remote.stop();
    }
  });
}

// Stop Fiber (or an SDK app's stop()) and then a logout: the node no longer holds the device, so there is no backup,
// but the peer's last revocation, queued by the stop, failed to send and is still being retried.
test("a logout after a stop fails until the revocation the stop left queued reaches KeyWay's watchtower", async () => {
  let reachable = false;
  const remote = createRemoteWatchtower({
    send: async () => {
      if (!reachable) throw Object.assign(new Error("KeyWay request failed"), { status: 502 });
    },
    retryMs: 60_000,
    log: { info: () => undefined, warn: () => undefined },
  });
  const stops: string[] = [];
  // The stopped node's own logout: stopForLogout without a device lease.
  const keyway = {
    stopForLogout: () => stopBeforeLogout({ stop: async () => { stops.push("stop"); }, flushWatchtower: () => remote.deliver(500) }),
  };
  const stopped = createStoppedNodes<typeof keyway>();
  try {
    remote.enqueue({ operation: "revoke", channelId: `0x${"ab".repeat(32)}`, revocation: { commitment_number: "0x5", aggregated_signature: "0x", output: "0x", output_data: "0x" } });
    stopped.add(keyway);
    await assert.rejects(keyway.stopForLogout(), /watchtower/, "an SDK app's stop() then stopForLogout()");
    await assert.rejects(stopped.logout(), /watchtower/, "the provider's Stop Fiber then logout");
    assert.equal(remote.pending(), 1);
    reachable = true;
    await stopped.logout();
    assert.equal(remote.pending(), 0);
    // Delivered: a later logout has nothing more to do with that node.
    stops.length = 0;
    await stopped.logout();
    assert.deepEqual(stops, []);
  } finally {
    remote.stop();
  }
});

test("confirms a restore only after import succeeds", async () => {
  const order: string[] = [];
  const key = new Uint8Array(32).fill(9);
  await restoreBeforeStart({
    loadFiberKey: async () => key,
    loadBackup: async () => ({ ...payload, generation: 3 }),
    restoreBackup: async () => { order.push("restore"); },
    confirmRestore: async (generation) => { order.push(`confirm-${generation}`); },
  });
  assert.deepEqual(order, ["restore", "confirm-3"]);
  assert.deepEqual(key, new Uint8Array(32));
});

test("does not consume a backup when IndexedDB restore fails", async () => {
  let confirmed = false;
  await assert.rejects(restoreBeforeStart({
    loadFiberKey: async () => new Uint8Array(32),
    loadBackup: async () => ({ ...payload, generation: 3 }),
    restoreBackup: async () => { throw new Error("restore failed"); },
    confirmRestore: async () => { confirmed = true; },
  }), /restore failed/);
  assert.equal(confirmed, false);
});

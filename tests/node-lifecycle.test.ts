import assert from "node:assert/strict";
import test from "node:test";
import { createNodeLifecycle } from "../src/sdk/browser/node-lifecycle.ts";

const tick = () => new Promise((resolve) => setTimeout(resolve, 0));

/**
 * A fake browser node whose start() resolves only when the test says so, the way @fiber-pay/sdk's does while the
 * key is still unlocking, so a stop can overtake it. While running it can send watchtower calls over the bridge.
 */
function harness() {
  const log: string[] = [];
  const stored: string[] = [];
  const dropped: string[] = [];
  let bridgeOpen = false;
  let running = false;
  let finishStart: (() => void) | undefined;
  let claimFails: Error | undefined;
  let startFails: Error | undefined;
  let holdClaim: Promise<void> | undefined;
  const node = {
    get isRunning() { return running; },
    start() {
      log.push("node.start");
      if (startFails) return Promise.reject(startFails);
      return new Promise<string>((resolve) => {
        finishStart = () => { running = true; log.push("node.up"); resolve("info"); };
      });
    },
    async stop() { log.push(running ? "node.stop" : "node.stop (not running)"); running = false; },
    async nodeInfo() { return "info"; },
  };
  const send = (call: string) => {
    if (!running) return;
    (bridgeOpen ? stored : dropped).push(call);
  };
  const lifecycle = createNodeLifecycle({
    node,
    async claim() {
      log.push("claim");
      await holdClaim;
      if (claimFails) throw claimFails;
    },
    openBridge() { bridgeOpen = true; log.push("bridge.open"); },
    async closeBridge() {
      if (!bridgeOpen) return;
      await tick();
      bridgeOpen = false;
      log.push("bridge.drained");
    },
    afterStart() { log.push("timers.start"); },
    async stopTimers() { log.push("timers.stop"); },
    async release() { log.push(bridgeOpen ? "release (bridge still open)" : "release"); },
    overtaken: () => new Error("The Fiber node was stopped while it was starting"),
  });
  return {
    log, stored, dropped, lifecycle, send,
    finishStart: () => finishStart!(),
    startPending: () => finishStart !== undefined,
    failClaim: (error: Error) => { claimFails = error; },
    failStart: (error: Error) => { startFails = error; },
    /** Makes claim() wait until the returned function is called. */
    deferClaim: () => { let finish!: () => void; holdClaim = new Promise((resolve) => { finish = resolve; }); return () => { log.push("claimed"); finish(); }; },
  };
}

async function until(condition: () => boolean) {
  for (let tries = 0; !condition() && tries < 100; tries++) await tick();
  assert.ok(condition(), "timed out");
}

test("a stop that overtakes a start keeps the bridge open until that start has stopped its node, then drains it", async () => {
  const h = harness();
  const started = h.lifecycle.start();
  await until(h.startPending);
  let stopped = false;
  const stopping = h.lifecycle.stop().then(() => { stopped = true; });
  await tick();
  assert.equal(stopped, false, "stop returned while the overtaken start could still bring the node up");

  // The node comes up after the stop and sends settlement data before the start notices and stops it.
  h.finishStart();
  h.send("update_local_settlement");
  await assert.rejects(started, /stopped while it was starting/);
  await stopping;

  assert.deepEqual(h.stored, ["update_local_settlement"]);
  assert.deepEqual(h.dropped, []);
  assert.deepEqual(h.log, [
    "claim", "bridge.open", "node.start",
    "timers.stop", "node.stop (not running)",
    "node.up", "node.stop",
    "bridge.drained", "release",
  ]);
});

test("a logout during a start backs up only after the overtaken node stopped and the bridge drained", async () => {
  const h = harness();
  const started = h.lifecycle.start();
  await until(h.startPending);
  const loggingOut = h.lifecycle.logout(async (steps) => {
    h.log.push("backup.load-key");
    await steps.stopNodeAndDrain();
    h.log.push(`backup.create (${h.stored.length} stored)`);
    await steps.releaseGuards();
  });
  await tick();
  h.finishStart();
  h.send("update_revocation");
  await assert.rejects(started, /stopped while it was starting/);
  await loggingOut;

  assert.deepEqual(h.dropped, []);
  assert.deepEqual(h.log, [
    "claim", "bridge.open", "node.start",
    "timers.stop",
    "node.up", "node.stop",
    "backup.load-key", "node.stop (not running)", "bridge.drained",
    "backup.create (1 stored)",
    "release",
  ]);
});

test("a stop while the device is being claimed keeps the node down, and lets go of the device once", async () => {
  const h = harness();
  const started = h.lifecycle.start();
  const stopping = h.lifecycle.stop();
  await assert.rejects(started, /stopped while it was starting/);
  await stopping;
  assert.deepEqual(h.log, ["timers.stop", "node.stop (not running)", "release"]);
});

test("a stop while the claim is still pending waits for it, never starts the node, and lets go of the device once", async () => {
  const h = harness();
  const finishClaim = h.deferClaim();
  const started = h.lifecycle.start();
  await until(() => h.log.includes("claim"));
  let stopped = false;
  const stopping = h.lifecycle.stop().then(() => { stopped = true; });
  await tick();
  await tick();
  assert.equal(stopped, false, "stop returned while the claim was still pending");
  finishClaim();
  await assert.rejects(started, /stopped while it was starting/);
  await stopping;
  assert.equal(h.log.includes("node.start"), false);
  assert.equal(h.log.filter((entry) => entry.startsWith("release")).length, 1);
  assert.deepEqual(h.log, ["claim", "timers.stop", "node.stop (not running)", "claimed", "release"]);
});

test("starts don't race: a second call joins the first, and a start after a stop waits for it", async () => {
  const h = harness();
  const first = h.lifecycle.start();
  const second = h.lifecycle.start();
  assert.equal(first, second);
  await until(h.startPending);
  h.finishStart();
  assert.equal(await first, "info");

  const stopping = h.lifecycle.stop();
  const again = h.lifecycle.start();
  await stopping;
  await until(() => h.log.filter((entry) => entry === "node.start").length === 2);
  assert.ok(h.log.lastIndexOf("claim") > h.log.lastIndexOf("release"), `the new start claimed the device before the stop let go of it: ${h.log.join(", ")}`);
  h.finishStart();
  assert.equal(await again, "info");
});

test("a start that fails on its own lets go of the device, after draining the bridge once it was open", async () => {
  const claimed = harness();
  claimed.failClaim(new Error("lease refused"));
  await assert.rejects(claimed.lifecycle.start(), /lease refused/);
  assert.deepEqual(claimed.log, ["claim", "release"]);

  const started = harness();
  started.failStart(new Error("wasm failed"));
  await assert.rejects(started.lifecycle.start(), /wasm failed/);
  assert.deepEqual(started.log, ["claim", "bridge.open", "node.start", "bridge.drained", "release"]);
});

test("a start retried as soon as the last one failed starts again", async () => {
  const h = harness();
  h.failClaim(new Error("lease refused"));
  const retried = h.lifecycle.start().catch(() => { h.failClaim(undefined as unknown as Error); return h.lifecycle.start(); });
  await until(h.startPending);
  h.finishStart();
  assert.equal(await retried, "info");
  assert.equal(h.log.filter((entry) => entry === "claim").length, 2);
});

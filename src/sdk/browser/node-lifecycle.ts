/**
 * Starting and stopping the browser Fiber node, and the order the watchtower bridge closes in.
 *
 * @fiber-pay/sdk's stop() doesn't cancel a start that is still unlocking the key, so a node can come up after a
 * stop (or a logout) has begun. Until that overtaken node has stopped again it can still send watchtower events
 * (new channels, revocations, settlement data), so the bridge that stores them stays open until then. Only after
 * that does the bridge drain, and only after the drain does the store close or a logout backup get taken.
 */

/** The parts of the browser node the lifecycle drives. createKeyWay supplies the real ones. */
export type NodeLifecycleParts<Info> = {
  node: { readonly isRunning: boolean; start(): Promise<Info>; stop(): Promise<void>; nodeInfo(): Promise<Info> };
  /** Claims the device and its lease, restoring a node backup when one is due. */
  claim(): Promise<void>;
  /** Opens the watchtower bridge, and whatever else listens while the node runs. A no-op while it is open. */
  openBridge(): void;
  /** Stops listening for watchtower calls and finishes storing the ones already received. */
  closeBridge(): Promise<void>;
  /** Starts what needs a running node (the sweep and watchtower timers). */
  afterStart(): void;
  /** Stops those timers and waits for a pass in progress. */
  stopTimers(): Promise<void>;
  /** Lets go of the device once the bridge has drained: closes the store and releases the lease and lock. */
  release(): Promise<void>;
  /** The error a start throws when a stop overtook it. */
  overtaken(): Error;
};

/** What a logout does between stopping the timers and letting go of the device. */
export type LogoutSteps = {
  /** Stops the node and drains the bridge, so the store holds every watchtower call before a backup reads it. */
  stopNodeAndDrain(): Promise<void>;
  /** Lets go of the device (after stopNodeAndDrain). */
  releaseGuards(): Promise<void>;
  /** A plain stop, for when there is nothing to back up. */
  stop(): Promise<void>;
};

export function createNodeLifecycle<Info>(parts: NodeLifecycleParts<Info>) {
  /** Bumped by every stop, so a start that a stop overtook (e.g. while the key was loading) can undo itself. */
  let generation = 0;
  /** The start in progress. `settled` settles once it has finished, or undone itself (stopped its node). */
  let starting: { generation: number; result: Promise<Info>; settled: Promise<void> } | undefined;
  /** The stop (or logout) in progress. A start waits for it, so the two never claim and release at once. */
  let stopping: Promise<void> | undefined;
  /** Holds the device (claimed, not yet released): true from a claim until the release after the bridge drains. */
  let claimed = false;

  async function run(startedAt: number): Promise<Info> {
    const overtaken = () => startedAt !== generation;
    // A logout that failed before letting go of the device (KeyWay unreachable) left it claimed: a start then brings
    // the node back on the same claim, and a failed one keeps it, so the next logout can still back up before it
    // lets go.
    const resumed = claimed;
    try {
      // Stopped while waiting, or while claiming: don't bring the node up at all.
      if (overtaken()) throw parts.overtaken();
      if (!resumed) {
        claimed = true;
        await parts.claim();
      }
      if (overtaken()) throw parts.overtaken();
      parts.openBridge();
      const info = await parts.node.start();
      if (overtaken()) {
        // Stop it again rather than leave it (and its timers) running without a lease. The bridge is still open,
        // so anything it sent before it stopped is stored.
        await parts.node.stop().catch(() => undefined);
        throw parts.overtaken();
      }
      parts.afterStart();
      return info;
    } catch (error) {
      // The stop that overtook this start lets go of the device itself, once this start has settled.
      if (!overtaken() && !resumed) await releaseGuards();
      throw error;
    }
  }

  function start(): Promise<Info> {
    // A running node is the answer, unless a stop is about to take it down: then start again after it.
    if (parts.node.isRunning && !stopping) return parts.node.nodeInfo();
    // A second call joins the start in progress rather than race it for the device.
    if (starting && starting.generation === generation) return starting.result;
    const startedAt = generation;
    const before = Promise.all([starting?.settled, stopping]);
    const result = before.then(() => run(startedAt));
    // Cleared by handlers on `result` itself, so a caller that retries as soon as it sees the outcome starts afresh.
    const clear = () => { if (starting === entry) starting = undefined; };
    const entry: { generation: number; result: Promise<Info>; settled: Promise<void> } = { generation: startedAt, result, settled: result.then(clear, clear) };
    starting = entry;
    return result;
  }

  /** Drains the bridge, then lets go of the device. */
  async function releaseGuards() {
    await parts.closeBridge();
    claimed = false;
    await parts.release();
  }

  /** Runs a stop or logout: it overtakes the start in progress and waits for it, and later starts wait for it. */
  function stopping_<T>(work: (overtakenStart: Promise<void>) => Promise<T>): Promise<T> {
    generation++;
    const overtakenStart = starting?.settled ?? Promise.resolve();
    const previous = stopping;
    const done = (async () => {
      await previous;
      return work(overtakenStart);
    })();
    const clear = () => { if (stopping === settled) stopping = undefined; };
    const settled: Promise<void> = done.then(clear, clear);
    stopping = settled;
    return done;
  }

  async function stopNow(overtakenStart: Promise<void>) {
    await parts.stopTimers();
    try {
      await parts.node.stop();
    } finally {
      // An overtaken start may still bring its node up and stop it again. Its watchtower calls keep reaching the
      // store until then; only after that does the bridge drain and the store close.
      await overtakenStart;
      await releaseGuards();
    }
  }

  function stop(): Promise<void> {
    return stopping_(stopNow);
  }

  /**
   * A logout: stops the timers, waits for an overtaken start to stop its node, then hands `backUp` the steps that
   * stop the node, drain the bridge and let go of the device, in that order. One that fails with the node still up
   * starts its timers again.
   */
  function logout<T>(backUp: (steps: LogoutSteps) => Promise<T>): Promise<T> {
    return stopping_(async (overtakenStart) => {
      await parts.stopTimers();
      await overtakenStart;
      try {
        return await backUp({
          stopNodeAndDrain: async () => {
            await parts.node.stop();
            await parts.closeBridge();
          },
          releaseGuards,
          stop: () => stopNow(Promise.resolve()),
        });
      } catch (error) {
        if (parts.node.isRunning) parts.afterStart();
        throw error;
      }
    });
  }

  return {
    start,
    stop,
    logout,
    /** Whether this node still holds the device: after a logout, only when the logout failed before letting go. */
    holdsDevice: () => claimed,
  };
}

/**
 * The browser node's WASM instance, with Fiber's own contract cells in its config.
 *
 * @fiber-pay/sdk 0.2.7 lists a ckb_auth cell dep (0x5a528876…:0) for the funding and commitment locks that
 * doesn't exist on CKB testnet. Transactions the browser node builds itself, such as a force-close
 * commitment, then fail with "TransactionFailedToResolve" and never reach the chain. Fiber 0.9.1's testnet
 * config uses 0x12c569a2…:0, which is live, so KeyWay swaps it in before the node starts.
 */
type FiberWasmInstance = {
  start(config: string, fiberKeyPair: Uint8Array, ckbSecretKey?: Uint8Array, chainSpec?: string, logLevel?: "trace" | "debug" | "info" | "error", databasePrefix?: string): Promise<void>;
  stop(): Promise<void>;
  invokeCommand(name: string, args?: unknown[]): Promise<unknown>;
};

const CKB_AUTH_CELL = {
  wrong: "0x5a5288769cecde6451cb5d301416c297a6da43dc3ac2f3253542b4082478b19b",
  testnet: "0x12c569a258dd9c5bd99f632bb8314b1263b90921ba31496467580d6b79dd14a7",
};

/** Points the funding and commitment locks at the ckb_auth cell from Fiber's own testnet config. */
export function withFiberContracts(config: string, network: "testnet" | "mainnet"): string {
  if (network !== "testnet") return config;
  return config.replaceAll(CKB_AUTH_CELL.wrong, CKB_AUTH_CELL.testnet);
}

/** A WASM factory for FiberBrowserNode that loads fiber-js on start and fixes its config first. */
export function fiberWasmFactory(network: "testnet" | "mainnet"): () => FiberWasmInstance {
  return () => {
    let fiber: FiberWasmInstance | undefined;
    return {
      async start(config, ...rest) {
        const module = await import("@nervosnetwork/fiber-js") as { Fiber?: new () => FiberWasmInstance; default?: { Fiber?: new () => FiberWasmInstance } };
        const Fiber = module.Fiber ?? module.default?.Fiber;
        if (!Fiber) throw new Error("Could not load Fiber's browser node");
        fiber = new Fiber();
        await fiber.start(withFiberContracts(config, network), ...rest);
      },
      async stop() {
        await fiber?.stop();
        fiber = undefined;
      },
      invokeCommand(name, args) {
        if (!fiber) return Promise.reject(new Error("The browser node isn't running"));
        return fiber.invokeCommand(name, args);
      },
    };
  };
}

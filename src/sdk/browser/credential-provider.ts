import type { CredentialProvider } from "@fiber-pay/sdk/browser";
import { deriveSettlementKey } from "./settlement-key";

export type FiberKeyLoader = () => Promise<Uint8Array>;

export class KeyWayCredentialProvider implements CredentialProvider {
  #fiberKey?: Uint8Array;
  private readonly identifier: string;
  private readonly loadFiberKey: FiberKeyLoader;

  constructor(identifier: string, loadFiberKey: FiberKeyLoader) {
    if (!identifier) throw new Error("Credential identifier is required");
    this.identifier = identifier;
    this.loadFiberKey = loadFiberKey;
  }

  async unlock() {
    const key = await this.loadFiberKey();
    if (key.length !== 32) throw new Error("Fiber key must be exactly 32 bytes");
    this.#fiberKey = new Uint8Array(key);
  }

  async getFiberKeyPair() {
    if (!this.#fiberKey) throw new Error("KeyWay credentials are locked");
    return new Uint8Array(this.#fiberKey);
  }

  /** The node's settlement key, derived from the Fiber key so force-closed funds stay recoverable. */
  async getCkbSecretKey() {
    if (!this.#fiberKey) throw new Error("KeyWay credentials are locked");
    return deriveSettlementKey(this.#fiberKey);
  }

  async lock() {
    this.#fiberKey?.fill(0);
    this.#fiberKey = undefined;
  }

  isUnlocked() {
    return this.#fiberKey !== undefined;
  }

  getIdentifier() {
    return this.identifier;
  }
}

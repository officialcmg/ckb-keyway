export function managedUserId(userId: string): string;
export function requireClosedChannels(channels: unknown): void;
export function purgeRetiredUser(userId: string, roots?: { dataRoot?: string; backupRoot?: string; retiredRoot?: string }): Promise<{ purged: boolean; userId: string }>;
export function authorizationMatches(header: string | undefined, token: string): boolean;
export function createCkbKey(path: string): Promise<void>;
export function requireCleanRestore(dataDir: string): Promise<void>;
export function withUserOperation<T>(userId: string, operation: () => Promise<T>): Promise<T>;
export function completeDatabaseOperation<T>(operation: () => Promise<T>, resume: () => Promise<void>): Promise<T>;
export function waitForExit(child: import("node:child_process").ChildProcess, timeout?: number): Promise<void>;
export function managedDataDir(userId: string): string;
export function managedBackupDir(userId: string): string;
export function snapshotDigest(directory: string): Promise<string>;
export function listSnapshots(input: {
  userId: string;
  root?: string;
}): Promise<Array<{ name: string; createdAt: string; bytes: number; digest: string }>>;
export function createSnapshot(input: {
  userId: string;
  dataDir?: string;
  root?: string;
  limitBytes?: number;
  keep?: number;
  encryptionKey?: Buffer;
}): Promise<{ name: string; createdAt: string; bytes: number; digest: string }>;
export function restoreSnapshot(input: {
  userId: string;
  dataDir?: string;
  root?: string;
  name: string;
  encryptionKey?: Buffer;
}): Promise<{ restored: boolean; name: string; digest: string }>;

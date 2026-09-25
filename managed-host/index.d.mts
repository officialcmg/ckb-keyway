export function managedUserId(userId: string): string;
export function authorizationMatches(header: string | undefined, token: string): boolean;
export function createCkbKey(path: string): Promise<void>;
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
}): Promise<{ name: string; createdAt: string; bytes: number; digest: string }>;
export function restoreSnapshot(input: {
  userId: string;
  dataDir?: string;
  root?: string;
  name: string;
}): Promise<{ restored: boolean; name: string; digest: string }>;

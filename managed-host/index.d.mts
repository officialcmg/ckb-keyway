export function managedUserId(userId: string): string;
export function authorizationMatches(header: string | undefined, token: string): boolean;
export function createCkbKey(path: string): Promise<void>;

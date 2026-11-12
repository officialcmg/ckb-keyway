/** A KeyWay account in one scope; `sessionId` is the session the request came with, when there is one. */
export type User = { id: string; scopeId?: string; sessionId?: string };

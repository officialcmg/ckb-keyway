import type { getAdapter } from "better-auth/db/adapter";

type Adapter = Awaited<ReturnType<typeof getAdapter>>;

// Only verification records are namespaced. Authentication users stay private;
// public wallet accounts and sessions are separately bound to the application.
// `challenge` names the login challenge being sent or checked, so each one keeps its own code record.
export function scopedAuthAdapter(adapter: Adapter, scopeId: string, challenge: () => string | undefined = () => undefined): Adapter {
  if (!scopeId) throw new Error("Authentication scope is required");
  return new Proxy(adapter, {
    get(target, property, receiver) {
      const operation = Reflect.get(target, property, receiver);
      if (typeof operation !== "function") return operation;
      if (property === "transaction") return (callback: (transaction: Adapter) => unknown) =>
        operation.call(target, (transaction: Adapter) => callback(scopedAuthAdapter(transaction, scopeId, challenge)));
      return async (input: Record<string, unknown>) => {
        if (input.model !== "verification") return operation.call(target, input);
        const scopePrefix = `keyway:${scopeId}:`;
        const challengeId = challenge();
        const challengePrefix = challengeId ? `${scopePrefix}${challengeId}:` : undefined;
        const where = (input.where ?? []) as Array<Record<string, unknown>>;
        // Calls that name an identifier reach only the current challenge's code. Others (Better Auth's cleanup of
        // expired codes, or a lookup by row id) cover the whole scope, so expired codes of every challenge are removed.
        const named = where.some((clause) => clause.field === "identifier")
          || ["data", "update", "set"].some((field) => (input[field] as Record<string, unknown> | undefined)?.identifier !== undefined);
        const prefix = named && challengePrefix ? challengePrefix : scopePrefix;
        const scoped = { ...input };
        for (const field of ["data", "update", "set"]) {
          const data = input[field] as Record<string, unknown> | undefined;
          if (data?.identifier !== undefined) scoped[field] = { ...data, identifier: `${prefix}${data.identifier}` };
        }
        scoped.where = where.map((clause) => clause.field === "identifier"
          ? { ...clause, value: Array.isArray(clause.value) ? clause.value.map((value) => `${prefix}${value}`) : `${prefix}${clause.value}` }
          : clause);
        if (property !== "create") {
          (scoped.where as Array<unknown>).push({ field: "identifier", operator: "starts_with", value: prefix, connector: "AND" });
        }
        const result = await operation.call(target, scoped);
        const unprefix = (row: unknown) => {
          if (!row || typeof row !== "object") return row;
          const value = row as Record<string, unknown>;
          if (typeof value.identifier !== "string") return row;
          if (!value.identifier.startsWith(prefix)) throw new Error("Verification scope mismatch");
          const strip = challengePrefix && value.identifier.startsWith(challengePrefix) ? challengePrefix : prefix;
          return { ...value, identifier: value.identifier.slice(strip.length) };
        };
        return Array.isArray(result) ? result.map(unprefix) : unprefix(result);
      };
    },
  });
}

import type { getAdapter } from "better-auth/db/adapter";

type Adapter = Awaited<ReturnType<typeof getAdapter>>;

// Only verification records are namespaced. Authentication users stay private;
// public wallet accounts and sessions are separately bound to the application.
export function scopedAuthAdapter(adapter: Adapter, scopeId: string): Adapter {
  if (!scopeId) throw new Error("Authentication scope is required");
  const prefix = `keyway:${scopeId}:`;
  return new Proxy(adapter, {
    get(target, property, receiver) {
      const operation = Reflect.get(target, property, receiver);
      if (typeof operation !== "function") return operation;
      if (property === "transaction") return (callback: (transaction: Adapter) => unknown) =>
        operation.call(target, (transaction: Adapter) => callback(scopedAuthAdapter(transaction, scopeId)));
      return async (input: Record<string, unknown>) => {
        if (input.model !== "verification") return operation.call(target, input);
        const scoped = { ...input };
        for (const field of ["data", "update", "set"]) {
          const data = input[field] as Record<string, unknown> | undefined;
          if (data?.identifier !== undefined) scoped[field] = { ...data, identifier: `${prefix}${data.identifier}` };
        }
        const where = (input.where ?? []) as Array<Record<string, unknown>>;
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
          return { ...value, identifier: value.identifier.slice(prefix.length) };
        };
        return Array.isArray(result) ? result.map(unprefix) : unprefix(result);
      };
    },
  });
}

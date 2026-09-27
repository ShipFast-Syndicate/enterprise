// Alpha Bros enterprise layer — database errors without their SQL.
//
// A query that fails through a SQL adapter surfaces as an error carrying the
// statement and its parameter values: drizzle's `DrizzleQueryError` has them
// in its message (`Failed query: … params: …`) and as `query` / `params`
// properties. better-auth logs whatever error an endpoint or hook throws —
// through the auth logger, and again through `console.error` in the router —
// so every failed query put the SQL and the values bound to it (ids, e-mail
// addresses, audit metadata) in the product's logs. A plugin cannot replace
// the router's error handler, so the guard sits where every query passes:
// `withDatabaseErrorRedaction` wraps the auth adapter (installed by
// `enterpriseGate`, `./gate.ts`), and an error that carries a query leaves it
// as a `DatabaseQueryError` with no statement, no parameters and no cause.
// What stays is what an operator acts on: the model and adapter method, the
// driver's error code (also what unique-violation checks read — ours in
// `./audit/chain.ts` and upstream's), and a missing table/column hint, which
// names only identifiers.
//
// An error carries a query when it (or its `cause` chain) has a `query`,
// `sql` or `params` property, or a "Failed query" message. Every other error —
// `APIError`s, the secrets wrapper's own errors, better-auth's own adapter
// errors (schema mismatch, an empty `incrementOne`) — passes through
// unchanged, message included.

import { isAPIError } from "better-auth/api";
import type { AuthContext } from "better-auth";

type Adapter = AuthContext["adapter"];

const CODE_FIELDS = ["code", "errcode", "errno", "number"] as const;

/** A failed query, as the enterprise layer lets it reach a log. */
export class DatabaseQueryError extends Error {
  code?: string | number;
  errcode?: string | number;
  errno?: string | number;
  number?: string | number;

  constructor(
    message: string,
    codes: Partial<Record<(typeof CODE_FIELDS)[number], string | number>>,
  ) {
    super(message);
    this.name = "DatabaseQueryError";
    for (const field of CODE_FIELDS) {
      if (codes[field] !== undefined) this[field] = codes[field];
    }
  }
}

// Drizzle's wording for a failed statement (`DrizzleQueryError`: "Failed
// query: <sql> params: <values>"). Only this message is matched: a general
// SQL-keyword pattern also matched adapter errors that carry no statement at
// all (better-auth's "incrementOne resolved to an empty update: every
// increment/set field …") and replaced their diagnostic with a generic one.
const FAILED_QUERY_TEXT = /\bfailed query\b/i;

function chainOf(error: unknown): Record<string, unknown>[] {
  const chain: Record<string, unknown>[] = [];
  let current: unknown = error;
  while (current && typeof current === "object" && chain.length < 8) {
    if (chain.includes(current as Record<string, unknown>)) break;
    chain.push(current as Record<string, unknown>);
    current = (current as { cause?: unknown }).cause;
  }
  return chain;
}

/** Whether `error` (or anything in its `cause` chain) carries a statement or its parameters. */
export function carriesQuery(error: unknown): boolean {
  if (error instanceof DatabaseQueryError || isAPIError(error)) return false;
  return chainOf(error).some(
    (link) =>
      typeof link.query === "string" ||
      typeof link.sql === "string" ||
      Array.isArray(link.params) ||
      (typeof link.message === "string" && FAILED_QUERY_TEXT.test(link.message)),
  );
}

// The only driver text kept: a missing table or column names identifiers,
// never values, and it is what tells an integrator a migration is missing.
const SCHEMA_HINT =
  /no such (?:table|column): [\w."]+|table [\w."]+ has no column named [\w."]+|(?:relation|column) "[^"]{1,128}"(?: of relation "[^"]{1,128}")? does not exist|Unknown column '[^']{1,128}'/i;

/** `error` without its SQL: a `DatabaseQueryError` when it carries a query, else `error` itself. */
export function redactDatabaseError(
  error: unknown,
  where: { model?: unknown; method: string },
): unknown {
  if (!carriesQuery(error)) return error;
  const chain = chainOf(error);
  const codes: Partial<Record<(typeof CODE_FIELDS)[number], string | number>> = {};
  for (const field of CODE_FIELDS) {
    for (const link of chain) {
      const value = link[field];
      if (typeof value === "string" || typeof value === "number") {
        codes[field] = value;
        break;
      }
    }
  }
  let hint: string | undefined;
  for (const link of chain) {
    const match = typeof link.message === "string" ? SCHEMA_HINT.exec(link.message) : null;
    if (match) {
      hint = match[0];
      break;
    }
  }
  const model =
    typeof where.model === "string" && /^\w{1,64}$/.test(where.model) ? where.model : "?";
  const code = codes.code ?? codes.errcode ?? codes.errno ?? codes.number;
  return new DatabaseQueryError(
    `Database query failed (${model}.${where.method})${code !== undefined ? ` [${code}]` : ""}${hint ? `: ${hint}` : ""}. The statement and its parameters are not logged.`,
    codes,
  );
}

const REDACTING = Symbol("@alphabros/enterprise.db-errors.redacting");

/**
 * `adapter` with every error that carries a query replaced by a
 * `DatabaseQueryError` (see the file header). The transaction callback gets a
 * wrapped adapter too; any other property is the adapter's own.
 */
export function withDatabaseErrorRedaction(adapter: Adapter): Adapter {
  if ((adapter as { [REDACTING]?: true })[REDACTING]) return adapter;
  return new Proxy(adapter, {
    get(target, prop, receiver) {
      if (prop === REDACTING) return true;
      const value = Reflect.get(target, prop, receiver) as unknown;
      if (typeof value !== "function" || typeof prop !== "string") return value;
      const method = prop;
      if (method === "transaction") {
        return async (callback: (transaction: Adapter) => Promise<unknown>) => {
          try {
            return await (value as (cb: typeof callback) => Promise<unknown>).call(
              target,
              (transaction: Adapter) => callback(withDatabaseErrorRedaction(transaction)),
            );
          } catch (error) {
            throw redactDatabaseError(error, { method });
          }
        };
      }
      return function (this: unknown, ...args: unknown[]) {
        const model = (args[0] as { model?: unknown } | undefined)?.model;
        let result: unknown;
        try {
          result = (value as (...a: unknown[]) => unknown).apply(target, args);
        } catch (error) {
          throw redactDatabaseError(error, { model, method });
        }
        if (result && typeof (result as Promise<unknown>).then === "function") {
          return (result as Promise<unknown>).then(undefined, (error: unknown) => {
            throw redactDatabaseError(error, { model, method });
          });
        }
        return result;
      };
    },
  });
}

// Alpha Bros enterprise layer — the per-organization audit lock on Postgres.
//
// Two writers racing for one organization's next `seq` collide on the
// `audit_event_org_seq` unique index (SQLSTATE `23505`). Outside a transaction
// that is a failed statement `writeAudit` simply retries. Inside one — a SCIM
// request, an entitlement change — the failed statement leaves the transaction
// aborted (`25P02`, "current transaction is aborted"), so the retry cannot
// run and the whole request fails. `database: { dialect: "pg" }` therefore
// takes `pg_advisory_xact_lock` for the organization **before** the chain's
// head is read: the next writer waits until the holder commits or rolls back
// and then sees the head it left, so the collision never happens.
//
// The lock statement has to run on the connection of the transaction the row
// is written in, and better-auth's adapter (including the transaction adapter
// its drizzle build hands out) has no raw-SQL surface. `withPgAuditLock(db)`
// closes that gap: it wraps the drizzle database the adapter is built on so
// that, whenever the adapter opens a transaction (`db.transaction`), that
// transaction is remembered in async-local storage for the duration of the
// callback, and `lockOrganizationInTransaction` runs the lock statement on it.
// The storage lives on `globalThis` (like better-auth's own) so two copies of
// this module — a bundler duplicate, a test's fresh import — agree on it.

import { getAsyncLocalStorage } from "@better-auth/core/async_hooks";

/** What the lock needs of a transaction: drizzle's `execute(string)`, on any pg driver. */
export interface PgTransactionHandle {
  execute(query: string): PromiseLike<unknown>;
}

interface TransactionStorage {
  run<R>(store: PgTransactionHandle, fn: () => R): R;
  getStore(): PgTransactionHandle | undefined;
}

const STORAGE_KEY = Symbol.for("@alphabros/enterprise.pg-audit-lock.storage");

function transactionStorage(): Promise<TransactionStorage> {
  const holder = globalThis as { [STORAGE_KEY]?: Promise<TransactionStorage> };
  holder[STORAGE_KEY] ??= getAsyncLocalStorage().then(
    (Storage) => new Storage<PgTransactionHandle>() as TransactionStorage,
  );
  return holder[STORAGE_KEY];
}

/**
 * `db` (a drizzle Postgres database: `node-postgres`, `pglite`, `postgres-js`,
 * Neon, …) with every `transaction()` it opens made visible to the audit lock.
 * Everything else passes straight through to `db`.
 *
 *   drizzleAdapter(withPgAuditLock(db), { provider: "pg", transaction: true })
 *
 * Only needed with `database: { dialect: "pg" }`.
 */
export function withPgAuditLock<Db extends object>(db: Db): Db {
  return new Proxy(db, {
    get(target, prop, receiver) {
      const value = Reflect.get(target, prop, receiver) as unknown;
      if (prop !== "transaction" || typeof value !== "function") return value;
      return async (callback: (tx: PgTransactionHandle) => unknown, ...rest: unknown[]) => {
        const storage = await transactionStorage();
        return (value as (...args: unknown[]) => unknown).call(
          target,
          (tx: PgTransactionHandle) => storage.run(tx, () => callback(tx)),
          ...rest,
        );
      };
    },
  });
}

/** The transaction `withPgAuditLock` recorded for the running call, if any. */
export async function currentPgTransaction(): Promise<PgTransactionHandle | undefined> {
  return (await transactionStorage()).getStore();
}

// Namespace for the two-key form of the advisory lock, so the audit locks
// cannot collide with a product's own single-key advisory locks.
const LOCK_NAMESPACE = 0x41554454;

/** A stable signed 32-bit key for an organization id (first 4 bytes of its SHA-256). */
export async function orgLockKey(orgId: string): Promise<number> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(orgId));
  return new DataView(digest).getInt32(0);
}

/**
 * Takes the organization's audit lock on the running transaction; it is held
 * until that transaction commits or rolls back. Resolves `false` — and takes
 * nothing — when no transaction was recorded (the database is not wrapped
 * with `withPgAuditLock`, or the call is not inside one).
 */
export async function lockOrganizationInTransaction(orgId: string): Promise<boolean> {
  const transaction = await currentPgTransaction();
  if (!transaction) return false;
  const key = await orgLockKey(orgId);
  // Both arguments are integers this module computed (a constant and a hash
  // of the id), never text taken from a caller.
  await transaction.execute(`select pg_advisory_xact_lock(${LOCK_NAMESPACE}, ${key})`);
  return true;
}

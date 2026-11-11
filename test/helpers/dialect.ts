// Which database the core suites run against. The `server` vitest project is
// the SQLite baseline (unchanged); the `server-pg` project runs the same files
// with `TEST_DIALECT=pg`, where `makeAuth` (./auth.ts) builds the Postgres
// schema and applies `applyMigrationPg` instead.
//
// Postgres comes from one of two places:
// - `TEST_DATABASE_URL` set (the CI job's digest-pinned service container, or
//   any local server): a real Postgres, one throwaway schema per `makeAuth()`.
// - otherwise PGlite, in-process, so `pnpm test` needs no Docker.
//
// `TEST_DIALECT=pg` is set by the `server-pg` project only. `TEST_DATABASE_URL`
// alone never changes what the SQLite baseline does.

export type Dialect = "sqlite" | "pg";

export const dialect: Dialect = process.env.TEST_DIALECT === "pg" ? "pg" : "sqlite";
export const isPg = dialect === "pg";

/** The real Postgres this run is pointed at, when there is one (never set for the SQLite baseline). */
export const realPostgresUrl: string | undefined = isPg
  ? process.env.TEST_DATABASE_URL?.trim() || undefined
  : undefined;

/**
 * A point in time as the raw-SQL helpers of a suite want to bind it: epoch
 * milliseconds for SQLite's integer timestamps, a `Date` for Postgres'
 * `timestamptz`. Reads go the other way: the Postgres test client hands
 * timestamps back as epoch milliseconds, so a suite's `Number(row.created_at)`
 * is the same on both.
 */
export function ts(ms: number): number | Date {
  return isPg ? new Date(ms) : ms;
}

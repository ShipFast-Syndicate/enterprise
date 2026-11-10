// The smallest Postgres client surface the schema helpers need: a
// `query(sql, params?)` returning `{ rows }`. Satisfied by `pg` (`Pool` or
// `Client`), `@electric-sql/pglite`'s `PGlite`, and anything shaped alike.
// No Postgres driver is imported by this package.
export interface PgClient {
  query(sql: string, params?: unknown[]): Promise<{ rows: unknown[] }>;
}

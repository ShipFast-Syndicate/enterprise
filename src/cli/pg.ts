// Alpha Bros enterprise layer — the Postgres side of the `ab-enterprise` CLI:
// which database a command is pointed at (`--dialect`, autodetected from a
// `postgres://` URL), where its credentials may come from, and the connection.
//
// Credentials never travel on the command line: a Postgres URL carries the
// password, and argv is visible to every process on the host (`ps`) and lands
// in shell history. A Postgres URL is therefore read from the environment
// (`AB_DATABASE_URL`, `DATABASE_URL` or `TURSO_DATABASE_URL`); `--url` is
// accepted for Postgres only when it names no password (the password then
// comes from `PGPASSWORD`, `~/.pgpass` or a service file, which `pg` reads
// itself). With `--dialect pg` and no URL at all the connection is built from
// the standard `PG*` environment variables.
//
// The driver is `pg`, loaded only when a Postgres command runs — the SQLite
// commands never import it, and it is an optional peer of the package.
import type { PgClient } from "../schema/pg-client";

export type CliDialect = "sqlite" | "pg";

const POSTGRES_URL = /^postgres(?:ql)?:\/\//i;

export function isPostgresUrl(url: string | undefined): url is string {
  return url !== undefined && POSTGRES_URL.test(url.trim());
}

/** `PG*` variables that stand in for a URL (libpq's own). */
const LIBPQ_ENV = ["PGHOST", "PGHOSTADDR", "PGDATABASE", "PGSERVICE"] as const;

function present(value: string | undefined): string | undefined {
  return value === undefined || value.trim() === "" ? undefined : value;
}

/** Whether a Postgres URL carries a password (userinfo or a `password` query parameter). */
export function urlCarriesPassword(url: string): boolean {
  try {
    const parsed = new URL(url);
    return parsed.password !== "" || parsed.searchParams.has("password");
  } catch {
    // Not parseable as a URL: assume the worst, it may hold credentials.
    return true;
  }
}

export type DialectSelection =
  | { dialect: "sqlite"; url: string | undefined }
  | { dialect: "pg"; url: string | undefined }
  | { error: string };

/**
 * Which dialect a command that connects to a database runs against, and the
 * URL it connects to.
 *
 * - `--dialect sqlite|pg` decides when given. SQLite keeps its sources
 *   (`--url`, `TURSO_DATABASE_URL`); Postgres reads its URL from the
 *   environment (see the header) or, passwordless, from `--url`.
 * - Without `--dialect`, `--url` / `TURSO_DATABASE_URL` is looked at as
 *   before, and a `postgres://` / `postgresql://` URL there means Postgres.
 *   When neither is set, a Postgres URL in `AB_DATABASE_URL` / `DATABASE_URL`
 *   does too; anything else is the SQLite command's usual "--url is required".
 */
export function selectDialect(
  command: string,
  flags: { dialect?: string; url?: string },
  env: NodeJS.ProcessEnv,
): DialectSelection {
  const prefix = `ab-enterprise ${command}:`;
  const requested = flags.dialect === "postgres" ? "pg" : flags.dialect;
  if (requested !== undefined && requested !== "sqlite" && requested !== "pg") {
    return { error: `${prefix} --dialect must be "sqlite" or "pg" (got "${flags.dialect}")` };
  }

  const turso = present(env.TURSO_DATABASE_URL);
  const abUrl = present(env.AB_DATABASE_URL);
  const databaseUrl = present(env.DATABASE_URL);

  let dialect: CliDialect;
  if (requested) {
    dialect = requested;
  } else if (flags.url !== undefined) {
    dialect = isPostgresUrl(flags.url) ? "pg" : "sqlite";
  } else if (turso !== undefined) {
    dialect = isPostgresUrl(turso) ? "pg" : "sqlite";
  } else {
    dialect = isPostgresUrl(abUrl) || isPostgresUrl(databaseUrl) ? "pg" : "sqlite";
  }

  if (dialect === "sqlite") {
    const url = flags.url ?? turso;
    if (isPostgresUrl(url)) {
      return { error: `${prefix} --dialect sqlite was given a postgres:// URL` };
    }
    return { dialect, url };
  }

  if (flags.url !== undefined) {
    if (!isPostgresUrl(flags.url)) {
      return { error: `${prefix} --dialect pg needs a postgres:// or postgresql:// URL` };
    }
    if (urlCarriesPassword(flags.url)) {
      return {
        error: `${prefix} a Postgres URL with credentials is read from the environment, never from --url (it would show in ps and shell history): set AB_DATABASE_URL, DATABASE_URL or TURSO_DATABASE_URL`,
      };
    }
    return { dialect, url: flags.url };
  }
  const url = [abUrl, databaseUrl, turso].find((candidate) => candidate !== undefined);
  if (url !== undefined) {
    if (!isPostgresUrl(url)) {
      return { error: `${prefix} --dialect pg needs a postgres:// or postgresql:// URL` };
    }
    return { dialect, url };
  }
  if (LIBPQ_ENV.some((name) => present(env[name]) !== undefined))
    return { dialect, url: undefined };
  return {
    error: `${prefix} a Postgres connection is required: set AB_DATABASE_URL, DATABASE_URL or TURSO_DATABASE_URL to a postgres:// URL (or the PG* variables)`,
  };
}

export interface OpenPgClient extends PgClient {
  close(): Promise<void>;
}

/** Connects with `pg`. `url` undefined: the `PG*` environment variables decide. */
export async function openPgClient(url: string | undefined): Promise<OpenPgClient> {
  let driver: typeof import("pg");
  try {
    driver = await import("pg");
  } catch {
    throw new Error(
      'ab-enterprise: the Postgres commands need the "pg" package — install it next to @alphabros/enterprise (e.g. pnpm add pg)',
    );
  }
  const Client = driver.default?.Client ?? driver.Client;
  const client = new Client(url === undefined ? {} : { connectionString: url });
  await client.connect();
  return {
    query: async (sql, params) => {
      const result = await client.query(sql, params);
      return { rows: result.rows };
    },
    close: () => client.end(),
  };
}

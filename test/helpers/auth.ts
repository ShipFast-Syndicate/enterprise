// Test helper: boots a real better-auth instance wired through
// `enterprisePreset` on an in-memory libsql db, creates every table it
// needs, and exposes a tiny fetch-style `api` so tests drive the plugin
// through `auth.handler` (real HTTP request objects) rather than calling
// internals directly.
//
// Schema bridge — why this is more than "call getMigrations() and go":
//
// The task-2 brief's own sketch of this file is `getMigrations(auth.options)`
// (`import { getMigrations } from "better-auth/db"`) followed by
// `runMigrations()`, plus hand-written `CREATE TABLE` SQL for our own 3
// tables. Verified against the pinned better-auth@1.6.33, two things in
// that sketch don't hold and had to be worked around:
//
// 1. `getMigrations` isn't exported from `better-auth/db` in this version —
//    `better-auth/db/migration` is the subpath that actually exports it
//    (`node_modules/better-auth/package.json`'s `exports["./db/migration"]`,
//    backed by `dist/db/get-migration.d.mts`).
// 2. More fundamentally, `getMigrations(...).runMigrations()` only works
//    against a database better-auth can turn into a raw Kysely connection
//    itself (`createKyselyAdapter` in `@better-auth/kysely-adapter`
//    recognizes better-sqlite3/pg/mysql/D1/etc. driver shapes). A
//    `drizzleAdapter(...)` instance — what this file (per the brief) passes
//    as `database` — isn't one of those shapes, so `createKyselyAdapter`
//    returns `{ kysely: null }` and `getMigrations()` calls
//    `process.exit(1)` (verified directly: it logs "Only kysely adapter is
//    supported for migrations" and exits before returning anything, so
//    there's no way to reach `runMigrations()` or `compileMigrations()`
//    through it here).
//
// Separately, `drizzleAdapter` itself requires every better-auth model it's
// asked to read/write (user, session, account, organization, ssoProvider,
// scimProvider, ...) to already exist as a real drizzle table in the schema
// it's given (`config.schema ?? db._.fullSchema` — see
// `@better-auth/drizzle-adapter`'s `getSchema()`); passing only our 3
// enterprise tables leaves every better-auth core/plugin table missing, so
// the first real sign-up or org-create call would throw
// `BetterAuthError('The model "user" was not found in the schema object')`.
//
// So both problems are solved the same way real projects solve them outside
// tests — by generating a schema/migration from better-auth's own resolved
// table definitions — except done at test-boot time instead of as a
// checked-in file: `getAuthTables()` (the same introspection
// `getMigrations`/`better-auth generate` are themselves built on, exported
// from `better-auth/db`) gives the full field list per model, and
// `buildDynamicSchema` turns that into both a drizzle sqlite schema (for
// `drizzleAdapter` to query through) and matching `CREATE TABLE IF NOT
// EXISTS` SQL (executed directly on the libsql client) for every upstream
// better-auth model. Our own 3 tables aren't part of that model registry
// (the `enterpriseGate` plugin declares no `schema`) — Task 3's real
// `applyMigration` (`src/schema/migrate.ts`, executing the checked-in
// `sql/0001_enterprise.sql`) creates those, plus the two `studio_ref`
// columns on `user`/`organization`, on top of the dynamic upstream schema
// below. Per Task 3's controller ruling (a), every server test now goes
// through that real migration rather than hand-written SQL mirroring
// `src/schema/index.ts`, so the shipped SQL is what's actually exercised.

import type { BetterAuthOptions, BetterAuthPlugin } from "better-auth";
import { betterAuth } from "better-auth";
import { drizzleAdapter } from "better-auth/adapters/drizzle";
import { getAuthTables } from "better-auth/db";
import { createClient, type Client } from "@libsql/client";
import { drizzle } from "drizzle-orm/libsql";
import { integer, sqliteTable, text } from "drizzle-orm/sqlite-core";
import { applyMigration, enterpriseSchema } from "../../src/schema";
import { enterprisePreset } from "../../src/server/preset";
import type { EnterpriseOptions, Feature } from "../../src/server/types";

function sqliteColumn(name: string, type: string, notNull: boolean) {
  const col =
    type === "number"
      ? integer(name)
      : type === "boolean"
        ? integer(name, { mode: "boolean" })
        : type === "date"
          ? integer(name, { mode: "timestamp_ms" })
          : text(name); // string, json, string[], number[]
  return notNull ? col.notNull() : col;
}

function sqlColumnType(type: string): string {
  return type === "number" || type === "boolean" || type === "date" ? "INTEGER" : "TEXT";
}

function buildDynamicSchema(authOptions: BetterAuthOptions) {
  const tables = getAuthTables(authOptions);
  // Each `sqliteTable(...)` call below returns a distinctly-shaped type (its
  // own column set), so the map that collects them across every model can't
  // be typed any more precisely than this and still accept all of them.
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const drizzleSchema: Record<string, any> = {};
  const ddl: string[] = [];
  for (const table of Object.values(tables)) {
    const columns: Record<string, unknown> = { id: text("id").primaryKey() };
    const columnDdl = [`"id" TEXT PRIMARY KEY NOT NULL`];
    for (const [key, field] of Object.entries(table.fields)) {
      const name = field.fieldName ?? key;
      const notNull = field.required !== false;
      columns[key] = sqliteColumn(name, field.type as string, notNull);
      columnDdl.push(
        `"${name}" ${sqlColumnType(field.type as string)}${notNull ? " NOT NULL" : ""}${field.unique ? " UNIQUE" : ""}`,
      );
    }
    drizzleSchema[table.modelName] = sqliteTable(table.modelName, columns as never);
    ddl.push(`CREATE TABLE IF NOT EXISTS "${table.modelName}" (\n  ${columnDdl.join(",\n  ")}\n)`);
  }
  return { drizzleSchema, ddl };
}

// Applies just the dynamically-derived upstream better-auth DDL. Our own 3
// enterprise tables (and the `studio_ref` columns) are never part of a
// `buildDynamicSchema()` result — not in better-auth's model registry (the
// `enterpriseGate` plugin declares no `schema`) — so `makeAuth` below
// follows this with the real `applyMigration` (`src/schema/migrate.ts`,
// executing the checked-in `sql/0001_enterprise.sql`) rather than any
// hand-written SQL here.
async function applyMigrations(ddl: string[], client: Client): Promise<void> {
  await client.batch(ddl, "write");
}

// Recomputes the dynamic schema from `auth.options` — fine for a one-off
// standalone call, but `makeAuth` below already has a `buildDynamicSchema()`
// result in hand (it needs the schema before `auth` exists, to build `db`)
// and calls `applyMigrations` with that directly rather than through this,
// to avoid deriving the schema from the same options twice. Upstream-only,
// deliberately: callers that also want our own tables/columns call the real
// `applyMigration` (`src/schema`) afterward, same as `makeAuth` does.
export async function runMigrations(
  auth: { options: BetterAuthOptions },
  client: Client,
): Promise<void> {
  const { ddl } = buildDynamicSchema(auth.options);
  await applyMigrations(ddl, client);
}

type ApiHeaders = Record<string, string>;

export async function makeAuth(
  overrides: Partial<EnterpriseOptions> & { plugins?: BetterAuthPlugin[] } = {},
) {
  const entitled = new Set<Feature>([
    "sso",
    "scim",
    "audit_log",
    "enforce_2fa",
    "api_keys",
    "teams",
  ]);
  const opts: EnterpriseOptions = {
    product: "test",
    secretsKey: "s".repeat(32),
    resolveEntitlements: async () => entitled,
    ...overrides,
  };
  const baseOptions: BetterAuthOptions = {
    secret: "x".repeat(32),
    baseURL: "http://localhost:3000",
    emailAndPassword: { enabled: true },
    plugins: [...enterprisePreset(opts), ...(overrides.plugins ?? [])],
  };

  const { drizzleSchema, ddl } = buildDynamicSchema(baseOptions);
  const client = createClient({ url: ":memory:" });
  const db = drizzle(client, { schema: { ...enterpriseSchema, ...drizzleSchema } });
  const auth = betterAuth({
    database: drizzleAdapter(db, { provider: "sqlite" }),
    ...baseOptions,
  });
  await applyMigrations(ddl, client);
  // Real migration (ruling (a)): creates org_policy/audit_event/scim_group
  // and adds the two studio_ref columns, now that user/organization exist.
  await applyMigration(client);

  const api = {
    post: (path: string, body: unknown, headers: ApiHeaders = {}) =>
      auth.handler(
        new Request(`http://localhost:3000/api/auth${path}`, {
          method: "POST",
          headers: {
            "content-type": "application/json",
            origin: "http://localhost:3000",
            ...headers,
          },
          body: JSON.stringify(body),
        }),
      ),
    get: (path: string, headers: ApiHeaders = {}) =>
      auth.handler(
        new Request(`http://localhost:3000/api/auth${path}`, {
          headers: { origin: "http://localhost:3000", ...headers },
        }),
      ),
  };

  return { auth, db, client, api, entitled };
}

export type TestAuth = Awaited<ReturnType<typeof makeAuth>>;

function extractCookie(res: Response): string {
  const setCookies = res.headers.getSetCookie();
  return setCookies.map((raw) => raw.split(";")[0]).join("; ");
}

export async function signUpOwner(t: TestAuth, email = "owner@acme.test") {
  const res = await t.api.post("/sign-up/email", {
    name: "Owner",
    email,
    password: "password1234",
  });
  if (!res.ok) {
    throw new Error(`signUpOwner failed: ${res.status} ${await res.text()}`);
  }
  const cookie = extractCookie(res);
  const body = (await res.json()) as { user: { id: string } };
  return { cookie, userId: body.user.id };
}

export async function createOrg(t: TestAuth, cookie: string, slug = "acme") {
  const res = await t.api.post("/organization/create", { name: slug, slug }, { cookie });
  if (!res.ok) {
    throw new Error(`createOrg failed: ${res.status} ${await res.text()}`);
  }
  const org = (await res.json()) as { id: string };
  return { orgId: org.id };
}

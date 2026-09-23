// Real HTTP auth handler backed by an isolated SQLite file. Native interactive
// transactions require all connections to share a database, so :memory: is unsuitable.
// getAuthTables supplies the actual pinned model definitions; package migrations
// add enterprise columns and indexes. File/client cleanup runs after each test.
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach } from "vitest";
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

const databases: { client: Client; directory: string }[] = [];
afterEach(() => {
  for (const { client, directory } of databases.splice(0)) {
    client.close();
    rmSync(directory, { recursive: true, force: true });
  }
});

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
      // Keyed by `name` (the physical column name a `fieldName` override
      // maps to — equal to `key` for every model that doesn't set one),
      // not by `key`: `@better-auth/drizzle-adapter`'s own field resolution
      // (`getFieldName`) looks columns up on the schema object by the
      // *mapped* name, not the semantic field key, so a drizzle table
      // object must expose its columns under that same name for the
      // adapter to find them. This only diverges from `key` for a model
      // with an explicit `fieldName` mapping — Task 4's `auditLog` plugin
      // (`src/server/audit/plugin.ts`) is the first one, mapping its
      // camelCase field keys to the SQL migration's snake_case columns.
      columns[name] = sqliteColumn(name, field.type as string, notNull);
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

// Rate limiting is disabled by default outside production
// (`options.rateLimit?.enabled ?? isProduction`,
// `node_modules/better-auth/dist/context/create-context.mjs`) — off by
// default in this `NODE_ENV=test` suite too, so `test/server/home-realm.
// test.ts`'s rate-limit behavioural test needs it turned on here to exercise
// real behavior instead of asserting against a no-op. Products embedding
// this package must likewise keep rate limiting enabled in whatever
// environment actually faces traffic — `enterpriseGate`/`orgPolicy`'s own
// per-path rules (10/min on `/enterprise/home-realm`, ruling (c)) only bite
// when the global switch is on.
//
// better-auth also hardcodes a *separate*, much stricter "special rule" for
// every `/sign-in*`/`/sign-up*`/`/change-password`/`/change-email` path
// (`getDefaultSpecialRules()` in `node_modules/better-auth/dist/api/
// rate-limiter/index.mjs`: window 10s, max **3** — not configurable via the
// top-level `rateLimit.max`, which only sets the *generic* per-path default
// used when nothing more specific matches). Every test file in this suite
// calls `/sign-up/email` (`signUpOwner`) and `/sign-in/email` far more than
// 3 times each, and the rate limiter's in-memory store is a module-level
// singleton shared by every `it()` in one test file (vitest isolates
// modules per *file*, not per test) regardless of how many separate
// `makeAuth()` instances a file creates — so enabling rate limiting without
// relaxing this specific special rule would break most of the existing
// suite, not just add coverage. `customRules` is the only mechanism that
// overrides it (checked after both the special rule and any plugin's own
// `rateLimit` array, so it always wins for a matching path); scoped to just
// `/sign-up/*` and `/sign-in/*` so plugin-declared rules — `orgPolicy`'s own
// `/enterprise/home-realm` (10/min) and upstream `magicLink`'s
// `/sign-in/magic-link`+`/magic-link/verify` (5/min, matched by exact path,
// not by this wildcard) — stay intact and testable.
const TEST_RATE_LIMIT: NonNullable<BetterAuthOptions["rateLimit"]> = {
  enabled: true,
  // Generous generic ceiling for every other path (`/get-session`,
  // `/organization/*`, `/scim/*`, `/api-key/*`, `/enterprise/policy*`, ...)
  // that has neither a special rule nor a plugin-declared one — the
  // upstream default (100/10s) is plenty in isolation, but many of those
  // paths are also called dozens of times per test file.
  max: 1000,
  customRules: {
    "/sign-up/*": { window: 10, max: 10_000 },
    "/sign-in/*": { window: 10, max: 10_000 },
  },
};

// The same "Task 2 preset mounted" base options `test/schema/verify.test.ts`
// and `test/cli/cli.test.ts` both need to derive the upstream better-auth
// schema (`getAuthTables`/`runMigrations`) without booting a full `makeAuth`
// instance (which also folds in the real `applyMigration`, which those
// tests want to apply — or not — themselves, explicitly). Kept minimal and
// fixed (no per-test entitlements) since neither caller drives gated
// endpoints through it.
export function baseAuthOptions(): BetterAuthOptions {
  return {
    secret: "x".repeat(32),
    baseURL: "http://localhost:3000",
    emailAndPassword: { enabled: true },
    rateLimit: TEST_RATE_LIMIT,
    plugins: enterprisePreset({
      product: "test",
      secretsKey: "s".repeat(32),
      scimCredentialHashSecret: "catalog-test-key-".repeat(3),
      resolveEntitlements: async () => new Set(),
    }),
  };
}

type ApiHeaders = Record<string, string>;

export async function makeAuth(
  overrides: Partial<EnterpriseOptions> & {
    plugins?: BetterAuthPlugin[];
    // Task 8's SAML/OIDC e2e tests run a real in-process OIDC issuer
    // (`test/helpers/oidc-issuer.ts`) on a loopback origin.
    // `@better-auth/sso`'s own SSRF guard (`assertOIDCEndpointsResolvePublic`/
    // `validateSkipDiscoveryEndpoint`) re-validates every OIDC endpoint as a
    // "publicly routable host" on every `/sign-in/sso` call and callback —
    // a loopback origin fails that check unless it's in `trustedOrigins`, so
    // those tests pass `[issuer.issuerUrl]` here. Unused by every other
    // caller (better-auth defaults `trustedOrigins` to just the configured
    // `baseURL` when this is omitted).
    trustedOrigins?: string[];
  } = {},
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
    scimCredentialHashSecret: "catalog-test-key-".repeat(3),
    resolveEntitlements: async () => entitled,
    ...overrides,
  };
  const baseOptions: BetterAuthOptions = {
    secret: "x".repeat(32),
    baseURL: "http://localhost:3000",
    emailAndPassword: { enabled: true },
    rateLimit: TEST_RATE_LIMIT,
    plugins: [...enterprisePreset(opts), ...(overrides.plugins ?? [])],
    ...(overrides.trustedOrigins ? { trustedOrigins: overrides.trustedOrigins } : {}),
  };

  const { drizzleSchema, ddl } = buildDynamicSchema(baseOptions);
  // Interactive libsql transactions use separate connections; file-backed SQLite
  // keeps the same database visible after commit. Each test gets its own file.
  const directory = mkdtempSync(join(tmpdir(), "enterprise-auth-"));
  const client = createClient({ url: `file:${join(directory, "auth.db")}` });
  databases.push({ client, directory });
  const db = drizzle(client, { schema: { ...enterpriseSchema, ...drizzleSchema } });
  const auth = betterAuth({
    database: drizzleAdapter(db, { provider: "sqlite", transaction: true }),
    ...baseOptions,
  });
  await applyMigrations(ddl, client);
  // Real migration (ruling (a)): creates org_policy/audit_event/scim_group
  // and adds the two studio_ref columns, now that user/organization exist.
  await applyMigration(client);

  const withBody =
    (method: string) =>
    (path: string, body: unknown, headers: ApiHeaders = {}) =>
      auth.handler(
        new Request(`http://localhost:3000/api/auth${path}`, {
          method,
          headers: {
            "content-type": "application/json",
            origin: "http://localhost:3000",
            ...headers,
          },
          body: JSON.stringify(body),
        }),
      );

  const api = {
    post: withBody("POST"),
    patch: withBody("PATCH"),
    put: withBody("PUT"),
    get: (path: string, headers: ApiHeaders = {}) =>
      auth.handler(
        new Request(`http://localhost:3000/api/auth${path}`, {
          headers: { origin: "http://localhost:3000", ...headers },
        }),
      ),
    delete: (path: string, headers: ApiHeaders = {}) =>
      auth.handler(
        new Request(`http://localhost:3000/api/auth${path}`, {
          method: "DELETE",
          headers: { origin: "http://localhost:3000", ...headers },
        }),
      ),
    // Raw-`Request` escape hatch for Task 6's scimGroups tests: a method
    // not covered by a dedicated helper above, and/or a content type other
    // than the `withBody`/`get`/`delete` helpers' hardcoded
    // `application/json` (`@better-auth/scim`'s own
    // `supportedMediaTypes` accepts `application/scim+json` too, and this
    // plugin's every *response* uses it — ruling (b) — so tests want to be
    // able to send it as a request content type as well).
    request: (method: string, path: string, body?: unknown, headers: ApiHeaders = {}) =>
      auth.handler(
        new Request(`http://localhost:3000/api/auth${path}`, {
          method,
          headers: {
            ...(body !== undefined ? { "content-type": "application/json" } : {}),
            origin: "http://localhost:3000",
            ...headers,
          },
          ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
        }),
      ),
    // `application/x-www-form-urlencoded` POST — Task 8's SAML ACS
    // (`/sso/saml2/sp/acs/:providerId`) is posted a `SAMLResponse`/
    // `RelayState` form body the way a real IdP's browser-redirect POST
    // binding would, not JSON.
    postForm: (path: string, form: Record<string, string>, headers: ApiHeaders = {}) =>
      auth.handler(
        new Request(`http://localhost:3000/api/auth${path}`, {
          method: "POST",
          headers: {
            "content-type": "application/x-www-form-urlencoded",
            origin: "http://localhost:3000",
            ...headers,
          },
          body: new URLSearchParams(form).toString(),
        }),
      ),
  };

  return { auth, db, client, api, entitled };
}

export type TestAuth = Awaited<ReturnType<typeof makeAuth>>;

export function extractCookie(res: Response): string {
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

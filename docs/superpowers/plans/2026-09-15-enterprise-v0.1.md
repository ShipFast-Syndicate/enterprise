# @alphabros/enterprise v0.1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship `@alphabros/enterprise` v0.1 — one npm package that makes any better-auth 1.6.33 product enterprise-ready: preset (orgs, SSO, SCIM incl. Groups, 2FA, passkeys, API keys, audit log, org policy), schema + live-DB verify, client helpers, and a Lit admin portal.

**Architecture:** A single ESM TypeScript package with four entry points (`/server`, `/schema`, `/client`, `/portal`) and a CLI. Server code is a set of better-auth plugins (upstream `organization`, `sso`, `scim`, `admin`, `twoFactor`, `passkey`, `apiKey` plus ours: `enterpriseGate`, `auditLog`, `orgPolicy`, `scimGroups`, `enterpriseApi`), so the portal talks only to `/api/auth/*` and no product needs framework-specific server code. Tests run better-auth on drizzle + libsql `:memory:`.

**Tech Stack:** TypeScript 5 (ESM, `moduleResolution: bundler`), pnpm 10, tsup (build), vitest 3 (unit/e2e, `happy-dom` for portal), better-auth 1.6.33 + `@better-auth/sso@1.6.33` + `@better-auth/scim@1.6.33` + `@better-auth/passkey@1.6.33` + `@better-auth/api-key@1.6.33` (pinned exact, plus the peer set `@better-auth/core@1.6.33`, `@better-fetch/fetch@1.3.1`, `better-call@1.4.0`, `@better-auth/utils@0.4.2`), drizzle-orm + `@libsql/client`, `samlify@2.13.1` (test IdP only), `lit@^3`, `zod@^4`, semantic-release (fleet convention; the spec's "changesets" is satisfied by conventional-commit semver).

**Spec:** `~/bros-home/bros-brain/knowledge/specs/2026-09-15-studio-enterprise-layer-design.md` (§3 architecture, §4 data model, §5 flows, §6 P0 results, §7.1 CI). Spike facts: `knowledge/spikes/2026-09-15-p0{a,b,c}-*.md`. Records: ADR-0057, PRD-enterprise-0001, FDR-enterprise-0001.

## Global Constraints

- better-auth line is **1.6.33 exactly**; never `^`. `@better-auth/*` all `1.6.33`. `passkey` and `apiKey` come from `@better-auth/passkey` / `@better-auth/api-key`, not `better-auth/plugins`.
- The SSO provisioning hook is `provisionUser` (spec §6 P0(b)); `resolveUser` does not exist on 1.6.
- SCIM `active` maps to the `admin` plugin's `banned` column → the preset **must** include `admin()`.
- No colours, fonts or spacing literals in portal components — only `var(--ab-*)` custom properties with no fallback values (spec §3.4).
- SCIM tokens are shown once and stored hashed (`storeSCIMToken: "hashed"`); IdP client secrets encrypted at rest with `secretsKey` (spec §7.4). Never log a `clientSecret` (the upstream `/sso/register` response echoes it — redact in our wrapper).
- Every portal-facing endpoint returns **403 `FEATURE_NOT_ENTITLED`** when `resolveEntitlements(orgId)` lacks the feature (spec §7.1).
- Audit rows are hash-chained per org: `hash = sha256(prev_hash + "\n" + canonical(row))`, hex; `prev_hash` of the first row = `"GENESIS"`.
- IDs: `organization.studio_ref` and `user.studio_ref` nullable text, unused (spec §3.5). We do not change upstream id formats in v0.1 (prefixed ids are a P2 per-product concern).
- Node 22 locally (`mise exec node@22 --`), pnpm 10. CI = `reusable-ci-app.yml@v1` from the hub, release = `reusable-release.yml@v1` (semantic-release, `NPM_TOKEN` secret).
- Conventional commits; tests before code; commit after every green step.

---

## File structure

```
enterprise/
  package.json                # name @alphabros/enterprise, type module, exports ./server ./schema ./client ./portal, bin ab-enterprise
  tsconfig.json  tsup.config.ts  vitest.config.ts  .releaserc.json  .gitleaks.toml  .github/workflows/{ci.yml,release.yml}
  src/server/index.ts         # public surface: enterprisePreset, requireFeature, types
  src/server/types.ts         # Feature, EnterpriseOptions, Entitlements
  src/server/entitlements.ts  # requireFeature + per-request cache
  src/server/gate.ts          # enterpriseGate plugin: before-hooks mapping upstream paths → features
  src/server/audit/chain.ts   # canonical(row), hashRow(prev, row), verifyChain(rows)  (pure)
  src/server/audit/plugin.ts  # auditLog plugin: schema audit_event, writeAudit(), after-hooks, /enterprise/audit/* endpoints
  src/server/policy/plugin.ts # orgPolicy plugin: schema org_policy, /enterprise/policy, sign-in + session enforcement, home-realm, deprovision cascade
  src/server/scim-groups/scim.ts     # SCIM Group resource ↔ team mapping, filter parser, PATCH ops (pure)
  src/server/scim-groups/plugin.ts   # scimGroups plugin: schema scim_group, bearer auth, /scim/v2/Groups endpoints
  src/server/preset.ts        # enterprisePreset(options) → BetterAuthPlugin[]
  src/schema/index.ts         # drizzle tables: orgPolicy, auditEvent, scimGroup (+ studio_ref columns documented)
  src/schema/sql/0001_enterprise.sql
  src/schema/expected.ts      # EXPECTED_TABLES: {table: [columns]} for upstream plugin tables + ours
  src/schema/verify.ts        # verifyDatabase(client) → {ok, missing[]}
  src/cli/index.ts            # ab-enterprise migrate|verify|audit-verify
  src/client/index.ts         # enterpriseClient() plugin + discoverHomeRealm(email)
  src/portal/base.ts          # AbElement: apiFetch, org-id/base-path attrs, theming contract
  src/portal/{ab-security-settings,ab-members,ab-sso-wizard,ab-scim-tokens,ab-security-policy,ab-api-keys,ab-audit-log}.ts
  src/portal/index.ts         # registers all elements
  test/helpers/auth.ts        # makeAuth(opts): better-auth + drizzle/libsql :memory: + preset; signUpOwner(); createOrg()
  test/helpers/saml-idp.ts    # in-process samlify IdP (from spike A level 1)
  test/helpers/oidc-issuer.ts # in-process OIDC issuer on node:http
  test/**/*.test.ts
```

---

### Task 1: Repo scaffold, toolchain, CI

**Files:** Create `package.json`, `tsconfig.json`, `tsup.config.ts`, `vitest.config.ts`, `.gitignore`, `.gitleaks.toml`, `.releaserc.json`, `README.md`, `.github/workflows/ci.yml`, `.github/workflows/release.yml`, `src/server/index.ts` (exports nothing yet), `test/smoke.test.ts`.

**Interfaces:** Produces the scripts every later task runs: `pnpm typecheck` (`tsc --noEmit`), `pnpm lint` (`eslint .`), `pnpm format:check` (`prettier --check .`), `pnpm test` (`vitest run`), `pnpm test:coverage`, `pnpm build` (`tsup`).

- [ ] **Step 1: package.json**

```json
{
  "name": "@alphabros/enterprise",
  "version": "0.0.0-development",
  "description": "Alpha Bros studio enterprise layer for better-auth: SSO (SAML/OIDC), SCIM (Users+Groups), orgs, audit log, security policy, admin portal",
  "license": "MIT",
  "type": "module",
  "packageManager": "pnpm@10.30.1",
  "engines": { "node": ">=22" },
  "files": ["dist", "sql"],
  "bin": { "ab-enterprise": "./dist/cli/index.js" },
  "exports": {
    "./server": { "types": "./dist/server/index.d.ts", "import": "./dist/server/index.js" },
    "./schema": { "types": "./dist/schema/index.d.ts", "import": "./dist/schema/index.js" },
    "./client": { "types": "./dist/client/index.d.ts", "import": "./dist/client/index.js" },
    "./portal": { "types": "./dist/portal/index.d.ts", "import": "./dist/portal/index.js" }
  },
  "scripts": {
    "build": "tsup && cp -R src/schema/sql sql",
    "typecheck": "tsc --noEmit",
    "lint": "eslint .",
    "format:check": "prettier --check .",
    "format": "prettier --write .",
    "test": "vitest run",
    "test:coverage": "vitest run --coverage",
    "prepack": "pnpm build"
  },
  "peerDependencies": { "better-auth": "1.6.33", "@better-auth/sso": "1.6.33", "@better-auth/scim": "1.6.33", "@better-auth/passkey": "1.6.33", "@better-auth/api-key": "1.6.33", "drizzle-orm": ">=0.36", "lit": "^3" },
  "dependencies": { "zod": "^4.0.0" },
  "devDependencies": {
    "better-auth": "1.6.33", "@better-auth/core": "1.6.33", "@better-auth/sso": "1.6.33", "@better-auth/scim": "1.6.33", "@better-auth/passkey": "1.6.33", "@better-auth/api-key": "1.6.33", "@better-auth/utils": "0.4.2", "@better-fetch/fetch": "1.3.1", "better-call": "1.4.0",
    "drizzle-orm": "^0.44.0", "@libsql/client": "^0.15.0", "lit": "^3.3.0", "samlify": "2.13.1",
    "typescript": "^5.6.0", "tsup": "^8.3.0", "vitest": "^3.2.0", "@vitest/coverage-v8": "^3.2.0", "happy-dom": "^17.0.0",
    "eslint": "^9.0.0", "typescript-eslint": "^8.0.0", "prettier": "^3.3.0",
    "semantic-release": "^24.0.0", "@semantic-release/git": "^10.0.0", "@semantic-release/changelog": "^6.0.0", "conventional-changelog-conventionalcommits": "^8.0.0"
  }
}
```

Use the newest versions that `pnpm add` resolves at install time for the `^` ranges; keep the better-auth set exact.

- [ ] **Step 2: tsconfig / tsup / vitest**

`tsconfig.json`: `"target":"ES2022","module":"ESNext","moduleResolution":"bundler","strict":true,"declaration":true,"experimentalDecorators":false,"useDefineForClassFields":false,"skipLibCheck":true,"include":["src","test"]` (Lit needs `useDefineForClassFields:false` with standard decorators off; use `static properties` instead of decorators).

`tsup.config.ts`: entries `src/server/index.ts src/schema/index.ts src/client/index.ts src/portal/index.ts src/cli/index.ts`, `format:["esm"]`, `dts:true`, `splitting:false`, `clean:true`, `external:[/^better-auth/, /^@better-auth\//, "drizzle-orm", "@libsql/client", "lit", /^lit\//]`, `banner` for cli entry `#!/usr/bin/env node`.

`vitest.config.ts`: `test.include:["test/**/*.test.ts"]`, `environmentMatchGlobs:[["test/portal/**","happy-dom"]]`, `coverage.provider:"v8"`, `coverage.include:["src/**"]`, `testTimeout: 20000`.

- [ ] **Step 3: smoke test** `test/smoke.test.ts`:

```ts
import { describe, it, expect } from "vitest";
import { betterAuth } from "better-auth";
import { drizzleAdapter } from "better-auth/adapters/drizzle";
import { drizzle } from "drizzle-orm/libsql";
import { createClient } from "@libsql/client";
describe("toolchain", () => {
  it("boots better-auth 1.6.33 on libsql :memory:", async () => {
    const client = createClient({ url: ":memory:" });
    const db = drizzle(client);
    const auth = betterAuth({ database: drizzleAdapter(db, { provider: "sqlite" }), secret: "x".repeat(32), baseURL: "http://localhost:3000", emailAndPassword: { enabled: true } });
    const ctx = await auth.$context;
    expect(ctx.options.baseURL).toBe("http://localhost:3000");
    expect((await import("better-auth/package.json", { with: { type: "json" } })).default.version).toBe("1.6.33");
  });
});
```

Run `mise exec node@22 -- pnpm test` → PASS. (If the `package.json` import is blocked by exports, read `node_modules/better-auth/package.json` with `fs` instead.)

- [ ] **Step 4: CI callers.** `.github/workflows/ci.yml`:

```yaml
name: CI
on:
  pull_request:
  push: { branches: [develop, main] }
permissions: { contents: read, pull-requests: write, checks: write, statuses: read, id-token: write, security-events: write }
jobs:
  ci:
    uses: ShipFast-Syndicate/.github/.github/workflows/reusable-ci-app.yml@78bee37c6546003297a5740bbbc16a29f0832480 # v1
    with:
      project-name: enterprise
      eslint-command: 'pnpm lint'
      typecheck-command: 'pnpm typecheck'
      prettier-command: 'pnpm format:check'
      coverage-command: 'pnpm test:coverage'
      gitleaks-config-path: '.gitleaks.toml'
      build-matrix: '[{"target":"npm","command":"pnpm build","env":"","allow-failure":false}]'
      run-e2e: false
      run-migration-dry-run: false
    secrets: inherit
```

Read `USAGE.md` in `~/bros-home/projects/shipfast-dotgithub` (origin/develop) and `tests/caller-contract.test.mjs` there for the exact required permissions and input names; adjust to match (the caller contract is enforced by the hub). `release.yml`: `on: push: branches: [main]` → `reusable-release.yml@78bee37c…` with `secrets: inherit`. `.releaserc.json`: branches `["main"]`, plugins commit-analyzer (conventionalcommits), release-notes-generator, changelog, npm (`npmPublish: true`), git (assets `CHANGELOG.md package.json`), github. Tag `v0.0.0` on the first commit so the first `feat:` releases as **0.1.0**.

- [ ] **Step 5: repo + first commit.** `git init -b develop`, commit `chore: scaffold @alphabros/enterprise`, `git tag v0.0.0`, create `ShipFast-Syndicate/enterprise` (private is fine while unpublished; **public before the first npm publish** so the source of a public package is public), push `develop` and `main` (same commit), enable branch protection to match the fleet later (Bastien/IaC).

---

### Task 2: Types, entitlements, gate plugin

**Files:** Create `src/server/types.ts`, `src/server/entitlements.ts`, `src/server/gate.ts`; Test `test/server/entitlements.test.ts`, `test/server/gate.test.ts`; Create `test/helpers/auth.ts`.

**Interfaces (Produces):**

```ts
export type Feature = "sso" | "scim" | "audit_log" | "enforce_2fa" | "api_keys" | "teams";
export type ResolveEntitlements = (orgId: string) => Promise<Iterable<Feature>>;
export interface EnterpriseOptions {
  product: string;                       // "klar"
  resolveEntitlements: ResolveEntitlements;
  samlSpKeys?: { cert: string; privateKey: string };
  secretsKey: string;                    // ≥32 chars
  audit?: { retentionDays?: number };    // default 365
  scim?: { groupRoleMap?: Record<string, "owner"|"admin"|"member"> }; // default {}
}
export class FeatureNotEntitledError extends APIError {} // status 403, body { code: "FEATURE_NOT_ENTITLED", feature, orgId }
export async function requireFeature(ctx: GenericEndpointContext, orgId: string, feature: Feature): Promise<void>;
export function enterpriseGate(opts: EnterpriseOptions): BetterAuthPlugin; // id "enterprise-gate"
export const GATED_PATHS: Record<string, Feature> = {
  "/sso/register": "sso", "/sso/request-domain-verification": "sso", "/sso/verify-domain": "sso",
  "/scim/generate-token": "scim", "/scim/delete-provider-connection": "scim",
  "/organization/create-team": "teams", "/api-key/create": "api_keys",
  "/enterprise/audit/list": "audit_log", "/enterprise/audit/export": "audit_log",
  "/enterprise/policy/set": "enforce_2fa"  // any policy write needs the top tier
};
```

`test/helpers/auth.ts` (used by every server test):

```ts
export async function makeAuth(overrides: Partial<EnterpriseOptions> & { plugins?: BetterAuthPlugin[] } = {}) {
  const client = createClient({ url: ":memory:" });
  const db = drizzle(client, { schema: { ...enterpriseSchema } });
  const entitled = new Set<Feature>(["sso","scim","audit_log","enforce_2fa","api_keys","teams"]);
  const opts: EnterpriseOptions = { product: "test", secretsKey: "s".repeat(32), resolveEntitlements: async () => entitled, ...overrides };
  const auth = betterAuth({
    database: drizzleAdapter(db, { provider: "sqlite" }), secret: "x".repeat(32), baseURL: "http://localhost:3000",
    emailAndPassword: { enabled: true }, plugins: [...enterprisePreset(opts), ...(overrides.plugins ?? [])],
  });
  await runMigrations(auth, client);   // better-auth getMigrations(auth.options) + our sql/0001_enterprise.sql
  const api = { post: (path, body, headers = {}) => auth.handler(new Request(`http://localhost:3000/api/auth${path}`, { method: "POST", headers: { "content-type": "application/json", origin: "http://localhost:3000", ...headers }, body: JSON.stringify(body) })),
                get: (path, headers = {}) => auth.handler(new Request(`http://localhost:3000/api/auth${path}`, { headers })) };
  return { auth, db, client, api, entitled };
}
export async function signUpOwner(t, email = "owner@acme.test") // → { cookie, userId }
export async function createOrg(t, cookie, slug = "acme")        // → { orgId }
```

Until Task 8 exists, `makeAuth` imports `enterprisePreset` from `src/server/preset.ts` — create that file in this task with the upstream plugins + `enterpriseGate` only, and extend it in later tasks.

- [ ] **Step 1: failing tests**

```ts
it("requireFeature throws 403 FEATURE_NOT_ENTITLED when the org lacks the feature", async () => {
  const t = await makeAuth({ resolveEntitlements: async () => ["teams"] });
  await expect(requireFeature(fakeCtx(t), "org_1", "sso")).rejects.toMatchObject({ status: "FORBIDDEN", body: { code: "FEATURE_NOT_ENTITLED", feature: "sso" } });
});
it("caches resolveEntitlements per request context", …)  // spy called once for two requireFeature calls on the same ctx
it("gate: POST /sso/register returns 403 without the sso feature", async () => {
  const t = await makeAuth({ resolveEntitlements: async () => [] });
  const { cookie } = await signUpOwner(t); const { orgId } = await createOrg(t, cookie);
  const res = await t.api.post("/sso/register", { providerId: "p", issuer: "https://idp.test", domain: "acme.test", organizationId: orgId, oidcConfig: { clientId: "a", clientSecret: "b", skipDiscovery: true, authorizationEndpoint: "https://idp.test/a", tokenEndpoint: "https://idp.test/t" } }, { cookie });
  expect(res.status).toBe(403); expect((await res.json()).code).toBe("FEATURE_NOT_ENTITLED");
});
it("gate: same call succeeds with the feature", …) // 200
it("gate: orgId is read from body.organizationId, then from the active org of the session", …)
```

- [ ] **Step 2–4:** implement; `hooks.before` uses `createAuthMiddleware` and matches `ctx.path` against `GATED_PATHS`; org id resolution = `ctx.body?.organizationId ?? ctx.body?.orgId ?? session.session.activeOrganizationId`; missing org → 400 `ORG_REQUIRED`. Run tests → PASS. Commit `feat(server): entitlements and gate plugin`.

---

### Task 3: Schema package, SQL migration, verify, CLI

**Files:** Create `src/schema/index.ts`, `src/schema/sql/0001_enterprise.sql`, `src/schema/expected.ts`, `src/schema/verify.ts`, `src/schema/migrate.ts`, `src/cli/index.ts`; Test `test/schema/verify.test.ts`, `test/cli/cli.test.ts`.

**Interfaces (Produces):**

```ts
// drizzle (sqlite dialect)
export const orgPolicy = sqliteTable("org_policy", { orgId: text("org_id").primaryKey(), require2fa: integer("require_2fa",{mode:"boolean"}).notNull().default(false), ssoEnforced: integer("sso_enforced",{mode:"boolean"}).notNull().default(false), breakGlassUserId: text("break_glass_user_id"), sessionMaxAgeS: integer("session_max_age_s"), allowedMethods: text("allowed_methods").notNull().default('["sso","magic_link","google","github","linkedin","microsoft","password","passkey"]'), groupRoleMap: text("group_role_map").notNull().default("{}"), updatedAt: integer("updated_at",{mode:"timestamp_ms"}).notNull() });
export const auditEvent = sqliteTable("audit_event", { id: text("id").primaryKey(), orgId: text("org_id").notNull(), seq: integer("seq").notNull(), actorType: text("actor_type").notNull(), actorId: text("actor_id"), action: text("action").notNull(), targetType: text("target_type").notNull(), targetId: text("target_id"), ip: text("ip"), userAgent: text("user_agent"), metadata: text("metadata").notNull().default("{}"), createdAt: integer("created_at",{mode:"timestamp_ms"}).notNull(), prevHash: text("prev_hash").notNull(), hash: text("hash").notNull() }, (t) => [uniqueIndex("audit_event_org_seq").on(t.orgId, t.seq), index("audit_event_org_created").on(t.orgId, t.createdAt)]);
export const scimGroup = sqliteTable("scim_group", { teamId: text("team_id").primaryKey(), orgId: text("org_id").notNull(), externalId: text("external_id"), createdAt: integer("created_at",{mode:"timestamp_ms"}).notNull(), updatedAt: integer("updated_at",{mode:"timestamp_ms"}).notNull() }, (t) => [index("scim_group_org").on(t.orgId), uniqueIndex("scim_group_org_external").on(t.orgId, t.externalId)]);
export const enterpriseSchema = { orgPolicy, auditEvent, scimGroup };
export const EXPECTED_TABLES: Record<string, string[]>; // user(…,studio_ref) organization(…,studio_ref) member team teamMember invitation ssoProvider scimProvider twoFactor passkey apikey org_policy audit_event scim_group with their columns as better-auth 1.6.33 generates them (derive by running getMigrations in a test and snapshotting)
export async function verifyDatabase(client: Client): Promise<{ ok: boolean; missing: { table: string; column?: string }[] }>;
export async function applyMigration(client: Client): Promise<void>; // executes 0001_enterprise.sql statements (idempotent: CREATE TABLE IF NOT EXISTS / ALTER TABLE ADD COLUMN guarded by pragma check)
```

`0001_enterprise.sql` creates the three tables + `ALTER TABLE user ADD COLUMN studio_ref TEXT` / `ALTER TABLE organization ADD COLUMN studio_ref TEXT` (the CLI checks `PRAGMA table_info` first so re-runs are no-ops). CLI: `ab-enterprise migrate --out <dir>` copies the SQL into the product's drizzle migrations folder as `NNNN_enterprise.sql` (next number); `ab-enterprise verify` reads `TURSO_DATABASE_URL` + `TURSO_AUTH_TOKEN` (or `--url/--token`), prints one line per missing item, exit 1 if any; `ab-enterprise audit-verify --org <id>` is wired in Task 4.

- [ ] Tests: `verifyDatabase` on a fresh `:memory:` DB with only better-auth base tables → `missing` lists `org_policy`, `audit_event`, `scim_group`, `user.studio_ref`; after `applyMigration` + upstream migrations → `ok: true`; `applyMigration` twice → no throw. CLI test spawns `node dist/cli/index.js verify --url file:/tmp/x.db` after `pnpm build` and asserts exit codes 1 then 0. Commit `feat(schema): enterprise tables, verify and CLI`.

---

### Task 4: auditLog plugin (hash chain, hooks, endpoints, audit-verify)

**Files:** Create `src/server/audit/chain.ts`, `src/server/audit/plugin.ts`; Modify `src/cli/index.ts` (audit-verify); Test `test/server/audit-chain.test.ts`, `test/server/audit-plugin.test.ts`.

**Interfaces (Produces):**

```ts
export interface AuditInput { orgId: string; actorType: "user"|"scim"|"system"; actorId?: string|null; action: string; targetType: string; targetId?: string|null; ip?: string|null; userAgent?: string|null; metadata?: Record<string, unknown> }
export function canonical(row: AuditRowForHash): string;       // JSON with sorted keys of {orgId,seq,actorType,actorId,action,targetType,targetId,ip,userAgent,metadata,createdAt}
export function hashRow(prevHash: string, row: AuditRowForHash): string; // sha256 hex of prevHash + "\n" + canonical(row) (Web Crypto, works on workerd)
export function verifyChain(rows: AuditRow[]): { ok: true } | { ok: false; brokenAtSeq: number };
export async function writeAudit(ctx: { context: AuthContext }, input: AuditInput): Promise<AuditRow>; // seq = max(seq)+1 per org, prev_hash = last hash or "GENESIS"; serialised per org with an in-process mutex (document: cross-instance races are detected by the unique index and retried once)
export function auditLog(opts: EnterpriseOptions): BetterAuthPlugin; // id "enterprise-audit"
export const AUDITED_PATHS: Record<string, { action: string; targetType: string }> = {
  "/sign-in/email":"auth.sign_in", "/sign-in/social":"auth.sign_in", "/sign-in/magic-link":"auth.magic_link_requested", "/magic-link/verify":"auth.sign_in", "/sso/callback/:providerId":"auth.sso_sign_in", "/sso/saml2/sp/acs/:providerId":"auth.sso_sign_in", "/sign-out":"auth.sign_out",
  "/organization/invite-member":"member.invited", "/organization/remove-member":"member.removed", "/organization/update-member-role":"member.role_changed", "/organization/accept-invitation":"member.joined",
  "/sso/register":"sso.provider_registered", "/sso/verify-domain":"sso.domain_verified", "/scim/generate-token":"scim.token_created", "/scim/delete-provider-connection":"scim.token_revoked",
  "/scim/v2/Users":"scim.user_created", "/scim/v2/Users/:id":"scim.user_updated", "/api-key/create":"api_key.created", "/api-key/delete":"api_key.revoked", "/enterprise/policy/set":"policy.updated"
}; // (shape: value is {action,targetType}; targetType from the endpoint: "user"|"member"|"sso_provider"|"scim_provider"|"api_key"|"org_policy")
// endpoints (session + owner/admin of the org, gated by audit_log):
//   GET  /enterprise/audit/list?orgId&action&actorId&from&to&cursor&limit=50 → { items, nextCursor }
//   GET  /enterprise/audit/export?orgId&from&to → text/csv (header: id,seq,created_at,actor_type,actor_id,action,target_type,target_id,ip,user_agent,metadata,prev_hash,hash)
//   GET  /enterprise/audit/verify?orgId → { ok, brokenAtSeq? }
```

Behaviour: `hooks.after` on AUDITED_PATHS reads `ctx.context.returned` / `ctx.context.session` to fill actor and target; failures of `writeAudit` in an after-hook on **sign-in paths** are logged (`ctx.context.logger.error`) and swallowed; on **admin paths** they throw `APIError("INTERNAL_SERVER_ERROR", { code: "AUDIT_WRITE_FAILED" })` (spec §5 error handling, v0.1 = after-hook variant; noted in the ADR consequences). Retention: `audit_event` rows older than `retentionDays` are deleted lazily on `list` calls (one `DELETE … WHERE created_at < ?` per call, per org).

- [ ] Tests: chain — three rows chain correctly, tampering `metadata` of row 2 → `verifyChain` → `{ok:false, brokenAtSeq:2}`, deleting the last row keeps `ok:true` (documented limit), deleting a middle row → broken. Plugin — sign-up owner + create org + `POST /organization/invite-member` → one `member.invited` row with `actorId = owner`, `targetId = invitation id`; `/enterprise/audit/list` requires the feature (403 without) and owner/admin (403 for a plain member); CSV export has the header + N rows; `/enterprise/audit/verify` ok, then a raw SQL tamper → `ok:false`. CLI `audit-verify --org` exit 0/1. Commit `feat(server): audit log plugin with per-org hash chain`.

---

### Task 5: orgPolicy plugin (policy endpoints, sign-in enforcement, session max age, home-realm, deprovision cascade)

**Files:** Create `src/server/policy/plugin.ts`, `src/server/policy/home-realm.ts`; Test `test/server/policy.test.ts`, `test/server/home-realm.test.ts`, `test/server/deprovision.test.ts`.

**Interfaces (Produces):**

```ts
export interface OrgPolicy { orgId: string; require2fa: boolean; ssoEnforced: boolean; breakGlassUserId: string|null; sessionMaxAgeS: number|null; allowedMethods: string[]; groupRoleMap: Record<string,"owner"|"admin"|"member"> }
export function orgPolicy(opts: EnterpriseOptions): BetterAuthPlugin; // id "enterprise-policy"
// endpoints:
//   GET  /enterprise/policy?orgId          → OrgPolicy (defaults when no row)   [session, member of org]
//   POST /enterprise/policy/set {orgId, ...partial}  → OrgPolicy               [session, owner/admin; ssoEnforced:true requires a verified provider for the org AND a breakGlassUserId who is an owner, else 400 SSO_ENFORCE_PRECONDITION]
//   POST /enterprise/home-realm {email}     → { method: "sso", providerId } | { method: "local" }   [public; rate-limit 10/min/ip via ctx.context.rateLimit if available]
export async function findOrgByEmailDomain(ctx, email): Promise<{ orgId: string; providerId: string } | null>; // ssoProvider where domain = email domain and domainVerified = true
```

Enforcement:
- `hooks.before` on `/sign-in/email`, `/sign-in/social`, `/sign-in/magic-link`, `/sign-in/passkey`, `/magic-link/verify`: derive email (`body.email`, or for social/passkey skip — enforce on the callback instead via `databaseHooks.session.create.before` below); if `findOrgByEmailDomain` matches and policy.ssoEnforced and the user is not `breakGlassUserId` → throw 403 `{ code: "SSO_REQUIRED", message: "Your organization requires SSO" }`; if `allowedMethods` excludes the method → 403 `METHOD_NOT_ALLOWED`.
- `databaseHooks.session.create.before`: look up the user's email domain → org policy; if `ssoEnforced` and the session is not being created by an SSO callback (detect via `ctx.path` starting with `/sso/`) and user ≠ break-glass → throw 403 `SSO_REQUIRED`; if `sessionMaxAgeS` → return `{ data: { ...session, expiresAt: new Date(Date.now() + sessionMaxAgeS*1000) } }`.
- `require2fa`: `hooks.after` on `/get-session` adds `enterprise: { require2fa: true, twoFactorEnabled: user.twoFactorEnabled }` to the returned session JSON when the user's org policy requires it (product UI redirects to enrolment; enforcement of the second step itself is upstream `twoFactor`).
- Deprovision cascade (spec flow 5): `hooks.after` on `/scim/v2/Users/:id` (PATCH/PUT with `active:false`) and DELETE: delete `apikey` rows where `userId = user` (org-scoped: all keys — v0.1 has no per-org key scoping; document), then `writeAudit({actorType:"scim", action:"scim.user_deactivated"|"scim.user_deleted", targetType:"user"})`. Sessions are already revoked upstream (spike B §2.3) — assert it in the test, don't re-implement.

- [ ] Tests: policy defaults; owner sets `require2fa:true` → get-session carries `enterprise.require2fa`; `ssoEnforced:true` without break-glass → 400; with a verified provider (insert row with `domainVerified:true` directly) + break-glass owner: magic-link for `bob@acme.test` → 403 `SSO_REQUIRED`, magic-link for the break-glass owner → 200; `sessionMaxAgeS: 600` → new session `expiresAt - createdAt ≈ 600 s`; home-realm returns `{method:"sso", providerId}` for a verified domain, `{method:"local"}` otherwise, and never leaks whether a user exists; deprovision: create a SCIM user via `/scim/v2/Users` (bearer from `/scim/generate-token`), create an api key for that user (`/api-key/create` with a session for that user — sign in via a test-only session insert), PATCH active=false → 0 sessions, 0 api keys, one `scim.user_deactivated` audit row. Commit `feat(server): org policy plugin, home-realm discovery, deprovision cascade`.

---

### Task 6: scimGroups plugin (SCIM 2.0 Groups ↔ teams, role mapping)

**Files:** Create `src/server/scim-groups/scim.ts`, `src/server/scim-groups/plugin.ts`, `src/server/scim-groups/auth.ts`; Test `test/server/scim-groups.test.ts`, `test/server/scim-groups-pure.test.ts`.

**Interfaces (Produces):**

```ts
// pure (scim.ts)
export interface ScimGroupResource { schemas: ["urn:ietf:params:scim:schemas:core:2.0:Group"]; id: string; externalId?: string; displayName: string; members: { value: string; display?: string; $ref?: string }[]; meta: { resourceType: "Group"; created: string; lastModified: string; location: string } }
export function parseFilter(filter: string | undefined): { attr: "displayName"|"externalId"|"id"; op: "eq"; value: string } | null; // supports `displayName eq "x"`, `externalId eq "y"`, `id eq "z"`; anything else → SCIM 400 invalidFilter
export type PatchOp = { op: "add"|"remove"|"replace"; path?: string; value?: unknown };
export function applyGroupPatch(current: { displayName: string; members: string[] }, ops: PatchOp[]): { displayName: string; members: string[] }; // paths: "displayName", "members", `members[value eq "id"]`; unknown path → SCIM 400 invalidPath; case-insensitive op names (Entra sends "Add")
export function effectiveRole(groupNames: string[], map: Record<string,"owner"|"admin"|"member">): "owner"|"admin"|"member"; // highest wins; none → "member"
export function scimError(status: number, scimType: string | undefined, detail: string): Response; // body { schemas:["urn:ietf:params:scim:api:messages:2.0:Error"], status:"400", scimType, detail }
// auth.ts
export async function authenticateScimBearer(ctx, opts): Promise<{ providerId: string; organizationId: string }>; // same hashing as upstream storeSCIMToken:"hashed" (read @better-auth/scim dist to replicate defaultKeyHasher exactly; test asserts a token minted by upstream /scim/generate-token authenticates our endpoints); 401 SCIM error otherwise
// plugin.ts — id "enterprise-scim-groups"; endpoints (all bearer-authed, org = token's organizationId):
//   GET    /scim/v2/Groups?filter&startIndex=1&count=100  → ListResponse { schemas:[…ListResponse], totalResults, startIndex, itemsPerPage, Resources }
//   POST   /scim/v2/Groups {displayName, externalId?, members?} → 201 + Location; creates team (organization plugin adapter: model "team" {name, organizationId}) + scim_group row + teamMember rows; 409 uniqueness if displayName exists in org
//   GET    /scim/v2/Groups/:id → resource (404 if not in this org)
//   PUT    /scim/v2/Groups/:id → replace displayName + members
//   PATCH  /scim/v2/Groups/:id {Operations} → 200 with resource (Entra expects 200/204; return 200 + body)
//   DELETE /scim/v2/Groups/:id → 204; removes teamMember rows, scim_group row, team row
//   after every membership change: recompute each affected member's org role via effectiveRole(groups of user, policy.groupRoleMap ?? opts.scim.groupRoleMap); never demote an org owner who is the only owner (skip + audit "scim.role_change_skipped")
```

Members must be users that hold a `member` row in the org; unknown `value` → SCIM 400 `invalidValue`. Every mutation writes an audit row (`scim.group_created|updated|deleted`, `scim.group_member_added|removed`, `member.role_changed`) with `actorType:"scim"`, `actorId: providerId`.

- [ ] Tests (pure): filter parsing incl. quotes/escapes and a rejected `co` operator; patch add/remove/replace members with duplicates ignored; `members[value eq "u1"]` remove; `effectiveRole`. Tests (plugin, via a token from upstream `/scim/generate-token`): no bearer → 401 SCIM error; create group → 201, team row exists, `GET /scim/v2/Groups?filter=displayName eq "Engineering"` finds it; add two SCIM-provisioned users via PATCH → teamMember rows; group named "Admins" with `groupRoleMap {"Admins":"admin"}` → member role becomes `admin`, removal → back to `member`; DELETE → 204 and roles recomputed; cross-org: a token of org B gets 404 on org A's group; conformance shape: every resource carries `schemas`, `meta.location` = absolute URL. Commit `feat(server): SCIM 2.0 Groups plugin mapped to organization teams`.

---

### Task 7: enterpriseApi plugin — portal-facing wrappers (SSO wizard state, SCIM token list, members, features)

**Files:** Create `src/server/enterprise-api/plugin.ts`; Test `test/server/enterprise-api.test.ts`.

**Interfaces (Produces):** endpoints (session + org membership; owner/admin for writes; gated per GATED_PATHS additions):

```
GET  /enterprise/features?orgId                → { features: Feature[] }
GET  /enterprise/sso/providers?orgId           → { providers: [{ providerId, type, issuer, domain, domainVerified, verificationRecord: { name: "_better-auth-token-<providerId>.<domain>", value }, spMetadataUrl, acsUrl, redirectUri, testLoginPassedAt: string|null, enforced: boolean }] }  (never includes clientSecret or cert private material)
POST /enterprise/sso/register  (same body as upstream /sso/register)  → upstream call then **redacted** response; also stores nothing extra
POST /enterprise/sso/test-login/start {orgId, providerId} → { url }   // = upstream sign-in/sso with callbackURL "/api/auth/enterprise/sso/test-login/finish?providerId=…"; marks a pending test in `verification` table (identifier `ab-sso-test:<providerId>`, 10 min)
GET  /enterprise/sso/test-login/finish?providerId      → on success (session exists for a user whose email domain matches the provider) sets `testLoginPassedAt` (stored in `verification` identifier `ab-sso-test-ok:<providerId>`) and redirects to `?ab_sso_test=ok`; else `?ab_sso_test=failed&reason=…`
GET  /enterprise/scim/tokens?orgId             → { tokens: [{ providerId, createdAt, lastUsedAt: null }] }  (v0.1: lastUsedAt null — upstream has no last-used column; documented)
POST /enterprise/scim/tokens/create {orgId, providerId} → { scimToken, baseUrl: "<baseURL>/api/auth/scim/v2" }  (wraps upstream generate-token; shown once)
POST /enterprise/scim/tokens/revoke {orgId, providerId} → { ok: true }
GET  /enterprise/members?orgId                  → { members: [{ id, userId, email, name, role, teams: string[] }], invitations: [{ id, email, role, status, expiresAt }] }
```

`POST /enterprise/policy/set` with `ssoEnforced:true` additionally requires `testLoginPassedAt` for a verified provider of the org (spec §5.2 "mandatory successful test login"), else 400 `SSO_TEST_LOGIN_REQUIRED` — implement here as a `hooks.before` on `/enterprise/policy/set` (Task 5's plugin exposes `getPolicyPreconditions(ctx, orgId)` returning `{ verifiedProvider, testLoginPassed }`; add that export to Task 5 when doing this task).

- [ ] Tests: features reflect `resolveEntitlements`; `/enterprise/sso/register` response has no `clientSecret` key; providers list carries the DNS record name/value; test-login start returns a URL on the provider's issuer; token create returns the token once and list shows the providerId; members list includes teams; every endpoint 403 for a non-member and 403 `FEATURE_NOT_ENTITLED` when the feature is missing (table-driven over all endpoints). Commit `feat(server): enterprise portal API endpoints`.

---

### Task 8: enterprisePreset + `/server` public surface + SAML/OIDC end-to-end tests

**Files:** Modify `src/server/preset.ts`, `src/server/index.ts`; Create `test/helpers/saml-idp.ts` (port `spike-a-saml` level-1 IdP: samlify IdentityProvider with a test RSA key/cert generated at test start via `node:crypto generateKeyPairSync` + `X509Certificate`), `test/helpers/oidc-issuer.ts` (node:http: `/.well-known/openid-configuration`, `/jwks`, `/authorize` → 302 back with `code`, `/token` → id_token signed RS256 via `jose`, `/userinfo`); Test `test/e2e/saml.test.ts`, `test/e2e/oidc.test.ts`, `test/e2e/jit.test.ts`.

**Interfaces (Produces):**

```ts
export function enterprisePreset(opts: EnterpriseOptions): BetterAuthPlugin[]; // order: admin(), organization({ teams: { enabled: true } }), twoFactor(), passkey(), apiKey(), sso({ domainVerification: { enabled: true }, organizationProvisioning: { disabled: false, defaultRole: "member" }, disableImplicitSignUp: false, provisionUser: opts.provisionUser?, saml: { spMetadata from opts.samlSpKeys } }), scim({ storeSCIMToken: "hashed" }), enterpriseGate(opts), auditLog(opts), orgPolicy(opts), scimGroups(opts), enterpriseApi(opts)
export { requireFeature, FeatureNotEntitledError, writeAudit, verifyChain, hashRow, canonical, type Feature, type EnterpriseOptions, type OrgPolicy, GATED_PATHS, AUDITED_PATHS }
```

`sso.organizationProvisioning` + `domainVerification` give JIT auto-join (spec flow 3). With `scim` on for an org, `sso({ disableImplicitSignUp })` cannot be per-org upstream; implement "SSO only for SCIM-active users" as: `databaseHooks.user.create.before` in `orgPolicy` → if the org (by verified domain) has a `scimProvider` row, refuse user creation from an SSO path with 403 `SCIM_PROVISIONING_REQUIRED` ("Your account was not provisioned by your IT admin"); banned (deactivated) users are refused by the admin plugin (spike B §2.4).

- [ ] Tests: SAML — register a SAML provider from the test IdP metadata (domain verified by direct DB update), `GET /sso/saml2/sp/metadata` is XML, POST a signed SAMLResponse to the ACS → 302 + session cookie, `get-session` returns the user, user is a `member` of the org (JIT), audit has `auth.sso_sign_in`; tampered response → redirect with `error=`; OIDC — full code flow against the in-process issuer → session; JIT with a pending invitation keeps the invited role (`admin`); SCIM-required org refuses JIT with 403; `enterprisePreset` returns the plugin ids in order and `auth.$context.tables` includes all EXPECTED_TABLES. Commit `feat(server): enterprisePreset and SAML/OIDC end-to-end coverage`.

---

### Task 9: `/client` entry

**Files:** Create `src/client/index.ts`; Test `test/client/client.test.ts`.

**Interfaces (Produces):**

```ts
export function enterpriseClient(): BetterAuthClientPlugin; // id "enterprise"; $InferServerPlugin of enterpriseApi + orgPolicy so `authClient.enterprise.*` is typed; re-exports ssoClient, scimClient? (scim has no client), organizationClient, twoFactorClient, passkeyClient, apiKeyClient for products that want one import
export async function discoverHomeRealm(email: string, opts?: { basePath?: string; fetch?: typeof fetch }): Promise<{ method: "sso"; providerId: string } | { method: "local" }>; // POST <basePath>/enterprise/home-realm
export function startSsoLogin(providerId: string, opts?: { basePath?: string; callbackURL?: string }): Promise<{ url: string }>; // POST <basePath>/sign-in/sso
```

- [ ] Tests with a mocked `fetch`: `discoverHomeRealm` posts JSON with `origin` and returns the typed union; `startSsoLogin` returns the url; `enterpriseClient()` has id `enterprise`. Commit `feat(client): enterprise client plugin and home-realm helper`.

---

### Task 10: Portal base + `<ab-security-settings>` + `<ab-members>`

**Files:** Create `src/portal/base.ts`, `src/portal/api.ts`, `src/portal/ab-security-settings.ts`, `src/portal/ab-members.ts`, `src/portal/index.ts`, `src/portal/tokens.md` (the `--ab-*` contract); Test `test/portal/base.test.ts`, `test/portal/members.test.ts` (happy-dom).

**Interfaces (Produces):**

```ts
// base.ts
export class AbElement extends LitElement {
  static properties = { orgId: { type: String, attribute: "org-id" }, basePath: { type: String, attribute: "base-path" } }; // basePath default "/api/auth"
  protected api: PortalApi;   // new PortalApi(this.basePath) — fetch with credentials:"include", JSON, throws PortalError {status, code, message}
  protected static baseStyles = css`:host{display:block;font-family:var(--ab-font-family);color:var(--ab-color-text);background:var(--ab-color-bg)} button{font:inherit;background:var(--ab-color-primary);color:var(--ab-color-on-primary);border:var(--ab-border);border-radius:var(--ab-radius);padding:var(--ab-space-2) var(--ab-space-3)} …`; // ONLY var(--ab-*) values
  protected renderError(e: unknown): TemplateResult;   // maps FEATURE_NOT_ENTITLED → "This feature is not included in your plan" slot `not-entitled`
}
// tokens.md lists every --ab-* token used: --ab-font-family --ab-font-size --ab-color-text --ab-color-text-muted --ab-color-bg --ab-color-surface --ab-color-primary --ab-color-on-primary --ab-color-danger --ab-color-success --ab-color-border --ab-border --ab-radius --ab-space-1..4 --ab-shadow
// ab-security-settings: attributes org-id, base-path, tabs (default "members,sso,scim,policy,api-keys,audit"); renders a tab bar and the selected child element; hides tabs whose feature is absent from GET /enterprise/features (shows a locked marker instead)
// ab-members: list from GET /enterprise/members; invite form (email + role) → POST /organization/invite-member; role select → /organization/update-member-role; remove → /organization/remove-member (confirm); teams column; emits `ab-change` CustomEvent after every mutation
```

- [ ] Tests (happy-dom, mocked `fetch`): element upgrades with a shadowRoot; renders N member rows from the mocked response; invite submit posts the right body and re-fetches; 403 FEATURE_NOT_ENTITLED renders the not-entitled message; a scan test reads every `src/portal/*.ts` and asserts no `#[0-9a-f]{3,8}`, no `rgb(`, no `px` literal outside `var(--ab-`, no `font-family:` literal (theming contract). Commit `feat(portal): base element, settings shell and members`.

---

### Task 11: `<ab-sso-wizard>` + `<ab-scim-tokens>`

**Files:** Create `src/portal/ab-sso-wizard.ts`, `src/portal/ab-scim-tokens.ts`; Test `test/portal/sso-wizard.test.ts`, `test/portal/scim-tokens.test.ts`.

Wizard steps (state machine, one `step` property): `choose` (SAML metadata XML paste/upload or OIDC issuer + client id/secret) → `register` (POST /enterprise/sso/register) → `verify-domain` (shows the TXT record name/value from providers list; "Check DNS" → POST /sso/verify-domain; polls every 10 s up to 5 min) → `test-login` (button opens `POST /enterprise/sso/test-login/start` url in a new window; listens for `?ab_sso_test=ok` via `storage` event written by the finish page, or "I completed the test" → re-fetch providers and read `testLoginPassedAt`) → `enforce` (toggle → POST /enterprise/policy/set {ssoEnforced, breakGlassUserId: current user}) → `done`. Errors from each call render inline; raw diagnostics only in `test-login` (spec §5 error handling). `<ab-scim-tokens>`: list, create (providerId input, default `scim-<orgSlug>`) → shows token **once** in a copy box with the base URL, revoke with confirm.

- [ ] Tests: step transitions with mocked responses; DNS record rendered with the exact name; enforce toggle disabled until `testLoginPassedAt`; token shown once and cleared after `Done`. Commit `feat(portal): SSO wizard and SCIM tokens`.

---

### Task 12: `<ab-security-policy>` + `<ab-api-keys>` + `<ab-audit-log>`

**Files:** Create the three elements; Test `test/portal/policy.test.ts`, `test/portal/api-keys.test.ts`, `test/portal/audit-log.test.ts`.

Policy: form bound to GET/POST `/enterprise/policy`, fields require2fa, sessionMaxAgeS (select: off/1h/8h/24h/7d), allowedMethods checkboxes, groupRoleMap editor (rows displayName→role). API keys: list `/api-key/list`, create (name, expiresIn) shows key once, delete. Audit log: table from `/enterprise/audit/list` with filters (action select, actor, from/to), cursor pagination, "Export CSV" link to `/enterprise/audit/export?orgId&from&to` (`<a download>`), "Verify chain" → `/enterprise/audit/verify` with an ok/broken badge.

- [ ] Tests: policy form posts the changed fields only; api key shown once; audit table paginates via `nextCursor` and builds the export URL with the current filters. Commit `feat(portal): policy, api keys and audit log`.

---

### Task 13: Docs, README, CHANGELOG, publish

**Files:** Modify `README.md` (install, `enterprisePreset` snippet, `ab-enterprise migrate|verify|audit-verify`, portal embedding recipes for SvelteKit/Astro/Next from spike C, theming table, entitlements hook example with a Stripe-plan mapping), Create `docs/scim.md` (Users from upstream + our Groups; Okta/Entra setup notes; ResourceTypes limitation), `docs/sso.md` (wizard flow, DNS record, SP metadata URLs, `node:dns` caveat on Workers: run `verify-domain` on a Node leg or via DoH — v0.1 documents; P2 decides), `docs/security.md` (secrets, token storage, audit chain limits).

- [ ] Steps: `pnpm build` → `dist/` has the 5 entries + `sql/`; `npm pack --dry-run` lists only `dist sql README.md package.json`; PR `develop → main` (release grant from Bastien; the FIRST publish needs `NPM_TOKEN` in the repo secrets — Bastien creates a granular publish token for `@alphabros/enterprise` from the 1Password npm account); after `v0.1.0` is on npm, `npm view @alphabros/enterprise version` → `0.1.0`. Commit `docs: v0.1 README and guides`.

---

## Self-review

- **Spec coverage:** §3.1 preset/plugins/requireFeature → Tasks 2, 4, 5, 6, 7, 8; §3.2 schema/migrate/verify → Task 3; §3.3 client → Task 9; §3.4 portal (7 elements, theming) → Tasks 10–12; §3.5 studio_ref → Task 3; §4 tables → Task 3 (+ `scim_group`, `seq`, `group_role_map` additions justified in Tasks 4–6); §5 flows 1–5 → Tasks 5, 7, 8, 11; flow 6 (backfill) is per-product P2 — out of scope, stated; §7.1 CI items: vitest on libsql ✓, SAML in-process ✓ (Task 8), OIDC mock ✓, SCIM Users+Groups ✓ (Task 6; Users conformance relies on upstream + our deprovision test), audit tamper ✓ (Task 4), entitlement 403 table-driven ✓ (Task 7). Keycloak on atlas = ops follow-up task for `bro`, not package code.
- **Placeholders:** none of the forbidden phrases; every endpoint has a path, verb, body and response shape.
- **Type consistency:** `EnterpriseOptions`, `Feature`, `OrgPolicy`, `writeAudit`, `GATED_PATHS`, `effectiveRole`, `PortalApi` names are used identically across tasks. `opts.provisionUser` is referenced in Task 8 — add `provisionUser?: SSOOptions["provisionUser"]` to `EnterpriseOptions` in Task 2.

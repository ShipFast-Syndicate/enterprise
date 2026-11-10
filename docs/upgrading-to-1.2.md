# Upgrading to 1.2

1.2.0 is a minor release (semantic-release computes it from the `feat` commits since 1.1.3, with
no breaking-change footer). It adds three things, all **additive and opt-in**:

1. **Postgres support** (schema, migration, verify, audit writes, CLI).
2. **A staff-managed entitlement table** (`entitlements: { store: "table" }`).
3. **Staff-only organization creation and metadata** (`organization.creation` /
   `organization.metadata`).

A deployment that changes nothing is unaffected: no schema change, no migration to apply, no
behaviour change, and `ab-enterprise verify` / `verifyDatabase` expect exactly what they did before.
SQLite and libSQL (Turso) stay the default dialect.

Upgrading from 1.0.x or 0.1.x: do [`docs/upgrading-to-1.1.md`](./upgrading-to-1.1.md) first.

Two other changes are not opt-in and need a glance:

- `resolveEntitlements` is now optional in `EnterpriseOptions` (see
  [TypeScript note](#typescript-note-resolveentitlements-is-optional)).
- `FEATURES` (the `Feature` list) is exported from `@alphabros/enterprise/server`.

Dev toolchain: this release is tested against better-auth `1.7.19`. The peer ranges are unchanged
(`^1.7.10`), so you do not have to move.

## 1. Postgres (optional)

Nothing changes for SQLite/libSQL deployments. `pg` is an **optional** peer dependency
(`^8.0.0`): install it only to use the Postgres CLI or to give `applyMigrationPg` a `pg` client.

What is new:

| Piece                                                        | Where                                                                        |
| ------------------------------------------------------------ | ---------------------------------------------------------------------------- |
| Drizzle `pg-core` tables (`orgPolicy`, `auditEvent`, ...)    | `@alphabros/enterprise/schema/pg` (new subpath export)                       |
| `studioRefColumns()` for the `studio_ref` column             | `@alphabros/enterprise/schema/pg`                                            |
| `sql/pg/0001_enterprise.sql` (idempotent) and `0002_org_...` | shipped in the package, applied by `applyMigrationPg`                        |
| `applyMigrationPg(client, { entitlements? })`                | `@alphabros/enterprise/schema`                                               |
| `verifyDatabase(client, ...)` on a `pg` / PGlite client      | `@alphabros/enterprise/schema` (picks Postgres when there is no `execute()`) |
| `withPgAuditLock(db)` and `database: { dialect: "pg" }`      | `@alphabros/enterprise/server`                                               |
| `ab-enterprise ... --dialect pg`                             | CLI                                                                          |

### Steps for a Postgres deployment

1. **Tables.** Either spread the exported tables into your Drizzle schema
   (`import { enterpriseSchema, studioRefColumns } from "@alphabros/enterprise/schema/pg"`; spread
   `studioRefColumns()` into your `user` and `organization` tables), or write the SQL migration:
   `ab-enterprise migrate --dialect pg --out ./drizzle/migrations`, or
   `await applyMigrationPg(client)` at deploy time (see the caveat below).
2. **Audit writes.** Set `database: { dialect: "pg" }` in `enterprisePreset` and wrap the Drizzle
   database your adapter is built on:
   `drizzleAdapter(withPgAuditLock(db), { provider: "pg", transaction: true })`. The audit writer
   then takes a transaction-scoped advisory lock per organization before it reads the chain head
   (that includes SCIM's writes), so concurrent writers never hit the `(org_id, seq)` unique index
   inside an open transaction. Without `withPgAuditLock` the lock cannot be taken, one warning is
   logged, and only the unique-violation retry guards the write. The lock is held until the
   surrounding transaction ends: keep transactions that write audit rows short.
3. **Verify.** `AB_DATABASE_URL=postgres://... ab-enterprise verify`, or
   `verifyDatabase(client)` with a `pg` client. Run it after every deploy.

### `audit_event.metadata` is `json`, not `jsonb`

This is the one thing that bites. `jsonb` re-orders object keys, which changes the bytes the audit
hash chain was computed over and makes every later `audit-verify` fail. The shipped migration and
the exported Drizzle table use `json`. So:

- Do **not** regenerate `audit_event` with `@better-auth/cli generate` (it emits `jsonb` for `json`
  fields); take the table from `schema/pg` or `sql/pg/0001_enterprise.sql`.
- Do not "tidy" the column to `jsonb` in a later migration.
- `verifyDatabase` fails on a `jsonb` column and on a missing unique index (`audit_event
(org_id, seq)`, `org_policy (org_id)`, `enterprise_scim_member (member_id)`), so a wrong column
  type is caught at deploy time.

### Caveats

- `applyMigrationPg` is **not** wrapped in a transaction and must not run concurrently: a failure
  part-way leaves earlier statements applied. Re-running is safe (every statement is idempotent),
  so run it once per deploy, from a single process.
- **Drizzle adapter on `pg`** is the supported and tested path (`provider: "pg"`, with
  `transaction: true`). Array columns (`org_policy.allowed_methods`, `org_entitlement.features`)
  are native `text[]`, which needs an adapter that passes arrays to the driver as-is. The kysely
  adapter serialises arrays to a JSON string that Postgres rejects, so entitlement writes fail
  there.
- Timestamps are `timestamptz`; `audit-verify` reads them as dates, so keyed and compacted chains
  verify the same as on SQLite.

### CLI

`--dialect pg` works on `migrate`, `verify` and `audit-verify`. A `postgres://` or `postgresql://`
URL selects it on its own, so the flag is optional there. Credentials stay out of argv: the URL
comes from `AB_DATABASE_URL`, `DATABASE_URL` or `TURSO_DATABASE_URL`; `--url` is accepted only for a
URL without a password; `--dialect pg` with no URL at all uses the `PG*` environment variables.

```sh
ab-enterprise migrate --dialect pg --out ./drizzle/migrations   # sql/pg/0001 (+ 0002 with --entitlements)
AB_DATABASE_URL=postgres://... ab-enterprise verify
AB_DATABASE_URL=postgres://... AB_AUDIT_CHAIN_KEY=... ab-enterprise audit-verify --org org_123
```

Existing SQLite invocations (`--url`, `TURSO_DATABASE_URL`, `--from 0003`) behave as before.

## 2. Staff-managed entitlement table (opt-in)

`entitlements: { store: "table" }` resolves an organization's features from a new `org_entitlement`
table instead of a `resolveEntitlements` callback. Only platform staff can write it (never an
organization's owner, an API key, or an impersonation session), through
`POST /enterprise/entitlements/set` or `setEntitlements()`, audited as `entitlement.changed`.
Read [README, "Staff-managed entitlement table"](../README.md#staff-managed-entitlement-table) for
the API and [`docs/security.md`](./security.md#entitlements-why-not-organizationmetadata) for the
threat it closes: an organization's owner can write `organization.metadata`, so granting features
from it lets an owner entitle itself.

Also new: `GET /enterprise/features` resolves through the gate's per-request cache.

### TypeScript note: `resolveEntitlements` is optional

`EnterpriseOptions["resolveEntitlements"]` is now typed `ResolveEntitlements | undefined`, because
one of it or `entitlements: { store: "table" }` is required (a deployment with neither fails at
construction with a clear error, and a value that is not a function is rejected at construction).
Code that calls `opts.resolveEntitlements(...)` directly on an `EnterpriseOptions` value stops
compiling until it narrows (`opts.resolveEntitlements?.(orgId)`). To resolve features the supported
way, use `requireFeature` or `resolveEntitledFeatures` from `@alphabros/enterprise/server`.

### Callback-only deployments (nothing to do)

- Keep `resolveEntitlements`; the callback still decides and still fails closed.
- Do not apply the optional migration; do not pass `--entitlements`. `ab-enterprise migrate`
  without `--from`, and `--from 0003`, never write it; `verify` never expects it.
- Adds one endpoint, `POST /enterprise/entitlements/set`, which answers `403 NOT_PLATFORM_STAFF` to
  everyone but staff and `404 ENTITLEMENT_STORE_DISABLED` to staff on a deployment without the
  table store. It is listed as self-audited in `SELF_AUDITED_PATHS`; a product that mirrors the
  audit route table needs no change.

### Moving to the table store

1. **Stop trusting `organization.metadata`.** If your `resolveEntitlements` reads features from it,
   an owner of any org can grant itself everything today. Switch to the table (below) or to your
   billing system, then clear any entitlement keys out of existing organizations' metadata.
2. **Create the table** (idempotent, touches no existing table):
   - drizzle folder: `ab-enterprise migrate --out <folder> --entitlements` (the whole set on a new
     install) or, on SQLite, `ab-enterprise migrate --out <folder> --from 0004` (just this file).
     On Postgres add `--dialect pg --entitlements`;
   - or `applyMigration(client, { entitlements: true })` (SQLite/libSQL), or
     `applyMigrationPg(client, { entitlements: true })` (Postgres,
     `sql/pg/0002_org_entitlement.sql`);
   - Drizzle schema: spread `orgEntitlementSchema` from `@alphabros/enterprise/schema` (or
     `/schema/pg`) next to `enterpriseSchema`.
3. **Enable it**: `entitlements: { store: "table" }`; drop `resolveEntitlements` (a callback given
   with the table store still takes precedence, and the table is then written but not read for
   gating). Set `staffRoles` if your `admin()` plugin uses roles other than `"admin"`.
4. **Verify**: `ab-enterprise verify --entitlements` (or `verifyDatabase(client, { entitlements:
true })`) expects `org_entitlement`.
5. **Seed the features** for existing organizations as a staff user:
   `POST /enterprise/entitlements/set` `{ "orgId": "...", "features": ["sso", "scim"] }`. An
   organization with no row has no features, so do this before switching a paying tenant over.

**Table not migrated.** With `store: "table"` and no `org_entitlement` table, every gated route
fails closed with a 500 (not a `FEATURE_NOT_ENTITLED` 403) whose logged error names the migration
to apply. Run `ab-enterprise verify --entitlements` in your deploy to catch it first.

Rate limiting must be enabled in production for the staff route's 20-per-minute limit to apply
(better-auth leaves it off outside production by default).

Hand-composed plugin lists: the model is declared by `enterpriseGate(opts)` when `opts.entitlements`
is set, so mount the gate with the same options as `enterpriseApi(opts)` and no extra plugin is
needed.

## 3. Staff-only organization creation and metadata (opt-in)

`organization.creation` (`"self-service"` | `"staff-only"` | `(ctx) => boolean`) and
`organization.metadata` (`"open"` | `"staff-only"`) lock `/organization/create` and the `metadata`
field of `/organization/create` and `/organization/update` to platform staff (same definition as
`setEntitlements`, never an impersonation session) and server-only calls. Refusals are
`403 ORG_CREATION_STAFF_ONLY` / `403 ORG_METADATA_STAFF_ONLY`, audited as
`organization.write_refused` (a refusal for a caller who belongs to no organization has no chain
and is only logged). Defaults are unchanged and the preset's plugin list is identical until you set
one: the lock is a separate plugin (`enterprise-org-lock`) mounted only then. If you replace the
preset's `organization()` entry, nothing changes for you: the lock still applies. Hand-composed
lists add `orgWriteLock(opts)` after `enterpriseGate(opts)`. Read
[`docs/security.md`](./security.md#staff-only-organization-creation-and-metadata) for the audit
rules and how this differs from upstream's `allowUserToCreateOrganization`. If you keep plans or
flags in `organization.metadata`, set `metadata: "staff-only"` and write it from staff or server
code.

## Smaller fixes in this release

- An SSO registration that races another on the same `providerId` now answers a client error
  instead of a server error.
- The audit hash byte format is frozen by golden-vector tests: a future refactor cannot change what
  existing chains verify against.
- Dev dependencies (better-auth family `1.7.19`, tooling) are bumped; none of it changes the
  published peer ranges.

## Checklist

- [ ] SQLite/libSQL, callback entitlements, no lock: upgrade the package, nothing else.
- [ ] Postgres: tables from `schema/pg` or `sql/pg`, `database: { dialect: "pg" }`,
      `withPgAuditLock(db)`, `ab-enterprise verify`, and confirm `audit_event.metadata` is `json`.
- [ ] Table store: migrate, enable, seed features, `verify --entitlements`.
- [ ] Staff-only org creation: set `organization.creation` / `organization.metadata`.

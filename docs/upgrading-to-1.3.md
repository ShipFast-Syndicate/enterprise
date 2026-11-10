# Upgrading to 1.3

1.3.0 is a minor release that adds one **opt-in** feature: a staff-managed entitlement table. A
deployment that changes nothing is unaffected — no schema change, no migration to apply, no
behaviour change, and `ab-enterprise verify` / `verifyDatabase` expect exactly what they did before.

## What is new

`entitlements: { store: "table" }` resolves an organization's features from a new `org_entitlement`
table instead of a `resolveEntitlements` callback. Only platform staff can write it (never an
organization's owner, an API key, or an impersonation session), through
`POST /enterprise/entitlements/set` or `setEntitlements()`, audited as `entitlement.changed`.
Read [README, "Staff-managed entitlement table"](../README.md#staff-managed-entitlement-table) for
the API and [`docs/security.md`](./security.md#entitlements-why-not-organizationmetadata) for the
threat it closes: an organization's owner can write `organization.metadata`, so granting features
from it lets an owner entitle itself.

Also: `resolveEntitlements` is now optional in `EnterpriseOptions` (one of it or
`entitlements: { store: "table" }` is required — a deployment with neither fails at construction
with a clear error), `GET /enterprise/features` resolves through the gate's per-request cache, and
`FEATURES` (the `Feature` list) is exported from `@alphabros/enterprise/server`.

**TypeScript note:** because of that, `EnterpriseOptions["resolveEntitlements"]` is typed
`ResolveEntitlements | undefined`. Code that calls `opts.resolveEntitlements(...)` directly on an
`EnterpriseOptions` value stops compiling until it narrows (`opts.resolveEntitlements?.(orgId)`);
to resolve features the supported way, use `requireFeature` or `resolveEntitledFeatures` from
`@alphabros/enterprise/server`. At runtime a value that is not a function is now rejected at
construction.

## Callback-only deployments (nothing to do)

- Keep `resolveEntitlements`; the callback still decides and still fails closed.
- Do not apply the optional migration; do not pass `--entitlements`. `ab-enterprise migrate`
  without `--from`, and `--from 0003`, never write it; `verify` never expects it.
- Adds one endpoint, `POST /enterprise/entitlements/set`, which answers
  `403 NOT_PLATFORM_STAFF` to everyone but staff and `404 ENTITLEMENT_STORE_DISABLED` to staff on a
  deployment without the table store. It is listed as self-audited in `SELF_AUDITED_PATHS`; a
  product that mirrors the audit route table needs no change.

## Moving to the table store

1. **Stop trusting `organization.metadata`.** If your `resolveEntitlements` reads features from it,
   an owner of any org can grant itself everything today. Switch to the table (below) or to your
   billing system, then clear any entitlement keys out of existing organizations' metadata.
2. **Create the table** (idempotent, touches no existing table):
   - drizzle folder: `ab-enterprise migrate --out <folder> --entitlements` (the whole set on a new
     install) or `ab-enterprise migrate --out <folder> --from 0004` (just this file);
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

**Postgres adapter.** `org_entitlement.features` is a native `text[]` on Postgres, like
`org_policy.allowed_methods`. It needs a better-auth adapter that hands arrays to the driver
as-is: the drizzle adapter on `pg` is supported and tested end to end
(`test/security/entitlement-store-pg.test.ts`). The kysely adapter serialises arrays to a JSON
string, which Postgres rejects for a `text[]` column, so `setEntitlements` would fail there.

**Table not migrated.** With `store: "table"` and no `org_entitlement` table, every gated route
fails closed with a 500 (not a `FEATURE_NOT_ENTITLED` 403) whose logged error names the migration
to apply. Run `ab-enterprise verify --entitlements` in your deploy to catch it first.

Rate limiting must be enabled in production for the staff route's 20-per-minute limit to apply
(better-auth leaves it off outside production by default).

Hand-composed plugin lists: the model is declared by `enterpriseGate(opts)` when `opts.entitlements`
is set, so mount the gate with the same options as `enterpriseApi(opts)` and no extra plugin is
needed.

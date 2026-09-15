# SCIM 2.0 provisioning

`@alphabros/enterprise` exposes a single SCIM 2.0 base URL per organization:
`/api/auth/scim/v2` (adjust the prefix if your product mounts better-auth
somewhere other than `/api/auth`). An identity provider (Okta, Entra ID, or
any SCIM 2.0 client) is pointed at this URL with a bearer token minted from
the security portal.

## Users vs. Groups — two different implementations

| Resource | Implemented by | Endpoints |
| --- | --- | --- |
| **Users** | upstream `@better-auth/scim` (peer dependency) | `GET/POST /scim/v2/Users`, `GET/PATCH/PUT/DELETE /scim/v2/Users/:id` |
| **Groups** | this package's own `scimGroups()` plugin (`src/server/scim-groups/`) | `GET/POST /scim/v2/Groups`, `GET/PATCH/DELETE /scim/v2/Groups/:groupId` |

`@better-auth/scim` 1.6 has no SCIM Groups support at all — `scimGroups()` is
an in-house fill of that gap (FDR-enterprise-0001), not a wrapper around an
upstream feature. A SCIM "Group" maps 1:1 to an organization **team**
(`organization({ teams: { enabled: true } })`, already registered by
`enterprisePreset`): `Group.id` is the team id, `Group.displayName` is the
team name, and `members` are `teamMember` rows. `scimGroups` stores only
what `team` doesn't already carry — `externalId` and its own timestamps — in
a small `scim_group` table (see the schema doc / `sql/0001_enterprise.sql`).

`groupRoleMap` (`EnterpriseOptions.scim.groupRoleMap`) maps a SCIM group's
`displayName` to an org role (`owner` | `admin` | `member`) that a member of
that group is granted in addition to their base role — e.g. map an IdP
group called `Acme-Admins` to `admin` so anyone your IdP puts in that group
is provisioned as an org admin.

## `ResourceTypes` limitation

`GET /scim/v2/ResourceTypes` is left exactly as `@better-auth/scim`
registers it: it advertises **Users only**. An identity provider that reads
this endpoint to auto-discover supported resource types will not see Groups
listed there, even though the `/scim/v2/Groups*` endpoints exist and work.
This is a known v0.1 gap, not an oversight — most IdPs (Okta, Entra ID) let
you enable group provisioning manually regardless of what `ResourceTypes`
advertises; see the setup notes below. A future release may register Groups
in `ResourceTypes` once the upstream Users implementation and this
in-house Groups implementation are reconciled into one plugin.

## Setup notes

### Okta

1. In the Okta application's **Provisioning** tab, enable **SCIM
   provisioning** and set the **SCIM connector base URL** to
   `https://<your-app>/api/auth/scim/v2`.
2. **Unique identifier field for users**: `email`.
3. Paste the bearer token from `<ab-scim-tokens>` (or
   `POST /enterprise/scim/tokens/create`) as the **Bearer Token**
   authentication value.
4. Under **Provisioning to App**, enable *Create Users*, *Update User
   Attributes*, and *Deactivate Users*.
5. **Group push**: Okta's group-push UI does not gate on `ResourceTypes`
   advertising Groups — add the groups you want pushed under **Push
   Groups** and they provision against `/scim/v2/Groups` normally. Map the
   pushed group's name to `groupRoleMap` if it should carry a role.

### Microsoft Entra ID (Azure AD)

1. In the enterprise application's **Provisioning** blade, set **Provisioning
   Mode** to *Automatic*.
2. **Tenant URL**: `https://<your-app>/api/auth/scim/v2`.
3. **Secret Token**: the bearer token from the portal.
4. Click **Test Connection** — it exercises `GET /scim/v2/Users` and
   `GET /scim/v2/ResourceTypes`; a green result only confirms Users support
   (see the limitation above), not Groups.
5. Under **Mappings**, both *Provision Azure Active Directory Users* and
   *Provision Azure Active Directory Groups* can be left enabled — Entra
   does not require `ResourceTypes` to list `Group` before it will attempt
   `/scim/v2/Groups` calls; verify with a small pilot group first.

## Deprovisioning behaviour

A SCIM deactivate (`PATCH .../Users/:id` with `active: false`) or delete
does four things in one operation (`src/server/policy/deprovision.ts`):

1. suspends the user in that organization,
2. revokes **all** of their sessions,
3. revokes the API keys they own in that organization,
4. writes an `audit_event` row.

## Token storage

Tokens are stored **hashed** (`scim({ storeSCIMToken: "hashed" })`, set by
`enterprisePreset` and not overridable) and bound to the organization that
generated them (`scim({ providerOwnership: { enabled: true } })`) — see
[`security.md`](./security.md) for why, and for the accepted-advisory note
this defends against.

## Portal component

`<ab-scim-tokens>` (`@alphabros/enterprise/portal`) lists existing tokens
(id, provider, last-used, created), creates a new one (shown once, then
never retrievable again — copy it into the IdP immediately), and revokes
one. It talks to `/enterprise/scim/tokens`, `/enterprise/scim/tokens/create`,
and `/enterprise/scim/tokens/revoke` — all gated on `requireFeature('scim')`.

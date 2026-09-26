# SCIM provisioning

The preset uses Better Auth **1.7.5** native Users and Groups at `/api/auth/scim/v2`.
Both resources are isolated by connection and gated on the organization's `scim`
entitlement. Supply `scimCredentialHashSecret` independently from the SSO encryption
key, and enable interactive adapter transactions (`transaction: true` for Drizzle).
D1 is not supported by this SCIM adapter contract.

## Credentials

Use the portal's `/enterprise/scim/tokens` endpoints with an explicit `orgId`:

- `GET /tokens?orgId=…`: owner/admin metadata listing; no bearer or digest.
- `POST /tokens/create { orgId, providerId }`: owner-only, one-time bearer and expiry.
- `POST /tokens/rotate { orgId, providerId }`: owner-only; old token stops immediately.
- `POST /tokens/revoke { orgId, providerId }`: owner-only decommission, including
  the access this connection provisioned (since 1.1.0; it was owner/admin before —
  a decommission replays every provisioned user as inactive, which is a
  platform-wide deprovision). A user who holds an `owner` membership anywhere is
  never banned by that replay (their API keys are still revoked, audited as
  `api_key.revoked`; the skipped ban is audited as `scim.user_deactivation_skipped`).
  `202` means cleanup is in progress; continue the same request until `ok: true`.
  The portal exposes Continue removal.

Provider labels have a maximum of 64 characters and are unique among active
connections within an organization. The same label in another organization is
independent. Native catalog APIs remain server-only; do not expose them directly.

## Identity and roles

Send standard SCIM `schemas` URNs. Group member `value` is a SCIM User resource ID,
**not** a core user ID or team ID. The native implementation handles list/filter,
pagination, PATCH and PUT. SCIM groups no longer create Better Auth teams.

Provisioning creates a core user without an authentication Account. Matching an
existing email never links an identity automatically. Provision identities before
SSO. To pair them, use the **same provider ID** for the SCIM connection and the
verified SSO provider in that organization. Send the case-exact OIDC `sub` (or
SAML account subject) as SCIM `externalId`. The transaction-bound resolver links
only that active connection and subject; email matching is never used. JIT creation is
blocked while an organization has an active or decommissioning SCIM connection.

`scim.groupRoleMap` (or the owner's organization policy override) maps group names
to `member` or `admin`. Ownership cannot be granted by SCIM. The projector only
changes memberships it created and still owns. A manual role change relinquishes
that ownership. Memberships in other organizations remain untouched.

Deactivating the final identity source bans the core user, revokes sessions and
every one of the user's API keys (keys are user-global — the revocation is audited
as `api_key.revoked`, one row per key, into every organization the user belongs to,
the provisioning organization included), and removes SCIM-owned organization
access. A user holding an `owner` membership anywhere is not banned (the skipped
ban is audited as `scim.user_deactivation_skipped` in the provisioning
organization); their keys are revoked all the same. Reactivation clears only the
SCIM ban; an unrelated manual administrator ban is retained. Group, user and
credential changes are audited. Native catalog events retain credential history.

## Upgrade

Read [migration-1-7.md](./migration-1-7.md) before upgrading a 0.1 installation.
Legacy token formats and the `scimGroups` plugin are retired. Existing core users,
authentication accounts, sessions and manual memberships are preserved by the
additive database migration; old provisioning resources require explicit IdP
reprovisioning rather than automatic email-based linking.

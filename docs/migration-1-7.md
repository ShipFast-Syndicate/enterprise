# Migration from enterprise 0.1 / Better Auth 1.6

This release pins the complete Better Auth peer set to 1.7.5, including SCIM's
patched connection catalog. It removes the GHSA-j8v8-g9cx-5qf4 audit exception.

1. Back up the database and test a restore. Inventory existing SCIM providers,
   users and groups; freeze provisioning during the cutover.
2. Upgrade all six auth peers together to 1.7.5 and `better-call` to 1.4.0.
   Enable native interactive transactions on the database adapter. Do not use D1.
3. Generate upstream auth tables from the **actual product configuration**.
   There are ten new SCIM models: managed connection, credential, event, connection
   binding, identity tombstone, subject, user, projection grant, group and member.
   Preserve the upstream unique keys and indexes. Do not rename legacy `scim_group`
   into native `scimGroup`: their shapes and identities differ.
4. Apply enterprise `0002_scim_1_7.sql` through `applyMigration` (idempotent), or the
   equivalent product migration. It adds policy adapter IDs and the
   `enterprise_scim_member` ownership marker. Legacy provisioning tables remain
   untouched for recovery; the new plugin does not read them.
5. Provision a separate random `ENTERPRISE_SCIM_CREDENTIAL_HASH_SECRET` (at least
   32 characters) and pass it as `scimCredentialHashSecret`. Retain the existing
   `ENTERPRISE_SECRETS_KEY` unchanged so stored SSO secrets remain decryptable.
6. Recreate SCIM connections through the owner-authorized portal, replace the
   bearer in the IdP and perform full reprovisioning. New SCIM resource IDs differ
   from both old core user IDs and group/team IDs. A collision with an existing
   user's email fails closed; linking requires an application-owned, stable,
   verified identity mapping. This release does not infer such a mapping.
7. Verify normal sign-in, SSO, active/deactivated users, token rotation, group
   grants, audit chains, and cross-organization denial on staging before rollout.

Better Auth 1.7.3 reverted the account issuer-column change. A direct 1.6 to
**1.7.5** migration does not need that column or an issuer backfill. Still check
for duplicate `(providerId, accountId)` pairs and validate any Microsoft OAuth
identity transition against the actual product's providers.

For the first Nomi pilot, staging had no active SCIM integrations or enterprise
tables at inventory time. Its additive migration can therefore install the new
models without converting live SCIM resources. Recheck this condition at rollout.

Rollback: disable the enterprise pilot, restore the prior dependency/deployment
set, and restore the verified backup if live provisioning has changed data.
Do not roll back only the package after enabling new SCIM clients; old tokens and
new connection identities are incompatible.

Primary references: [Better Auth upgrade guide](https://better-auth.com/docs/guides/1-7-upgrade-guide),
[SCIM documentation](https://better-auth.com/docs/plugins/scim).

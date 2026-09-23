import { acquireActiveSCIMUserLink, type SCIMManagedConnection } from "@better-auth/scim";
import type { sso } from "@better-auth/sso";
import { scimConnectionLabel } from "./scim-connection";

type Resolver = NonNullable<NonNullable<Parameters<typeof sso>[0]>["resolveUser"]>;
/** Pair an SSO provider only to its own organization's same-label SCIM connection. */
export const resolveScimSsoUser: Resolver = async (input, context) => {
  if (input.providerReference.source.type !== "persisted") return { action: "continue" };
  const provider = await context.database.findOne<{
    organizationId: string | null;
    domainVerified: boolean;
  }>({
    model: "ssoProvider",
    where: [
      { field: "id", value: input.providerReference.source.recordId },
      { field: "providerId", value: input.providerId },
    ],
  });
  if (!provider?.organizationId) return { action: "continue" };
  const connections = await context.database.findMany<SCIMManagedConnection>({
    model: "scimManagedConnection",
    where: [
      { field: "provisioningDomainId", value: provider.organizationId },
      { field: "status", value: "decommissioned", operator: "ne" },
    ],
    limit: 1001,
  });
  if (!connections.length) return { action: "continue" };
  const matches = connections.filter((c) => scimConnectionLabel(c) === input.providerId);
  if (!provider.domainVerified || matches.length !== 1 || connections.length > 1000)
    return { action: "reject", code: "SCIM_PROVISIONING_REQUIRED" };
  const link = await acquireActiveSCIMUserLink(
    { connectionId: matches[0]!.connectionId, externalId: input.accountKey.accountId },
    context,
  );
  return link
    ? { action: "link", userId: link.userId, profile: "preserve" }
    : { action: "reject", code: "SCIM_USER_NOT_ACTIVE" };
};

/** Changing the IdP boundary requires retiring its provisioning authority first. */
export const guardScimSsoProviderMutation: NonNullable<
  NonNullable<Parameters<typeof sso>[0]>["guardProviderMutation"]
> = async (input, context) => {
  if (
    !input.provider.organizationId ||
    (input.action === "update" && !input.isAuthenticationBoundaryChange)
  )
    return;
  const connections = await context.database.findMany<SCIMManagedConnection>({
    model: "scimManagedConnection",
    where: [
      { field: "provisioningDomainId", value: input.provider.organizationId },
      { field: "status", value: "decommissioned", operator: "ne" },
    ],
    limit: 1001,
  });
  if (
    connections.length > 1000 ||
    connections.some((c) => scimConnectionLabel(c) === input.provider.providerId)
  ) {
    throw new Error(
      "Decommission the paired SCIM connection before changing its SSO provider identity.",
    );
  }
};

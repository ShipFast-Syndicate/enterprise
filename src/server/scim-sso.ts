import { acquireActiveSCIMUserLink, type SCIMManagedConnection } from "@better-auth/scim";
import type { sso } from "@better-auth/sso";
import { notePolicyRefusal } from "./audit/refusal";
import { scimConnectionLabel } from "./scim-connection";

export type SsoResolver = NonNullable<NonNullable<Parameters<typeof sso>[0]>["resolveUser"]>;
type Resolver = SsoResolver;

type ScimSignInRefusal = "SCIM_PROVISIONING_REQUIRED" | "SCIM_USER_NOT_ACTIVE";

/** The `ssoProvider` columns a resolver reads (`oidcConfig` is JSON text, or already decoded by some adapters). */
export interface PersistedSsoProvider {
  id: string;
  providerId: string;
  organizationId: string | null;
  domain: string;
  domainVerified: boolean;
  issuer: string;
  oidcConfig?: unknown;
}

/**
 * The persisted `ssoProvider` row a resolver call is about, read through the
 * sign-in transaction's database with both the record id the provider
 * reference names and the provider id; `null` for a provider that is not
 * persisted (`providerReference.source` is an object, `{ type: "configured" }`
 * for a `defaultSSO` entry) or that no longer has a row. Shared by the SCIM
 * pairing below and the 1.3 SSO options (`./sso-resolve.ts`).
 */
export async function findPersistedSsoProvider(
  input: Pick<Parameters<Resolver>[0], "providerId" | "providerReference">,
  context: Parameters<Resolver>[1],
): Promise<PersistedSsoProvider | null> {
  const source = input.providerReference.source;
  if (source.type !== "persisted") return null;
  return context.database.findOne<PersistedSsoProvider>({
    model: "ssoProvider",
    where: [
      { field: "id", value: source.recordId },
      { field: "providerId", value: input.providerId },
    ],
  });
}

/** A refusal upstream throws on our behalf — marked as this package's own for the audit log (`notePolicyRefusal`). */
function rejectSignIn(refusal: ScimSignInRefusal) {
  notePolicyRefusal(refusal);
  return { action: "reject", code: refusal } as const;
}

/** Pair an SSO provider only to its own organization's same-label SCIM connection. */
export const resolveScimSsoUser: Resolver = async (input, context) => {
  const provider = await findPersistedSsoProvider(input, context);
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
    return rejectSignIn("SCIM_PROVISIONING_REQUIRED");
  const link = await acquireActiveSCIMUserLink(
    { connectionId: matches[0]!.connectionId, externalId: input.accountKey.accountId },
    context,
  );
  return link
    ? { action: "link", userId: link.userId, profile: "preserve" }
    : rejectSignIn("SCIM_USER_NOT_ACTIVE");
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

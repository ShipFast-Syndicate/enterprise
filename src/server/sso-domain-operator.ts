// Alpha Bros enterprise layer — operator-attested SSO domain verification
// (`sso.domainVerificationMode: "operator"`, 1.3).
//
// Upstream proves domain ownership with a DNS TXT lookup
// (`POST /sso/verify-domain`, `dns.resolveTxt` from `node:dns/promises`).
// That lookup is not available on every runtime — Cloudflare Workers is the
// one this exists for — and `domainVerified` is what every SSO trust decision
// reads (`./policy/sso-jit.ts`, `./policy/domains.ts`, the callback itself), so
// a deployment that cannot run the lookup needs another way to set it. This is
// that way, and it is deliberately narrow:
//
// - **Server-only.** A plain function over the auth instance, the shape
//   `setEntitlements` has (`./entitlement-store.ts`): no endpoint, no route, no
//   cookie or token anybody can present. Whoever can call it already holds the
//   deployment's database credentials.
// - **Opt-in.** It throws unless `sso.domainVerificationMode` is `"operator"`,
//   which is also what closes the two DNS endpoints (`./sso-domain.ts`) — one
//   mode, one way to verify, never both.
// - **Unique.** The domain must not be verified by another provider (the same
//   F-30 rule `/sso/verify-domain` applies, `findVerifiedProvidersOverlapping`).
// - **Audited.** One `sso.domain_verified` row in the provider's organization
//   chain, `method: "operator"`, with the operator's name and the evidence they
//   give, written in the same transaction as the flag.
//
// It is an assertion by the operator, not a proof: nothing here checks DNS.
// The write copies upstream's own (`completeDomainVerification`,
// `@better-auth/sso` `src/routes/domain-verification.ts`): `incrementOne` with
// `where: id + domain` and `set: { domainVerified: true }`, so a provider whose
// domain changed in between is not verified for the old one.

import type { AuthContext, GenericEndpointContext } from "better-auth";
import { APIError } from "better-auth/api";
import { runWithTransaction } from "@better-auth/core/context";
import { auditId } from "./audit/bounds";
import { writeAudit } from "./audit/chain";
import { enterpriseOptionsOfContext } from "./entitlement-store";
import { normalizeProviderDomains } from "./policy/domains";
import { domainTakenError, findVerifiedProvidersOverlapping } from "./sso-domain";

/** The audit action both verification paths write (`./audit/routes.ts` names it for `/sso/verify-domain`). */
export const SSO_DOMAIN_VERIFIED_ACTION = "sso.domain_verified";

/** Longest `evidence` text accepted, in characters. */
export const SSO_DOMAIN_EVIDENCE_MAX_LENGTH = 500;
const ACTOR_MAX_LENGTH = 200;

export interface VerifySsoDomainOperatorInput {
  /** The `providerId` of the SSO provider whose domain is being verified. */
  providerId: string;
  /** What the operator checked, for the audit row (a ticket, a DNS lookup they ran): non-empty, at most 500 characters. */
  evidence: string;
  /** Who vouches for it — an operator id or name, at most 200 characters; recorded in the audit row, never trusted for anything else. */
  actor: string;
}

function invalidInput(message: string): APIError {
  return new APIError("BAD_REQUEST", { code: "SSO_DOMAIN_VERIFICATION_INPUT_INVALID", message });
}

function boundedText(value: unknown, name: string, max: number): string {
  if (typeof value !== "string" || value.trim().length === 0 || value.length > max) {
    throw invalidInput(`"${name}" must be a non-empty string of at most ${max} characters.`);
  }
  return value.trim();
}

interface ProviderRow {
  id: string;
  providerId: string;
  organizationId: string | null;
  domain: string;
  domainVerified: boolean;
}

/**
 * Server API: marks the SSO provider's domain verified on the operator's word
 * and audits it. `auth` is the better-auth instance built with
 * `sso: { domainVerificationMode: "operator" }`. Resolves with the provider
 * and its organization. Throws an `APIError` (`code` in `body`) for every
 * refusal: `SSO_DOMAIN_VERIFICATION_NOT_OPERATOR_MODE`,
 * `SSO_DOMAIN_VERIFICATION_INPUT_INVALID`, `SSO_PROVIDER_NOT_FOUND`,
 * `DOMAIN_VERIFIED` (already verified), `SSO_PROVIDER_NOT_ORG_SCOPED`,
 * `SSO_DOMAIN_INVALID`, `SSO_DOMAIN_TAKEN`, `SSO_PROVIDER_CHANGED`.
 */
export async function verifySsoDomainOperator(
  auth: { $context: PromiseLike<unknown> },
  input: VerifySsoDomainOperatorInput,
): Promise<{ providerId: string; organizationId: string; domain: string }> {
  // `$context` is typed per auth instance (its own option set); the layer
  // only relies on the surface every instance shares.
  const context = (await auth.$context) as AuthContext;
  const opts = enterpriseOptionsOfContext(context);
  if (opts.sso?.domainVerificationMode !== "operator") {
    throw new APIError("FORBIDDEN", {
      code: "SSO_DOMAIN_VERIFICATION_NOT_OPERATOR_MODE",
      message:
        'Operator domain verification is off: set sso.domainVerificationMode to "operator" to use it.',
    });
  }
  const providerId = boundedText(input?.providerId, "providerId", 256);
  const evidence = boundedText(input?.evidence, "evidence", SSO_DOMAIN_EVIDENCE_MAX_LENGTH);
  const actor = boundedText(input?.actor, "actor", ACTOR_MAX_LENGTH);

  const adapter = context.adapter;
  const provider = await adapter.findOne<ProviderRow>({
    model: "ssoProvider",
    where: [{ field: "providerId", value: providerId }],
  });
  if (!provider) {
    throw new APIError("NOT_FOUND", {
      code: "SSO_PROVIDER_NOT_FOUND",
      message: "No SSO provider with this id exists.",
    });
  }
  if (provider.domainVerified) {
    throw new APIError("CONFLICT", {
      code: "DOMAIN_VERIFIED",
      message: "Domain has already been verified",
    });
  }
  // The audit chain is per organization; an org-less (legacy "personal")
  // provider has none to record the attestation in, so it is refused rather
  // than verified unaudited.
  const organizationId = provider.organizationId;
  if (!organizationId) {
    throw new APIError("BAD_REQUEST", {
      code: "SSO_PROVIDER_NOT_ORG_SCOPED",
      message: "Only a provider that belongs to an organization can be verified by the operator.",
    });
  }
  const domains = normalizeProviderDomains(provider.domain);
  if (!domains) {
    throw new APIError("BAD_REQUEST", {
      code: "SSO_DOMAIN_INVALID",
      message: "The provider's domain is not a comma-separated list of plain hostnames.",
    });
  }
  const ctx = { context } as unknown as GenericEndpointContext;
  const taken = await findVerifiedProvidersOverlapping(ctx, domains, {
    excludeOrgId: organizationId,
    excludeProviderId: provider.providerId,
  });
  if (taken.length > 0) throw domainTakenError(domains, taken);

  await runWithTransaction(adapter, async () => {
    const updated = await adapter.incrementOne({
      model: "ssoProvider",
      where: [
        { field: "id", value: provider.id },
        { field: "domain", value: provider.domain },
      ],
      increment: {},
      set: { domainVerified: true },
    });
    if (!updated) {
      throw new APIError("CONFLICT", {
        code: "SSO_PROVIDER_CHANGED",
        message:
          "SSO provider changed while domain verification was in progress. Reload the provider and try again",
      });
    }
    await writeAudit(
      { context },
      {
        orgId: organizationId,
        actorType: "system",
        actorId: null,
        action: SSO_DOMAIN_VERIFIED_ACTION,
        targetType: "sso_provider",
        targetId: auditId(provider.providerId),
        metadata: { method: "operator", actor, evidence },
      },
    );
  });
  return { providerId: provider.providerId, organizationId, domain: provider.domain };
}

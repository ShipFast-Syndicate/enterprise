// Alpha Bros enterprise layer — home-realm discovery.
//
// `findOrgByEmailDomain` is the single domain -> org/provider lookup every
// SSO-enforcement path needs (the sign-in hooks and `databaseHooks.session.
// create.before` in `./plugin.ts`, and this file's own `/enterprise/
// home-realm` endpoint) — kept here, not in `./plugin.ts`, so `./plugin.ts`
// can import it from this (leaf) module without the two files importing
// each other.
//
// `POST /enterprise/home-realm { email }` is public (no session — a sign-in
// page calls this before the visitor has authenticated at all) and answers
// "home realm discovery" for a sign-in UI: redirect straight to the org's
// SSO provider, or fall back to the normal local sign-in form. Per the
// controller ruling, the response must never leak whether the email belongs
// to an existing user — it only reflects whether the email's *domain* has a
// verified SSO provider, which is public information about an organization,
// not about any individual account, so both branches below are safe to
// return regardless of whether `email` is a real user.

import type { GenericEndpointContext } from "better-auth";
import { createAuthEndpoint } from "better-auth/api";
import * as z from "zod";

export const HOME_REALM_PATH = "/enterprise/home-realm";

function getEmailDomain(email: string): string | null {
  const at = email.lastIndexOf("@");
  if (at === -1 || at === email.length - 1) return null;
  return email.slice(at + 1).toLowerCase();
}

interface SsoProviderRow {
  providerId: string;
  organizationId: string | null;
}

/**
 * `ssoProvider` where `domain` = the email's domain (case-insensitive) and
 * `domainVerified` = true. `domain` is a required, non-unique field on
 * `ssoProvider` (`node_modules/@better-auth/sso/dist/index.mjs`'s schema) —
 * multiple providers could in principle claim the same verified domain, in
 * which case the first match wins; provider registration/domain-verification
 * (upstream `sso()`, gated `"sso"` by `./gate.ts`) is the place that would
 * need to prevent that ambiguity, not this read path.
 */
export async function findOrgByEmailDomain(
  ctx: GenericEndpointContext,
  email: string,
): Promise<{ orgId: string; providerId: string } | null> {
  const domain = getEmailDomain(email);
  if (!domain) return null;
  const provider = await ctx.context.adapter.findOne<SsoProviderRow>({
    model: "ssoProvider",
    where: [
      { field: "domain", value: domain },
      { field: "domainVerified", value: true },
    ],
  });
  if (!provider?.organizationId) return null;
  return { orgId: provider.organizationId, providerId: provider.providerId };
}

const homeRealmBodySchema = z.object({ email: z.email() });

export const homeRealmEndpoint = createAuthEndpoint(
  HOME_REALM_PATH,
  { method: "POST", body: homeRealmBodySchema },
  async (ctx) => {
    const match = await findOrgByEmailDomain(
      ctx as unknown as GenericEndpointContext,
      ctx.body.email,
    );
    if (match) {
      return ctx.json({ method: "sso" as const, providerId: match.providerId });
    }
    return ctx.json({ method: "local" as const });
  },
);

/** `BetterAuthPlugin["rateLimit"]` entry — merged into `orgPolicy()`'s returned plugin. */
export const HOME_REALM_RATE_LIMIT = {
  pathMatcher: (path: string) => path === HOME_REALM_PATH,
  window: 60,
  max: 10,
};

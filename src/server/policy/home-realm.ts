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
import { findOrgsByEmailDomain } from "./domains";

export { findOrgsByEmailDomain, type EmailDomainMatch } from "./domains";

export const HOME_REALM_PATH = "/enterprise/home-realm";

/**
 * The first (most specific domain, then lowest `providerId`) org-scoped,
 * domain-verified `ssoProvider` whose `domain` list authorizes the email's
 * domain — or `null`. A thin wrapper over `findOrgsByEmailDomain`
 * (`./domains.ts`), kept for the public export and the callers that only
 * need one answer (this file's `/enterprise/home-realm`).
 *
 * Matching follows upstream `@better-auth/sso` semantics — comma-separated
 * lists, case-insensitive, subdomains — instead of the exact, case-sensitive
 * `findOne({domain})` it used to be (F-04), so a provider registered as
 * `"Acme.test, acme-two.test"` now routes `x@eu.acme.test` to SSO the same
 * way upstream's own `/sign-in/sso {email}` already did. Multiple providers
 * can still claim overlapping verified domains; preventing that ambiguity is
 * the registration path's job, not this read path's.
 */
export async function findOrgByEmailDomain(
  ctx: GenericEndpointContext,
  email: string,
): Promise<{ orgId: string; providerId: string } | null> {
  const first = (await findOrgsByEmailDomain(ctx, email))[0];
  return first ? { orgId: first.orgId, providerId: first.providerId } : null;
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

// GHSA-8p84-pc7q-69jr — F-01(c): the invitation gate. An account whose
// e-mail is not verified cannot accept (or reject) an organization
// invitation, so an account minted for someone else's address can never
// cash in the invitation meant for that address's real owner. The preset
// sets upstream `organization({ requireEmailVerificationOnInvitation: true })`
// (foundations); this file pins the behaviour end to end and the one case
// the domain binding adds: a domain-bound SSO user *is* verified and claims
// the invited role straight away (RED on the parent, where a JIT user was
// stored unverified and refused).
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createOrg, makeAuth, signUpOwner, type TestAuth } from "../helpers/auth";
import { startOidcIssuer, type OidcIssuer } from "../helpers/oidc-issuer";
import { registerOidcProvider } from "../helpers/sso";
import { driveSsoSignIn, sessionCookieOf, sessionOf } from "./ghsa-sso-helpers";

const UPSTREAM_CODE = "EMAIL_VERIFICATION_REQUIRED_BEFORE_ACCEPTING_OR_REJECTING_INVITATION";

async function invite(
  t: TestAuth,
  ownerCookie: string,
  orgId: string,
  email: string,
  role = "admin",
) {
  const res = await t.api.post(
    "/organization/invite-member",
    { email, role, organizationId: orgId },
    { cookie: ownerCookie },
  );
  expect(res.status).toBe(200);
  return ((await res.json()) as { id: string }).id;
}

async function memberRole(t: TestAuth, orgId: string, userId: string): Promise<string | null> {
  const rows = await t.client.execute({
    sql: `SELECT role FROM member WHERE organizationId = ? AND userId = ?`,
    args: [orgId, userId],
  });
  return rows.rows.length ? String(rows.rows[0]!.role) : null;
}

describe("F-01(c) — invitations require a verified e-mail", () => {
  it("an unverified password account holding the invitation id can neither accept nor reject it", async () => {
    const t = await makeAuth();
    const owner = await signUpOwner(t, "owner@acme.test");
    const { orgId } = await createOrg(t, owner.cookie, "acme");
    const invitationId = await invite(t, owner.cookie, orgId, "ceo@acme.test");
    // A password sign-up is stored `emailVerified: false` (no verification
    // e-mail wired in this suite) — the same state a squatted account is in.
    const holder = await signUpOwner(t, "ceo@acme.test");

    const accept = await t.api.post(
      "/organization/accept-invitation",
      { invitationId },
      { cookie: holder.cookie },
    );
    expect(accept.status).toBe(403);
    expect(((await accept.json()) as { code?: string }).code).toBe(UPSTREAM_CODE);
    expect(await memberRole(t, orgId, holder.userId)).toBeNull();

    const reject = await t.api.post(
      "/organization/reject-invitation",
      { invitationId },
      { cookie: holder.cookie },
    );
    expect(reject.status).toBe(403);
    expect(((await reject.json()) as { code?: string }).code).toBe(UPSTREAM_CODE);
    const pending = await t.client.execute({
      sql: `SELECT status FROM invitation WHERE id = ?`,
      args: [invitationId],
    });
    expect(pending.rows[0]!.status).toBe("pending");
  });

  it("organization.requireEmailVerificationOnInvitation:false is the documented opt-out (upstream behaviour restored)", async () => {
    const t = await makeAuth({ organization: { requireEmailVerificationOnInvitation: false } });
    const owner = await signUpOwner(t, "owner@acme.test");
    const { orgId } = await createOrg(t, owner.cookie, "acme");
    const invitationId = await invite(t, owner.cookie, orgId, "ceo@acme.test");
    const holder = await signUpOwner(t, "ceo@acme.test");

    const accept = await t.api.post(
      "/organization/accept-invitation",
      { invitationId },
      { cookie: holder.cookie },
    );
    expect(accept.status).toBe(200);
    expect(await memberRole(t, orgId, holder.userId)).toBe("admin");
  });

  describe("with a domain-bound SSO user", () => {
    let issuer: OidcIssuer;
    beforeAll(async () => {
      issuer = await startOidcIssuer();
    });
    afterAll(async () => {
      await issuer.close();
    });

    it("the IdP-vouched (emailVerified) user claims the invited role; nothing else changes for them", async () => {
      const t = await makeAuth({ trustedOrigins: [issuer.issuerUrl] });
      const owner = await signUpOwner(t, "owner@acme.test");
      const { orgId } = await createOrg(t, owner.cookie, "acme");
      await registerOidcProvider(t, owner.cookie, orgId, issuer, "acme-oidc", "acme.test");
      const invitationId = await invite(t, owner.cookie, orgId, "ceo@acme.test");

      issuer.setUser({ sub: "ceo-real", email: "ceo@acme.test" });
      const cookie = sessionCookieOf(await driveSsoSignIn(t, issuer, "acme-oidc"));
      const session = await sessionOf(t, cookie);
      expect(session.user.emailVerified).toBe(true);
      // Upstream skips the provider-bound auto-join while an invitation is
      // pending, so the role comes from the invitation, not `defaultRole`.
      expect(await memberRole(t, orgId, session.user.id)).toBeNull();

      const accept = await t.api.post(
        "/organization/accept-invitation",
        { invitationId },
        { cookie },
      );
      expect(accept.status).toBe(200);
      expect(await memberRole(t, orgId, session.user.id)).toBe("admin");
    });
  });
});

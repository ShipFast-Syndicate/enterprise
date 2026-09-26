// `getEffectivePolicy` (`src/server/policy/store.ts`) and
// `resolvePolicyOrgsForUser` (`src/server/policy/enforcement.ts`) — the
// union-of-orgs resolution that replaces "pick one org or give up" (F-03).
// These are the primitives; the sign-in hooks that consume them are
// exercised in `policy.test.ts` and the security suite.
import { describe, expect, it } from "vitest";
import type { GenericEndpointContext } from "better-auth";
import { ALLOWED_METHOD_VALUES, getEffectivePolicy } from "../../src/server/policy/store";
import { resolvePolicyOrgsForUser } from "../../src/server/policy/enforcement";
import { makeAuth, signUpOwner, createOrg, type TestAuth } from "../helpers/auth";
import { enrollTotp, insertMemberRow, setPolicy } from "../security/helpers";

async function ctxOf(t: TestAuth): Promise<GenericEndpointContext> {
  return { context: await t.auth.$context } as unknown as GenericEndpointContext;
}

async function insertVerifiedProvider(
  t: TestAuth,
  orgId: string,
  domain: string,
  providerId: string,
) {
  await t.client.execute({
    sql: `INSERT INTO "ssoProvider" (id, issuer, domain, domainVerified, organizationId, providerId, userId) VALUES (?, ?, ?, 1, ?, ?, ?)`,
    args: [`ssop_${providerId}`, "https://idp.test", domain, orgId, providerId, "creator"],
  });
  await t.client.execute({
    sql: `INSERT INTO verification (id, identifier, value, expiresAt, createdAt, updatedAt) VALUES (?, ?, ?, ?, ?, ?)`,
    args: [
      `verif_${providerId}`,
      `ab-sso-test-ok:${providerId}`,
      new Date().toISOString(),
      Date.now() + 1000 * 60 * 60 * 24,
      Date.now(),
      Date.now(),
    ],
  });
}

async function ok(res: Response) {
  if (!res.ok) throw new Error(`${res.status} ${await res.text()}`);
}

describe("getEffectivePolicy", () => {
  it("no orgs -> the permissive default (free agents unchanged)", async () => {
    const t = await makeAuth();
    const eff = await getEffectivePolicy(await ctxOf(t), [], "user_x");

    expect(eff).toEqual({
      orgIds: [],
      ssoEnforced: false,
      allowedMethods: [...ALLOWED_METHOD_VALUES],
      sessionMaxAgeS: null,
      require2fa: false,
      restricted: false,
      breakGlass: false,
      sources: {
        ssoEnforcedBy: [],
        allowedMethodsBy: [],
        sessionMaxAgeBy: null,
        require2faBy: [],
        breakGlassIn: [],
      },
    });
  });

  it("orgs without a policy row contribute the defaults (not restricted)", async () => {
    const t = await makeAuth();
    const eff = await getEffectivePolicy(await ctxOf(t), ["org_a", "org_b", "org_a"], "user_x");

    expect(eff.orgIds).toEqual(["org_a", "org_b"]);
    expect(eff.restricted).toBe(false);
    expect(eff.allowedMethods).toEqual([...ALLOWED_METHOD_VALUES]);
  });

  it("narrowing is judged against the full vocabulary: a no-row org allows declared methods, a built-ins-only row excludes them", async () => {
    const opts = { policy: { signInMethods: { "/sign-in/email-otp": "email_otp" } } };
    const t = await makeAuth(opts as never);
    const { cookie, userId } = await signUpOwner(t, "owner@acme.test");
    const { orgId: rowOrg } = await createOrg(t, cookie, "acme-row");
    await ok(
      await setPolicy(t, cookie, { orgId: rowOrg, allowedMethods: [...ALLOWED_METHOD_VALUES] }),
    );

    const noRow = await getEffectivePolicy(await ctxOf(t), ["org_no_row"], userId, opts);
    expect(noRow.restricted).toBe(false);
    expect(noRow.sources.allowedMethodsBy).toEqual([]);
    expect(noRow.allowedMethods).toEqual([...ALLOWED_METHOD_VALUES, "email_otp"]);
    // No contributing org at all: the permissive default is the whole vocabulary too.
    expect((await getEffectivePolicy(await ctxOf(t), [], userId, opts)).allowedMethods).toEqual([
      ...ALLOWED_METHOD_VALUES,
      "email_otp",
    ]);

    const withRow = await getEffectivePolicy(await ctxOf(t), ["org_no_row", rowOrg], userId, opts);
    expect(withRow.restricted).toBe(true);
    expect(withRow.sources.allowedMethodsBy).toEqual([rowOrg]);
    expect(withRow.allowedMethods).toEqual([...ALLOWED_METHOD_VALUES]);

    // Without the product's declaration the same row is the full vocabulary: not narrowed.
    const builtInsOnly = await getEffectivePolicy(await ctxOf(t), [rowOrg], userId);
    expect(builtInsOnly.restricted).toBe(false);
    expect(builtInsOnly.sources.allowedMethodsBy).toEqual([]);
  });

  it("allowedMethods is the intersection across orgs; the narrowing orgs are named in sources", async () => {
    const t = await makeAuth();
    const { cookie, userId } = await signUpOwner(t, "owner@acme.test");
    const { orgId: orgA } = await createOrg(t, cookie, "acme-a");
    const { orgId: orgB } = await createOrg(t, cookie, "acme-b");
    const { orgId: orgC } = await createOrg(t, cookie, "acme-c");
    await ok(
      await setPolicy(t, cookie, { orgId: orgA, allowedMethods: ["sso", "password", "passkey"] }),
    );
    await ok(
      await setPolicy(t, cookie, {
        orgId: orgB,
        allowedMethods: ["password", "passkey", "google"],
      }),
    );

    const eff = await getEffectivePolicy(await ctxOf(t), [orgA, orgB, orgC], "someone-else");

    expect(eff.allowedMethods).toEqual(["password", "passkey"]);
    expect(eff.restricted).toBe(true);
    expect(eff.sources.allowedMethodsBy).toEqual([orgA, orgB]);
    expect(eff.breakGlass).toBe(false);
    // The owner is nobody's break-glass user here, so the answer is the same for them.
    expect(
      (await getEffectivePolicy(await ctxOf(t), [orgA, orgB, orgC], userId)).allowedMethods,
    ).toEqual(["password", "passkey"]);
  });

  it("an empty intersection is reported as such (the two orgs' configuration, not a fallback to permissive)", async () => {
    const t = await makeAuth();
    const { cookie } = await signUpOwner(t, "owner@acme.test");
    const { orgId: orgA } = await createOrg(t, cookie, "acme-a");
    const { orgId: orgB } = await createOrg(t, cookie, "acme-b");
    await ok(await setPolicy(t, cookie, { orgId: orgA, allowedMethods: ["sso"] }));
    await ok(await setPolicy(t, cookie, { orgId: orgB, allowedMethods: ["passkey"] }));

    const eff = await getEffectivePolicy(await ctxOf(t), [orgA, orgB], "someone-else");

    expect(eff.allowedMethods).toEqual([]);
    expect(eff.restricted).toBe(true);
  });

  it("ssoEnforced ORs over the orgs where the user is not break-glass; break-glass exempts that org's SSO and allowedMethods only", async () => {
    const t = await makeAuth();
    const { cookie, userId: ownerId } = await signUpOwner(t, "owner@acme.test");
    const { orgId: orgA } = await createOrg(t, cookie, "acme-a");
    const { orgId: orgB } = await createOrg(t, cookie, "acme-b");
    await insertVerifiedProvider(t, orgA, "acme.test", "okta-a");
    await ok(
      await setPolicy(t, cookie, {
        orgId: orgA,
        ssoEnforced: true,
        breakGlassUserId: ownerId,
        allowedMethods: ["sso"],
        sessionMaxAgeS: 600,
      }),
    );
    await ok(await setPolicy(t, cookie, { orgId: orgB, allowedMethods: ["sso", "password"] }));

    const asOwner = await getEffectivePolicy(await ctxOf(t), [orgA, orgB], ownerId);
    expect(asOwner.ssoEnforced).toBe(false);
    expect(asOwner.breakGlass).toBe(true);
    expect(asOwner.sources.breakGlassIn).toEqual([orgA]);
    expect(asOwner.allowedMethods).toEqual(["sso", "password"]); // org B still binds
    expect(asOwner.sessionMaxAgeS).toBe(600); // the cap is not a sign-in gate: still applies

    const asOther = await getEffectivePolicy(await ctxOf(t), [orgA, orgB], "other-user");
    expect(asOther.ssoEnforced).toBe(true);
    expect(asOther.sources.ssoEnforcedBy).toEqual([orgA]);
    expect(asOther.allowedMethods).toEqual(["sso"]);
    expect(asOther.restricted).toBe(true);
  });

  it("sessionMaxAgeS is the minimum over all orgs and require2fa ORs over all orgs", async () => {
    const t = await makeAuth();
    const { cookie: signUpCookie } = await signUpOwner(t, "owner@acme.test");
    const { orgId: orgA } = await createOrg(t, signUpCookie, "acme-a");
    const { orgId: orgB } = await createOrg(t, signUpCookie, "acme-b");
    const { orgId: orgC } = await createOrg(t, signUpCookie, "acme-c");
    // `require2fa: true` is accepted only from an enrolled caller
    // (`REQUIRE_2FA_PRECONDITION`), so the owner enrols before writing it.
    const { cookie } = await enrollTotp(t, signUpCookie);
    await ok(await setPolicy(t, cookie, { orgId: orgA, sessionMaxAgeS: 3600 }));
    await ok(await setPolicy(t, cookie, { orgId: orgB, sessionMaxAgeS: 900, require2fa: true }));

    const eff = await getEffectivePolicy(await ctxOf(t), [orgA, orgB, orgC], "u");

    expect(eff.sessionMaxAgeS).toBe(900);
    expect(eff.sources.sessionMaxAgeBy).toBe(orgB);
    expect(eff.require2fa).toBe(true);
    expect(eff.sources.require2faBy).toEqual([orgB]);
    expect(eff.restricted).toBe(false); // neither knob narrows sign-in methods
  });
});

describe("resolvePolicyOrgsForUser", () => {
  it("returns the union of the active org, every membership and every verified-domain match, de-duplicated in that order", async () => {
    const t = await makeAuth();
    const { cookie, userId } = await signUpOwner(t, "owner@acme.test");
    const { orgId: orgA } = await createOrg(t, cookie, "acme-a");
    const { orgId: orgB } = await createOrg(t, cookie, "acme-b");
    await t.client.execute({
      sql: `INSERT INTO "ssoProvider" (id, issuer, domain, domainVerified, organizationId, providerId, userId) VALUES (?, ?, ?, 1, ?, ?, ?)`,
      args: ["ssop_c", "https://idp.test", "Acme.test, other.test", "org_c", "okta-c", "creator"],
    });
    await t.client.execute({
      sql: `INSERT INTO "ssoProvider" (id, issuer, domain, domainVerified, organizationId, providerId, userId) VALUES (?, ?, ?, 1, ?, ?, ?)`,
      args: ["ssop_a2", "https://idp.test", "acme.test", orgA, "okta-a", "creator"],
    });

    const orgIds = await resolvePolicyOrgsForUser(await ctxOf(t), {
      userId,
      email: "owner@EU.acme.test",
      activeOrganizationId: orgB,
    });

    expect(orgIds).toEqual([orgB, orgA, "org_c"]);
  });

  it("a user with no membership and no matching domain resolves to [] (no policy applies)", async () => {
    const t = await makeAuth();
    const { userId } = await signUpOwner(t, "free@nowhere.test");

    expect(
      await resolvePolicyOrgsForUser(await ctxOf(t), { userId, email: "free@nowhere.test" }),
    ).toEqual([]);
  });

  it("two memberships are both returned — never collapsed to 'ambiguous, no policy' (F-03)", async () => {
    const t = await makeAuth();
    const { userId } = await signUpOwner(t, "contractor@gmail.test");
    await insertMemberRow(t, "org_x", userId, "member");
    await t.client.execute({
      sql: `INSERT INTO member (id, organizationId, userId, role, createdAt) VALUES (?, ?, ?, ?, ?)`,
      args: [`member_${userId}_org_y`, "org_y", userId, "owner", Date.now()],
    });

    expect(
      await resolvePolicyOrgsForUser(await ctxOf(t), { userId, email: "contractor@gmail.test" }),
    ).toEqual(["org_x", "org_y"]);
  });

  it("resolves by e-mail domain alone for an unknown user (pre-auth)", async () => {
    const t = await makeAuth();
    await t.client.execute({
      sql: `INSERT INTO "ssoProvider" (id, issuer, domain, domainVerified, organizationId, providerId, userId) VALUES (?, ?, ?, 1, ?, ?, ?)`,
      args: ["ssop_a", "https://idp.test", "acme.test", "org_a", "okta", "creator"],
    });

    expect(
      await resolvePolicyOrgsForUser(await ctxOf(t), { userId: null, email: "ghost@acme.test" }),
    ).toEqual(["org_a"]);
  });
});

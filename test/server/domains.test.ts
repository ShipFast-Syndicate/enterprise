// `src/server/policy/domains.ts` — the one provider-domain matcher every
// enterprise read path shares (F-04: upstream `@better-auth/sso` matches a
// provider's comma-separated, any-case `domain` list exact-or-subdomain,
// while the enterprise resolver did an exact `findOne({domain})`).
import { describe, expect, it } from "vitest";
import type { GenericEndpointContext } from "better-auth";
import {
  domainMatches,
  emailDomain,
  findOrgsByEmailDomain,
  listVerifiedProviders,
  normalizeProviderDomains,
} from "../../src/server/policy/domains";
import { makeAuth, type TestAuth } from "../helpers/auth";

async function ctxOf(t: TestAuth): Promise<GenericEndpointContext> {
  return { context: await t.auth.$context } as unknown as GenericEndpointContext;
}

async function insertProvider(
  t: TestAuth,
  input: { providerId: string; domain: string; orgId: string | null; verified?: boolean },
) {
  await t.client.execute({
    sql: `INSERT INTO "ssoProvider" (id, issuer, domain, domainVerified, organizationId, providerId, userId) VALUES (?, ?, ?, ?, ?, ?, ?)`,
    args: [
      `ssop_${input.providerId}`,
      "https://idp.test",
      input.domain,
      input.verified === false ? 0 : 1,
      input.orgId,
      input.providerId,
      "test-provider-creator",
    ],
  });
}

describe("normalizeProviderDomains", () => {
  it("splits a comma list, trims, lower-cases, drops a trailing dot and de-duplicates", () => {
    expect(normalizeProviderDomains("Acme.test, acme-two.test ,ACME.TEST.")).toEqual([
      "acme.test",
      "acme-two.test",
    ]);
  });

  it("tolerates surrounding whitespace and empty entries", () => {
    expect(normalizeProviderDomains("  acme.test , , ")).toEqual(["acme.test"]);
  });

  it("returns null for an empty or non-string value", () => {
    expect(normalizeProviderDomains("")).toBeNull();
    expect(normalizeProviderDomains(" , ")).toBeNull();
    expect(normalizeProviderDomains(null)).toBeNull();
    expect(normalizeProviderDomains(undefined)).toBeNull();
  });

  it("returns null — the whole list matches nothing — when any entry is not a plain hostname", () => {
    expect(normalizeProviderDomains("acme.test, http://x")).toBeNull();
    expect(normalizeProviderDomains("acme.test/path")).toBeNull();
    expect(normalizeProviderDomains("acme test")).toBeNull();
    expect(normalizeProviderDomains("user@acme.test")).toBeNull();
    expect(normalizeProviderDomains("a_b.test")).toBeNull();
    expect(normalizeProviderDomains("-acme.test")).toBeNull();
  });
});

describe("emailDomain", () => {
  it("returns the lower-cased domain part", () => {
    expect(emailDomain("Alice@Acme.TEST")).toBe("acme.test");
    expect(emailDomain("  alice@acme.test  ")).toBe("acme.test");
  });

  it("returns null when there is not exactly one @ with a hostname after it", () => {
    expect(emailDomain("alice")).toBeNull();
    expect(emailDomain("alice@")).toBeNull();
    expect(emailDomain("@acme.test")).toBeNull();
    expect(emailDomain("a@b@acme.test")).toBeNull();
    expect(emailDomain("alice@acme.test/x")).toBeNull();
    expect(emailDomain(null)).toBeNull();
  });
});

describe("domainMatches (upstream parity table)", () => {
  it.each([
    ["acme.test", "Acme.test, acme-two.test", "acme.test"],
    ["acme-two.test", "Acme.test, acme-two.test", "acme-two.test"],
    ["eu.acme.test", "acme.test", "acme.test"],
    ["deep.eu.acme.test", "acme.test", "acme.test"],
    ["ACME.TEST", "acme.test", "acme.test"],
    ["acme.test", "acme.test.", "acme.test"],
  ])("%s matches %j via %s", (email, list, matched) => {
    expect(domainMatches(email, list)).toEqual({ matched });
  });

  it.each([
    ["evilacme.test", "acme.test"],
    ["acme.test.evil.test", "acme.test"],
    ["acme.test", "eu.acme.test"],
    ["acme.test", "acme.test, http://x"],
    ["acme.test", ""],
    ["", "acme.test"],
  ])("%s does not match %j", (email, list) => {
    expect(domainMatches(email, list)).toBeNull();
  });

  it("reports the most specific list entry when several match", () => {
    expect(domainMatches("eu.acme.test", "acme.test, eu.acme.test")).toEqual({
      matched: "eu.acme.test",
    });
  });
});

describe("listVerifiedProviders", () => {
  it("pages through every verified row (250 seeded, 100 per page) and skips unverified ones", async () => {
    const t = await makeAuth();
    for (let i = 0; i < 250; i++) {
      await insertProvider(t, {
        providerId: `p${String(i).padStart(3, "0")}`,
        domain: `org${i}.test`,
        orgId: `org_${i}`,
      });
    }
    await insertProvider(t, {
      providerId: "unverified",
      domain: "u.test",
      orgId: "org_u",
      verified: false,
    });

    const rows = await listVerifiedProviders(await ctxOf(t));

    expect(rows).toHaveLength(250);
    expect(new Set(rows.map((r) => r.providerId)).size).toBe(250);
    expect(rows.some((r) => r.providerId === "unverified")).toBe(false);
  });

  it("fails closed past `max`: throws SSO_DOMAIN_CHECK_OVERFLOW instead of truncating", async () => {
    const t = await makeAuth();
    for (let i = 0; i < 5; i++) {
      await insertProvider(t, { providerId: `p${i}`, domain: `org${i}.test`, orgId: `org_${i}` });
    }

    await expect(listVerifiedProviders(await ctxOf(t), { max: 4 })).rejects.toMatchObject({
      status: "INTERNAL_SERVER_ERROR",
      body: { code: "SSO_DOMAIN_CHECK_OVERFLOW" },
    });
    await expect(listVerifiedProviders(await ctxOf(t), { max: 5 })).resolves.toHaveLength(5);
  });
});

describe("findOrgsByEmailDomain", () => {
  it("returns every org-scoped verified provider whose list authorizes the domain, most specific first then providerId asc", async () => {
    const t = await makeAuth();
    await insertProvider(t, { providerId: "zeta", domain: "acme.test", orgId: "org_a" });
    await insertProvider(t, {
      providerId: "alpha",
      domain: "Acme.test, other.test",
      orgId: "org_b",
    });
    await insertProvider(t, { providerId: "sub", domain: "eu.acme.test", orgId: "org_c" });
    await insertProvider(t, { providerId: "personal", domain: "acme.test", orgId: null });
    await insertProvider(t, {
      providerId: "unverified",
      domain: "acme.test",
      orgId: "org_d",
      verified: false,
    });
    await insertProvider(t, { providerId: "elsewhere", domain: "evilacme.test", orgId: "org_e" });

    const matches = await findOrgsByEmailDomain(await ctxOf(t), "Someone@EU.acme.test");

    expect(matches).toEqual([
      { orgId: "org_c", providerId: "sub", matchedDomain: "eu.acme.test" },
      { orgId: "org_b", providerId: "alpha", matchedDomain: "acme.test" },
      { orgId: "org_a", providerId: "zeta", matchedDomain: "acme.test" },
    ]);
  });

  it("returns [] for an address without a usable domain", async () => {
    const t = await makeAuth();
    await insertProvider(t, { providerId: "okta", domain: "acme.test", orgId: "org_a" });
    expect(await findOrgsByEmailDomain(await ctxOf(t), "nobody")).toEqual([]);
  });
});

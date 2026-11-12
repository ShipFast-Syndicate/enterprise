// `composeSsoResolvers` (`src/server/sso-resolve.ts`) — the single enforcement
// point of the 1.3 SSO options — against a fake transaction database. Every
// branch, the order of the checks, and the rule that a refusal both marks the
// audit stash (`notePolicyRefusal`) and rejects: it never lets an OIDC sign-in
// continue when `existingUsersOnly` is on (SAML is delegated to the base
// resolver, and user creation is blocked by the create hook backstop).
import { beforeEach, describe, expect, it, vi } from "vitest";
import { notePolicyRefusal } from "../../src/server/audit/refusal";
import { composeSsoResolvers } from "../../src/server/sso-resolve";
import type { EnterpriseOptions } from "../../src/server/types";

vi.mock("../../src/server/audit/refusal", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../src/server/audit/refusal")>();
  return { ...actual, notePolicyRefusal: vi.fn(actual.notePolicyRefusal) };
});

type Row = Record<string, unknown>;
type Where = { field: string; value: unknown; operator?: string };

/** The slice of better-auth's transaction adapter the resolver reads, over plain arrays. */
function fakeDatabase(tables: Record<string, Row[]>) {
  const matches = (row: Row, where: Where[] = []) =>
    where.every((w) => (w.operator === "ne" ? row[w.field] !== w.value : row[w.field] === w.value));
  const findOne = vi.fn(async ({ model, where }: { model: string; where?: Where[] }) => {
    return (tables[model] ?? []).find((row) => matches(row, where)) ?? null;
  });
  const findMany = vi.fn(async ({ model, where }: { model: string; where?: Where[] }) => {
    return (tables[model] ?? []).filter((row) => matches(row, where));
  });
  return { findOne, findMany };
}

const SECRETS = {
  product: "test",
  secretsKey: "s".repeat(32),
  scimCredentialHashSecret: "catalog-test-key-".repeat(3),
  resolveEntitlements: async () => new Set<never>(),
};

function options(sso: EnterpriseOptions["sso"]): EnterpriseOptions {
  return { ...SECRETS, sso };
}

const PROVIDER_ROW = {
  id: "rec-1",
  providerId: "acme-oidc",
  organizationId: "org-1",
  domain: "acme.test",
  domainVerified: true,
  issuer: "https://idp.test",
  oidcConfig: JSON.stringify({ pkce: true }),
};

function baseTables(overrides: Partial<Record<string, Row[]>> = {}): Record<string, Row[]> {
  return {
    ssoProvider: [PROVIDER_ROW],
    user: [{ id: "u1", email: "jane@acme.test", banned: false }],
    member: [{ organizationId: "org-1", userId: "u1" }],
    account: [],
    ...(overrides as Record<string, Row[]>),
  };
}

function oidcInput(
  overrides: {
    claims?: Row;
    providerUser?: Row;
    accountId?: string;
    providerId?: string;
    source?: { type: "persisted"; recordId: string } | { type: "configured" };
  } = {},
) {
  return {
    protocol: "oidc" as const,
    providerId: overrides.providerId ?? "acme-oidc",
    accountKey: { issuer: "https://idp.test", accountId: overrides.accountId ?? "sub-1" },
    providerUser: {
      email: "jane@acme.test",
      emailVerified: false,
      name: "Jane",
      ...overrides.providerUser,
    },
    providerClaims: {} as Row,
    verifiedIdTokenClaims: {
      sub: overrides.accountId ?? "sub-1",
      email: "jane@acme.test",
      email_verified: true,
      hd: "acme.test",
      ...overrides.claims,
    } as Row,
    providerReference: {
      providerId: overrides.providerId ?? "acme-oidc",
      source: overrides.source ?? { type: "persisted" as const, recordId: "rec-1" },
      authenticationConfigurationFingerprint: "fingerprint",
    },
  };
}

function samlInput() {
  return {
    protocol: "saml" as const,
    providerId: "acme-saml",
    accountKey: { issuer: "https://idp.test/saml", accountId: "name-id-1" },
    providerUser: { email: "jane@acme.test", emailVerified: false, name: "Jane" },
    providerAttributes: { email: "jane@acme.test" },
    providerReference: {
      providerId: "acme-saml",
      source: { type: "persisted" as const, recordId: "rec-1" },
      authenticationConfigurationFingerprint: "fingerprint",
    },
  };
}

type Resolver = ReturnType<typeof composeSsoResolvers>;
type Input = Parameters<Resolver>[0];

function setup(
  sso: EnterpriseOptions["sso"],
  tables: Record<string, Row[]> = baseTables(),
  base: Resolver = async () => ({ action: "continue" }),
) {
  const database = fakeDatabase(tables);
  const baseResolver = vi.fn(base);
  const resolve = composeSsoResolvers(options(sso), baseResolver);
  const run = (input: Input) => resolve(input, { database: database as never });
  return { database, baseResolver, run };
}

const STRICT = { existingUsersOnly: true } as const;

beforeEach(() => {
  vi.mocked(notePolicyRefusal).mockClear();
});

type Decision = { action: string; code?: string };

async function expectRefusal(result: Decision | Promise<Decision>, code: string): Promise<void> {
  expect(await result).toEqual({ action: "reject", code });
  expect(notePolicyRefusal).toHaveBeenCalledWith(code);
}

describe("composeSsoResolvers — identity", () => {
  it("returns the base resolver itself when no resolver-affecting option is on", () => {
    const base: Resolver = async () => ({ action: "continue" });
    for (const sso of [
      undefined,
      {},
      { existingUsersOnly: false },
      { oidcClaims: {} },
      {
        oidcClaims: { requireEmailVerified: false, requireHostedDomain: false, requirePkce: false },
      },
      { organizationProvisioning: "off" as const },
      { domainVerificationMode: "operator" as const },
    ]) {
      expect(composeSsoResolvers(options(sso), base)).toBe(base);
    }
  });

  it("returns a different function for each resolver-affecting option", () => {
    const base: Resolver = async () => ({ action: "continue" });
    for (const sso of [
      { existingUsersOnly: true },
      { oidcClaims: { requireEmailVerified: true } },
      { oidcClaims: { requireHostedDomain: true } },
      { oidcClaims: { requireHostedDomain: ["acme.test"] } },
      { oidcClaims: { requirePkce: true } },
    ]) {
      expect(composeSsoResolvers(options(sso), base)).not.toBe(base);
    }
  });
});

describe("composeSsoResolvers — protocol", () => {
  it("SAML with oidcClaims set is refused SSO_POLICY_UNSUPPORTED_PROTOCOL (the claims cannot be checked)", async () => {
    const { run, baseResolver } = setup({ oidcClaims: { requireEmailVerified: true } });
    await expectRefusal(run(samlInput()), "SSO_POLICY_UNSUPPORTED_PROTOCOL");
    expect(baseResolver).not.toHaveBeenCalled();
  });

  it("SAML with only existingUsersOnly delegates to the base resolver unchanged", async () => {
    const { run, baseResolver, database } = setup(STRICT, baseTables(), async () => ({
      action: "link",
      userId: "scim-user",
      profile: "preserve",
    }));
    expect(await run(samlInput())).toEqual({
      action: "link",
      userId: "scim-user",
      profile: "preserve",
    });
    expect(baseResolver).toHaveBeenCalledTimes(1);
    expect(database.findOne).not.toHaveBeenCalled();
    expect(notePolicyRefusal).not.toHaveBeenCalled();
  });

  it("SAML: a base reject is returned as is", async () => {
    const { run } = setup(STRICT, baseTables(), async () => ({
      action: "reject",
      code: "SCIM_PROVISIONING_REQUIRED",
    }));
    expect(await run(samlInput())).toEqual({
      action: "reject",
      code: "SCIM_PROVISIONING_REQUIRED",
    });
  });
});

describe("composeSsoResolvers — provider", () => {
  it("a provider that is not persisted (source.type is an object field, not a string) is refused SSO_PROVIDER_UNRESOLVED", async () => {
    const { run, baseResolver } = setup(STRICT);
    await expectRefusal(
      run(oidcInput({ source: { type: "configured" } })),
      "SSO_PROVIDER_UNRESOLVED",
    );
    expect(baseResolver).not.toHaveBeenCalled();
  });

  it("strict mode applies to a non-persisted provider under oidcClaims alone, too", async () => {
    const { run } = setup({ oidcClaims: { requirePkce: true } });
    await expectRefusal(
      run(oidcInput({ source: { type: "configured" } })),
      "SSO_PROVIDER_UNRESOLVED",
    );
  });

  it("a persisted reference with no matching row (or another providerId) is refused SSO_PROVIDER_UNRESOLVED", async () => {
    await expectRefusal(
      setup(STRICT, baseTables({ ssoProvider: [] })).run(oidcInput()),
      "SSO_PROVIDER_UNRESOLVED",
    );
    await expectRefusal(
      setup(STRICT, baseTables({ ssoProvider: [{ ...PROVIDER_ROW, providerId: "other" }] })).run(
        oidcInput(),
      ),
      "SSO_PROVIDER_UNRESOLVED",
    );
  });
});

describe("composeSsoResolvers — verified ID-token claims", () => {
  it("email must be present, a string and equal (case-insensitively) to the profile e-mail", async () => {
    const { run } = setup(STRICT);
    for (const claims of [{ email: undefined }, { email: 42 }, { email: "mallory@acme.test" }]) {
      await expectRefusal(run(oidcInput({ claims })), "SSO_EMAIL_CLAIM_MISMATCH");
    }
    await expectRefusal(
      run(oidcInput({ providerUser: { email: "other@acme.test" } })),
      "SSO_EMAIL_CLAIM_MISMATCH",
    );
    expect(await run(oidcInput({ claims: { email: "JANE@ACME.TEST" } }))).toEqual({
      action: "link",
      userId: "u1",
      profile: "preserve",
    });
  });

  it("an absent or non-object verifiedIdTokenClaims is refused SSO_EMAIL_CLAIM_MISMATCH, not thrown (an older upstream without the field)", async () => {
    for (const sso of [STRICT, { oidcClaims: { requireEmailVerified: true } }]) {
      const { run, baseResolver } = setup(sso);
      for (const verifiedIdTokenClaims of [undefined, null, "claims", 42, ["jane@acme.test"]]) {
        const input = { ...oidcInput(), verifiedIdTokenClaims } as unknown as Input;
        await expectRefusal(run(input), "SSO_EMAIL_CLAIM_MISMATCH");
      }
      expect(baseResolver).not.toHaveBeenCalled();
    }
  });

  it("the e-mail claim name follows the provider's stored mapping.email, like upstream's own reader", async () => {
    const tables = baseTables({
      ssoProvider: [
        {
          ...PROVIDER_ROW,
          oidcConfig: JSON.stringify({ pkce: true, mapping: { email: "mail" } }),
        },
      ],
    });
    const { run } = setup(STRICT, tables);
    expect(
      await run(oidcInput({ claims: { email: "ignored@elsewhere.test", mail: "jane@acme.test" } })),
    ).toEqual({ action: "link", userId: "u1", profile: "preserve" });
    await expectRefusal(
      run(oidcInput({ claims: { email: "jane@acme.test", mail: "mallory@acme.test" } })),
      "SSO_EMAIL_CLAIM_MISMATCH",
    );
  });

  it("email_verified must be boolean true under requireEmailVerified and under existingUsersOnly: false, absent and the string 'true' are refused", async () => {
    for (const sso of [{ oidcClaims: { requireEmailVerified: true } }, STRICT]) {
      const { run } = setup(sso);
      for (const email_verified of [false, undefined, "true", "false", 1, null]) {
        await expectRefusal(
          run(oidcInput({ claims: { email_verified } })),
          "SSO_EMAIL_NOT_VERIFIED",
        );
      }
    }
  });

  it("email_verified is not required by the other options alone", async () => {
    const { run } = setup({ oidcClaims: { requirePkce: true } });
    expect(await run(oidcInput({ claims: { email_verified: false } }))).toEqual({
      action: "continue",
    });
  });

  it("requireHostedDomain:true — hd must be a string equal to one of the provider's domains (comma list, trimmed, lower-cased)", async () => {
    const tables = baseTables({
      ssoProvider: [{ ...PROVIDER_ROW, domain: "Acme.test, acme-two.test" }],
      user: [
        { id: "u1", email: "jane@acme.test", banned: false },
        { id: "u2", email: "joe@acme-two.test", banned: false },
      ],
      member: [
        { organizationId: "org-1", userId: "u1" },
        { organizationId: "org-1", userId: "u2" },
      ],
    });
    const { run } = setup({ ...STRICT, oidcClaims: { requireHostedDomain: true } }, tables);
    expect(await run(oidcInput({ claims: { hd: "ACME.test" } }))).toMatchObject({
      action: "link",
    });
    expect(
      await run(
        oidcInput({
          claims: { hd: "acme-two.test", email: "joe@acme-two.test" },
          providerUser: { email: "joe@acme-two.test" },
        }),
      ),
    ).toMatchObject({ action: "link", userId: "u2" });
    for (const hd of [
      undefined,
      "",
      42,
      ["acme.test"],
      "eu.acme.test",
      "evilacme.test",
      "acme.test.evil.test",
    ]) {
      await expectRefusal(run(oidcInput({ claims: { hd } })), "SSO_HOSTED_DOMAIN_MISMATCH");
    }
  });

  it("requireHostedDomain — the e-mail's domain must equal hd, with no subdomain matching", async () => {
    const { run } = setup({ oidcClaims: { requireHostedDomain: true } });
    await expectRefusal(
      run(
        oidcInput({
          claims: { email: "jane@eu.acme.test" },
          providerUser: { email: "jane@eu.acme.test" },
        }),
      ),
      "SSO_HOSTED_DOMAIN_MISMATCH",
    );
    await expectRefusal(
      run(
        oidcInput({
          claims: { email: "jane@other.test" },
          providerUser: { email: "jane@other.test" },
        }),
      ),
      "SSO_HOSTED_DOMAIN_MISMATCH",
    );
  });

  it("requireHostedDomain as an array is an explicit allow-list, independent of the provider's domain", async () => {
    const { run } = setup({ oidcClaims: { requireHostedDomain: ["corp.test"] } });
    const corp = {
      claims: { hd: "corp.test", email: "jane@corp.test" },
      providerUser: { email: "jane@corp.test" },
    };
    expect(await run(oidcInput(corp))).toEqual({ action: "continue" });
    await expectRefusal(
      run(oidcInput({ claims: { hd: "acme.test" } })),
      "SSO_HOSTED_DOMAIN_MISMATCH",
    );
  });

  it("hd comes from the verified ID token only, never from the profile or the userinfo claims", async () => {
    const { run } = setup({ oidcClaims: { requireHostedDomain: true } });
    const input = oidcInput({ claims: { hd: undefined } });
    input.providerClaims = { hd: "acme.test" };
    (input.providerUser as Row).hd = "acme.test";
    await expectRefusal(run(input), "SSO_HOSTED_DOMAIN_MISMATCH");
  });

  it("requirePkce refuses a stored provider whose pkce is false or absent (upstream sends no verifier then) or whose config cannot be read", async () => {
    for (const oidcConfig of [
      JSON.stringify({ pkce: false }),
      JSON.stringify({}),
      "not json",
      null,
    ]) {
      const { run } = setup(
        { oidcClaims: { requirePkce: true } },
        baseTables({ ssoProvider: [{ ...PROVIDER_ROW, oidcConfig }] }),
      );
      await expectRefusal(run(oidcInput()), "SSO_PKCE_REQUIRED");
    }
    const ok = setup({ oidcClaims: { requirePkce: true } });
    expect(await ok.run(oidcInput())).toEqual({ action: "continue" });
    const decoded = setup(
      { oidcClaims: { requirePkce: true } },
      baseTables({ ssoProvider: [{ ...PROVIDER_ROW, oidcConfig: { pkce: true } }] }),
    );
    expect(await decoded.run(oidcInput())).toEqual({ action: "continue" });
  });

  it("checks run in the documented order: e-mail claim, verified, hd, pkce", async () => {
    const tables = baseTables({
      ssoProvider: [{ ...PROVIDER_ROW, oidcConfig: JSON.stringify({ pkce: false }) }],
    });
    const { run } = setup(
      { ...STRICT, oidcClaims: { requireHostedDomain: true, requirePkce: true } },
      tables,
    );
    const claims = { email: "x@acme.test", email_verified: false, hd: "nope.test" };
    await expectRefusal(run(oidcInput({ claims })), "SSO_EMAIL_CLAIM_MISMATCH");
    await expectRefusal(
      run(oidcInput({ claims: { email_verified: false, hd: "nope.test" } })),
      "SSO_EMAIL_NOT_VERIFIED",
    );
    await expectRefusal(
      run(oidcInput({ claims: { hd: "nope.test" } })),
      "SSO_HOSTED_DOMAIN_MISMATCH",
    );
    await expectRefusal(run(oidcInput()), "SSO_PKCE_REQUIRED");
  });
});

describe("composeSsoResolvers — provider trust (existingUsersOnly)", () => {
  it("an unverified provider domain, or one that does not authorize the e-mail's domain, is SSO_DOMAIN_NOT_ALLOWED", async () => {
    await expectRefusal(
      setup(STRICT, baseTables({ ssoProvider: [{ ...PROVIDER_ROW, domainVerified: false }] })).run(
        oidcInput(),
      ),
      "SSO_DOMAIN_NOT_ALLOWED",
    );
    await expectRefusal(
      setup(STRICT, baseTables({ ssoProvider: [{ ...PROVIDER_ROW, domain: "other.test" }] })).run(
        oidcInput(),
      ),
      "SSO_DOMAIN_NOT_ALLOWED",
    );
  });

  it("is checked before the user is looked up", async () => {
    const { run, database } = setup(
      STRICT,
      baseTables({ ssoProvider: [{ ...PROVIDER_ROW, domainVerified: false }], user: [] }),
    );
    await expectRefusal(run(oidcInput()), "SSO_DOMAIN_NOT_ALLOWED");
    expect(database.findOne.mock.calls.some(([q]) => q.model === "user")).toBe(false);
  });

  it("oidcClaims without existingUsersOnly does not add the provider-trust check", async () => {
    const { run } = setup(
      { oidcClaims: { requireEmailVerified: true } },
      baseTables({ ssoProvider: [{ ...PROVIDER_ROW, domainVerified: false }] }),
    );
    expect(await run(oidcInput())).toEqual({ action: "continue" });
  });
});

describe("composeSsoResolvers — SCIM", () => {
  it("a base reject is returned as is, and no user lookup happens", async () => {
    const { run, database } = setup(STRICT, baseTables(), async () => ({
      action: "reject",
      code: "SCIM_USER_NOT_ACTIVE",
    }));
    expect(await run(oidcInput())).toEqual({ action: "reject", code: "SCIM_USER_NOT_ACTIVE" });
    expect(database.findOne.mock.calls.some(([q]) => q.model === "user")).toBe(false);
  });

  it("a base link keeps its user, and the ban, membership and conflict checks still run on it", async () => {
    const link = async () => ({
      action: "link" as const,
      userId: "u2",
      profile: "preserve" as const,
    });
    const tables = (over: Partial<Record<string, Row[]>> = {}) =>
      baseTables({
        user: [
          { id: "u1", email: "jane@acme.test", banned: false },
          { id: "u2", email: "scim@acme.test", banned: false },
        ],
        member: [
          { organizationId: "org-1", userId: "u1" },
          { organizationId: "org-1", userId: "u2" },
        ],
        ...over,
      });

    expect(await setup(STRICT, tables(), link).run(oidcInput())).toEqual({
      action: "link",
      userId: "u2",
      profile: "preserve",
    });
    await expectRefusal(
      setup(
        STRICT,
        tables({
          user: [
            { id: "u1", email: "jane@acme.test", banned: false },
            { id: "u2", email: "scim@acme.test", banned: true, banExpires: null },
          ],
        }),
        link,
      ).run(oidcInput()),
      "SSO_USER_BANNED",
    );
    await expectRefusal(
      setup(STRICT, tables({ member: [{ organizationId: "org-1", userId: "u1" }] }), link).run(
        oidcInput(),
      ),
      "SSO_NOT_MEMBER",
    );
    await expectRefusal(
      setup(
        STRICT,
        tables({ account: [{ providerId: "acme-oidc", accountId: "sub-1", userId: "u1" }] }),
        link,
      ).run(oidcInput()),
      "SSO_ACCOUNT_CONFLICT",
    );
  });

  it("a base link to a user that does not exist is SSO_USER_NOT_PROVISIONED", async () => {
    await expectRefusal(
      setup(STRICT, baseTables(), async () => ({
        action: "link",
        userId: "ghost",
        profile: "preserve",
      })).run(oidcInput()),
      "SSO_USER_NOT_PROVISIONED",
    );
  });

  it("without existingUsersOnly a base link is returned as is, unchecked", async () => {
    const link = { action: "link" as const, userId: "u2", profile: "update" as const };
    const { run, database } = setup(
      { oidcClaims: { requireEmailVerified: true } },
      baseTables(),
      async () => link,
    );
    expect(await run(oidcInput())).toBe(link);
    expect(database.findOne.mock.calls.some(([q]) => q.model === "user")).toBe(false);
  });
});

describe("composeSsoResolvers — linking an existing user", () => {
  it("links the pre-existing user found by the ID-token e-mail, preserving the profile", async () => {
    const { run } = setup(STRICT);
    expect(await run(oidcInput())).toEqual({ action: "link", userId: "u1", profile: "preserve" });
    expect(notePolicyRefusal).not.toHaveBeenCalled();
  });

  it("a repeat login with the same subject returns the same decision", async () => {
    const tables = baseTables({
      account: [{ providerId: "acme-oidc", accountId: "sub-1", userId: "u1" }],
    });
    const { run } = setup(STRICT, tables);
    expect(await run(oidcInput())).toEqual({ action: "link", userId: "u1", profile: "preserve" });
    expect(await run(oidcInput())).toEqual({ action: "link", userId: "u1", profile: "preserve" });
  });

  it("looks the user up by the lower-cased e-mail", async () => {
    const { run, database } = setup(STRICT);
    await run(
      oidcInput({ claims: { email: "Jane@Acme.Test" }, providerUser: { email: "jane@acme.test" } }),
    );
    const userQuery = database.findOne.mock.calls.find(([q]) => q.model === "user")![0];
    expect(userQuery.where).toEqual([{ field: "email", value: "jane@acme.test" }]);
  });

  it("no local user is SSO_USER_NOT_PROVISIONED, never a continue", async () => {
    await expectRefusal(
      setup(STRICT, baseTables({ user: [], member: [] })).run(oidcInput()),
      "SSO_USER_NOT_PROVISIONED",
    );
  });

  it("a banned user is refused; an expired ban is not; a missing column counts as not banned", async () => {
    const past = new Date(Date.now() - 60_000);
    const future = new Date(Date.now() + 60_000);
    const withUser = (user: Row) =>
      baseTables({ user: [{ id: "u1", email: "jane@acme.test", ...user }] });
    for (const user of [
      { banned: true },
      { banned: true, banExpires: null },
      { banned: true, banExpires: future },
      { banned: true, banExpires: future.getTime() },
      { banned: true, banExpires: future.toISOString() },
      { banned: true, banExpires: "not a date" },
    ]) {
      await expectRefusal(setup(STRICT, withUser(user)).run(oidcInput()), "SSO_USER_BANNED");
    }
    for (const user of [
      { banned: true, banExpires: past },
      { banned: true, banExpires: past.getTime() },
      { banned: false, banExpires: future },
      {},
    ]) {
      expect(await setup(STRICT, withUser(user)).run(oidcInput())).toMatchObject({
        action: "link",
      });
    }
  });

  it("requireMembership (default true): the user must be a member of the provider's organization", async () => {
    const noMember = baseTables({ member: [{ organizationId: "org-2", userId: "u1" }] });
    await expectRefusal(setup(STRICT, noMember).run(oidcInput()), "SSO_NOT_MEMBER");
    await expectRefusal(
      setup({ ...STRICT, requireMembership: true }, noMember).run(oidcInput()),
      "SSO_NOT_MEMBER",
    );
    expect(
      await setup({ ...STRICT, requireMembership: false }, noMember).run(oidcInput()),
    ).toMatchObject({ action: "link", userId: "u1" });
  });

  it("a provider with no organization cannot satisfy requireMembership", async () => {
    const tables = baseTables({ ssoProvider: [{ ...PROVIDER_ROW, organizationId: null }] });
    await expectRefusal(setup(STRICT, tables).run(oidcInput()), "SSO_NOT_MEMBER");
    expect(
      await setup({ ...STRICT, requireMembership: false }, tables).run(oidcInput()),
    ).toMatchObject({ action: "link" });
  });

  it("the same subject already linked to another user is SSO_ACCOUNT_CONFLICT", async () => {
    const tables = baseTables({
      account: [{ providerId: "acme-oidc", accountId: "sub-1", userId: "u-other" }],
    });
    await expectRefusal(setup(STRICT, tables).run(oidcInput()), "SSO_ACCOUNT_CONFLICT");
  });

  it("a different subject for a user already linked through this provider is SSO_ACCOUNT_CONFLICT", async () => {
    const tables = baseTables({
      account: [{ providerId: "acme-oidc", accountId: "sub-OLD", userId: "u1" }],
    });
    await expectRefusal(setup(STRICT, tables).run(oidcInput()), "SSO_ACCOUNT_CONFLICT");
  });

  it("accounts under another provider (or a credential account) are not a conflict", async () => {
    const tables = baseTables({
      account: [
        { providerId: "credential", accountId: "u1", userId: "u1" },
        { providerId: "other-oidc", accountId: "sub-1", userId: "u-other" },
        { providerId: "other-oidc", accountId: "sub-9", userId: "u1" },
      ],
    });
    expect(await setup(STRICT, tables).run(oidcInput())).toMatchObject({
      action: "link",
      userId: "u1",
    });
  });

  it("the order after the user is found: banned, then membership, then conflict", async () => {
    const tables = baseTables({
      user: [{ id: "u1", email: "jane@acme.test", banned: true, banExpires: null }],
      member: [],
      account: [{ providerId: "acme-oidc", accountId: "sub-1", userId: "u-other" }],
    });
    await expectRefusal(setup(STRICT, tables).run(oidcInput()), "SSO_USER_BANNED");
    const notMemberToo = baseTables({
      member: [],
      account: [{ providerId: "acme-oidc", accountId: "sub-1", userId: "u-other" }],
    });
    await expectRefusal(setup(STRICT, notMemberToo).run(oidcInput()), "SSO_NOT_MEMBER");
  });

  it("a database failure propagates (upstream turns it into SSO_USER_RESOLUTION_FAILED, which fails closed)", async () => {
    const { run, database } = setup(STRICT);
    database.findOne.mockRejectedValueOnce(new Error("db down"));
    await expect(run(oidcInput())).rejects.toThrow("db down");
  });

  it("never continues under existingUsersOnly: every outcome is a link or a reject", async () => {
    const scenarios: Array<[Record<string, Row[]>, Input]> = [
      [baseTables(), oidcInput()],
      [baseTables({ user: [] }), oidcInput()],
      [baseTables({ ssoProvider: [] }), oidcInput()],
      [baseTables(), oidcInput({ claims: { email_verified: undefined } })],
      [baseTables(), oidcInput({ source: { type: "configured" } })],
      [baseTables({ member: [] }), oidcInput()],
    ];
    for (const [tables, input] of scenarios) {
      const result = await setup(STRICT, tables).run(input);
      expect(["link", "reject"]).toContain(result.action);
    }
  });
});

describe("composeSsoResolvers — oidcClaims without existingUsersOnly", () => {
  it("passes the base decision through once the claims hold, and never reads the user table", async () => {
    const base = async () => ({ action: "continue" as const });
    const { run, database, baseResolver } = setup(
      { oidcClaims: { requireEmailVerified: true } },
      baseTables(),
      base,
    );
    expect(await run(oidcInput())).toEqual({ action: "continue" });
    expect(baseResolver).toHaveBeenCalledTimes(1);
    expect(database.findOne.mock.calls.every(([q]) => q.model === "ssoProvider")).toBe(true);
  });

  it("a claims failure rejects before the base resolver runs", async () => {
    const { run, baseResolver } = setup({ oidcClaims: { requireEmailVerified: true } });
    await expectRefusal(
      run(oidcInput({ claims: { email_verified: false } })),
      "SSO_EMAIL_NOT_VERIFIED",
    );
    expect(baseResolver).not.toHaveBeenCalled();
  });
});

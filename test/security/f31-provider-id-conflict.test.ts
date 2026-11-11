// A `providerId` owned by another organization is a client error, not a 500.
//
// Upstream's `/sso/register` looks the `providerId` up and answers 422 when it
// exists; that lookup and the insert are separate statements, so two
// registrations racing for one `providerId` leave the loser to the unique
// index, whose violation reached the client as a generic 500
// (`src/server/db-errors.ts`). It now answers the same 422 body, and the
// victim provider is untouched.
import { describe, expect, it } from "vitest";
import { createOrg, makeAuth, signUpOwner } from "../helpers/auth";
import { redactDatabaseError } from "../../src/server/db-errors";

const oidcConfig = {
  clientId: "c",
  clientSecret: "s",
  skipDiscovery: true,
  authorizationEndpoint: "https://idp.example.com/authorize",
  tokenEndpoint: "https://idp.example.com/token",
  jwksEndpoint: "https://idp.example.com/jwks",
};
const CONFLICT = { message: "SSO provider with this providerId already exists" };

describe("a providerId owned by another organization", () => {
  it("is 422 on a sequential duplicate, with the victim row preserved", async () => {
    const t = await makeAuth();
    const acme = await signUpOwner(t, "owner@acme.test");
    const { orgId: acmeOrg } = await createOrg(t, acme.cookie, "acme");
    const evil = await signUpOwner(t, "owner@evil.test");
    const { orgId: evilOrg } = await createOrg(t, evil.cookie, "evil");
    const body = { providerId: "shared", issuer: "https://idp.example.com", oidcConfig };
    const first = await t.api.post(
      "/sso/register",
      { ...body, domain: "acme.test", organizationId: acmeOrg },
      { cookie: acme.cookie },
    );
    expect(first.status).toBe(200);
    for (const path of ["/sso/register", "/enterprise/sso/register"]) {
      const res = await t.api.post(
        path,
        { ...body, domain: "evil.test", organizationId: evilOrg },
        { cookie: evil.cookie },
      );
      expect(res.status, path).toBe(422);
      expect(await res.json(), path).toEqual(CONFLICT);
    }
    const rows = await t.client.execute({
      sql: `SELECT organizationId FROM "ssoProvider" WHERE providerId = ?`,
      args: ["shared"],
    });
    expect(rows.rows.map((r) => String(r.organizationId))).toEqual([acmeOrg]);
  });

  it("is 422 when the unique index, not the lookup, rejects the insert", async () => {
    const t = await makeAuth();
    const acme = await signUpOwner(t, "owner@acme.test");
    const { orgId: acmeOrg } = await createOrg(t, acme.cookie, "acme");
    const evil = await signUpOwner(t, "owner@evil.test");
    const { orgId: evilOrg } = await createOrg(t, evil.cookie, "evil");
    const register = (cookie: string, organizationId: string, domain: string) =>
      t.api.post(
        "/sso/register",
        {
          providerId: "raced",
          issuer: "https://idp.example.com",
          oidcConfig,
          domain,
          organizationId,
        },
        { cookie },
      );
    const results = await Promise.all([
      register(acme.cookie, acmeOrg, "acme.test"),
      register(evil.cookie, evilOrg, "evil.test"),
    ]);
    const statuses = results.map((r) => r.status).sort();
    expect(statuses, "one wins, the loser is a client error, never a 500").toEqual([200, 422]);
    const loser = results.find((r) => r.status === 422)!;
    expect(await loser.json()).toEqual(CONFLICT);
  });
});

describe("redactDatabaseError and a providerId conflict", () => {
  const driver = (code: string, message: string) =>
    Object.assign(new Error(`Failed query: insert into "ssoProvider" params: secret-value`), {
      query: "insert into ssoProvider",
      params: ["secret-value"],
      cause: Object.assign(new Error(message), { code }),
    });

  for (const [label, error] of [
    [
      "sqlite",
      driver("SQLITE_CONSTRAINT_UNIQUE", "UNIQUE constraint failed: ssoProvider.providerId"),
    ],
    [
      "postgres",
      driver(
        "23505",
        'duplicate key value violates unique constraint "ssoProvider_providerId_key"',
      ),
    ],
    ["mysql", driver("ER_DUP_ENTRY", "Duplicate entry 'x' for key 'providerId'")],
  ] as const) {
    it(`${label}: 422 with upstream's body and no statement`, () => {
      const out = redactDatabaseError(error, { model: "ssoProvider", method: "create" });
      expect(out).toMatchObject({ statusCode: 422, body: CONFLICT });
      expect(JSON.stringify(out)).not.toContain("secret-value");
    });
  }

  it("another model, another method, or another constraint keeps the redacted 500 path", () => {
    const unique = driver("SQLITE_CONSTRAINT_UNIQUE", "UNIQUE constraint failed: user.email");
    for (const where of [
      { model: "user", method: "create" },
      { model: "ssoProvider", method: "update" },
    ]) {
      expect(redactDatabaseError(unique, where)).toMatchObject({ name: "DatabaseQueryError" });
    }
    const notNull = driver(
      "SQLITE_CONSTRAINT_NOTNULL",
      "NOT NULL constraint failed: ssoProvider.issuer",
    );
    expect(redactDatabaseError(notNull, { model: "ssoProvider", method: "create" })).toMatchObject({
      name: "DatabaseQueryError",
    });
  });
});

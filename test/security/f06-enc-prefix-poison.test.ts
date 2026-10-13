// F-06 (security audit 3, 2026-09-25) — `enc:v1:` prefix confusion.
//
// The C-04 write path skipped encryption for any value that already carried
// the `enc:v1:` prefix ("already encrypted, pass through"). A tenant
// owner/admin could therefore `POST /sso/register` with
// `oidcConfig.clientSecret = "enc:v1:<junk>"`: the literal was committed,
// the post-write decrypt threw (500), and — because every unfiltered
// `findMany` over `ssoProvider` decrypted all rows in one `Promise.all` —
// upstream `GET /sso/providers` and the `/sign-in/sso {email}` domain
// fallback answered 500 for **every** tenant, while get/update/delete on the
// poisoned row itself also 500'd (no recovery short of raw SQL).
//
// Fix (`src/server/secrets.ts`): the write path always encrypts (a wrapper
// never infers "already sealed" from caller data), the outer adapter
// delegates to the wrapped transaction adapter instead of double-wrapping,
// and a row whose secret cannot be opened is reported through the logger and
// left sealed rather than rejecting the whole read.

import { describe, expect, it, vi } from "vitest";
import { runWithTransaction } from "@better-auth/core/context";
import { makeAuth, signUpOwner, createOrg, type TestAuth } from "../helpers/auth";

const SECRET = "real-idp-client-secret";
const POISON = "enc:v1:AAAA";

async function register(
  t: TestAuth,
  cookie: string,
  orgId: string,
  providerId: string,
  clientSecret: string,
  domain: string,
) {
  return t.api.post(
    "/sso/register",
    {
      providerId,
      issuer: "https://idp.test",
      domain,
      organizationId: orgId,
      oidcConfig: {
        clientId: "cid",
        clientSecret,
        skipDiscovery: true,
        authorizationEndpoint: "https://idp.test/authorize",
        tokenEndpoint: "https://idp.test/token",
        jwksEndpoint: "https://idp.test/jwks",
      },
    },
    { cookie },
  );
}

async function storedClientSecret(t: TestAuth, providerId: string): Promise<string> {
  const res = await t.client.execute({
    sql: `SELECT oidcConfig FROM "ssoProvider" WHERE providerId = ?`,
    args: [providerId],
  });
  return (JSON.parse(String(res.rows[0]!.oidcConfig)) as { clientSecret: string }).clientSecret;
}

async function readClientSecret(t: TestAuth, providerId: string): Promise<string> {
  const ctx = await t.auth.$context;
  const row = await ctx.adapter.findOne<{ oidcConfig: string }>({
    model: "ssoProvider",
    where: [{ field: "providerId", value: providerId }],
  });
  return (JSON.parse(row!.oidcConfig) as { clientSecret: string }).clientSecret;
}

/** Corrupts a row the way an attacker (pre-fix) or a rotated key would: undecryptable ciphertext on disk. */
async function corruptRow(t: TestAuth, providerId: string): Promise<void> {
  const res = await t.client.execute({
    sql: `SELECT oidcConfig FROM "ssoProvider" WHERE providerId = ?`,
    args: [providerId],
  });
  const config = JSON.parse(String(res.rows[0]!.oidcConfig)) as Record<string, unknown>;
  config.clientSecret = POISON;
  await t.client.execute({
    sql: `UPDATE "ssoProvider" SET oidcConfig = ? WHERE providerId = ?`,
    args: [JSON.stringify(config), providerId],
  });
}

async function twoTenants(t: TestAuth) {
  const a = await signUpOwner(t, "a@acme.test");
  const { orgId: orgA } = await createOrg(t, a.cookie, "acme");
  const b = await signUpOwner(t, "b@beta.test");
  const { orgId: orgB } = await createOrg(t, b.cookie, "beta");
  expect((await register(t, b.cookie, orgB, "beta-okta", SECRET, "beta.test")).status).toBe(200);
  return { a, orgA, b, orgB };
}

describe("F-06 — an `enc:v1:` prefix in caller data is never trusted on write", () => {
  it("register with a prefixed clientSecret succeeds and is stored re-encrypted, not verbatim", async () => {
    const t = await makeAuth();
    const { a, orgA } = await twoTenants(t);

    const res = await register(t, a.cookie, orgA, "poison", POISON, "acme.test");
    expect(res.status).toBe(200);

    const stored = await storedClientSecret(t, "poison");
    expect(stored).not.toBe(POISON); // never the caller's literal
    expect(stored.startsWith("enc:v1:")).toBe(true); // sealed by the wrapper
    // …and it round-trips: the caller's odd string is just a (useless) secret.
    expect(await readClientSecret(t, "poison")).toBe(POISON);
  });

  it("one undecryptable row does not break unfiltered reads for other tenants", async () => {
    const t = await makeAuth();
    const { a, orgA, b } = await twoTenants(t);
    expect((await register(t, a.cookie, orgA, "acme-okta", SECRET, "acme.test")).status).toBe(200);
    await corruptRow(t, "acme-okta");

    // upstream `GET /sso/providers` = `findMany({ model: "ssoProvider" })`
    const list = await t.api.get("/sso/providers", { cookie: b.cookie });
    expect(list.status).toBe(200);
    const { providers } = (await list.json()) as { providers: Array<{ providerId: string }> };
    expect(providers.map((p) => p.providerId)).toEqual(["beta-okta"]);
    // tenant B's own secret is untouched
    expect(await readClientSecret(t, "beta-okta")).toBe(SECRET);

    // `/sign-in/sso {email}` subdomain fallback = the same unfiltered findMany.
    // Whatever it answers for an unverified domain, it is not a 500 any more.
    const signIn = await t.api.post("/sign-in/sso", {
      email: "someone@sub.beta.test",
      callbackURL: "/",
    });
    expect(signIn.status).not.toBe(500);
  });

  it("an undecryptable row is reported through the logger, left sealed, and recoverable through the API", async () => {
    const t = await makeAuth();
    const { a, orgA } = await twoTenants(t);
    expect((await register(t, a.cookie, orgA, "acme-okta", SECRET, "acme.test")).status).toBe(200);
    await corruptRow(t, "acme-okta");
    const ctx = await t.auth.$context;
    const error = vi.spyOn(ctx.logger, "error").mockImplementation(() => {});

    // Read: plaintext is never produced; the sealed value stays in place.
    expect(await readClientSecret(t, "acme-okta")).toBe(POISON);
    expect(error).toHaveBeenCalledWith(
      expect.stringContaining('ssoProvider "acme-okta" field "oidcConfig.clientSecret"'),
    );

    // get / update / delete all work — update with a fresh secret heals the row.
    const get = await t.api.get("/sso/get-provider?providerId=acme-okta", { cookie: a.cookie });
    expect(get.status).toBe(200);
    const update = await t.api.post(
      "/sso/update-provider",
      { providerId: "acme-okta", oidcConfig: { clientSecret: "fresh-secret" } },
      { cookie: a.cookie },
    );
    expect(update.status).toBe(200);
    expect(await readClientSecret(t, "acme-okta")).toBe("fresh-secret");
    const del = await t.api.post(
      "/sso/delete-provider",
      { providerId: "acme-okta" },
      { cookie: a.cookie },
    );
    expect(del.status).toBe(200);
    error.mockRestore();
  });

  // Regression guard for the fix itself (passes before and after): the prefix
  // trust removed above was silently what kept a write through the *outer*
  // `ctx.context.adapter` inside `runWithTransaction` from being encrypted
  // twice (outer wrapper + wrapped transaction adapter). The wrapper now
  // delegates to the wrapped transaction adapter instead.
  it("a write through the outer adapter inside runWithTransaction is encrypted exactly once", async () => {
    const t = await makeAuth();
    const { a, orgA } = await twoTenants(t);
    expect((await register(t, a.cookie, orgA, "acme-okta", SECRET, "acme.test")).status).toBe(200);
    const ctx = await t.auth.$context;

    await runWithTransaction(ctx.adapter, async () => {
      await ctx.adapter.update({
        model: "ssoProvider",
        where: [{ field: "providerId", value: "acme-okta" }],
        update: { oidcConfig: JSON.stringify({ clientId: "cid", clientSecret: "second" }) },
      });
      // …and reads inside the transaction see plaintext too
      expect(await readClientSecret(t, "acme-okta")).toBe("second");
    });
    expect(await readClientSecret(t, "acme-okta")).toBe("second");
    expect((await storedClientSecret(t, "acme-okta")).startsWith("enc:v1:")).toBe(true);
  });
});

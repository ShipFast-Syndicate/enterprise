// `sso.existingUsersOnly` — the `user.create.before` backstop, end to end.
//
// The composed resolver (`src/server/sso-resolve.ts`) refuses an unknown
// address before upstream can create a user, so on the real preset the create
// hook is never reached by an OIDC callback: `requestSignUp: true` lifts
// upstream's own `disableImplicitSignUp`, and the resolver answers
// `SSO_USER_NOT_PROVISIONED` first. The hook exists for the day that stops
// being true (a resolver composed out of the list, a future code path). This
// file builds exactly that world — `composeSsoResolvers` returns the base
// resolver, as if the existingUsersOnly branch were absent — and drives a real
// callback with a forged `requestSignUp: true`, to pin the hook's whole
// contract: a 302 carrying `error=SSO_SIGNUP_DISABLED`, no session cookie, no
// new `user`, `account` or `member` row, and an `auth.sign_in_refused` audit
// row naming the code.
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { createOrg, extractCookie, makeAuth, signUpOwner, type TestAuth } from "../helpers/auth";
import { getNoRedirect, startOidcIssuer, type OidcIssuer } from "../helpers/oidc-issuer";
import { registerOidcProvider } from "../helpers/sso";
import { userRowsFor } from "./ghsa-sso-helpers";

vi.mock("../../src/server/sso-resolve", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../../src/server/sso-resolve")>()),
  composeSsoResolvers: (_opts: unknown, base: unknown) => base,
}));

let issuer: OidcIssuer;
beforeAll(async () => {
  issuer = await startOidcIssuer();
});
afterAll(async () => {
  await issuer.close();
});

async function count(t: TestAuth, table: string): Promise<number> {
  const rows = await t.client.execute({ sql: `SELECT COUNT(*) AS n FROM ${table}` });
  return Number(rows.rows[0]!.n);
}

async function counts(t: TestAuth) {
  return {
    user: await count(t, "user"),
    account: await count(t, "account"),
    member: await count(t, "member"),
  };
}

async function refusedAuditMetadata(t: TestAuth): Promise<Array<Record<string, unknown>>> {
  const rows = await t.client.execute({
    sql: `SELECT metadata FROM audit_event WHERE action = 'auth.sign_in_refused'`,
  });
  return rows.rows.map((row) => {
    const raw = row.metadata;
    return (typeof raw === "string" ? JSON.parse(raw) : raw) as Record<string, unknown>;
  });
}

async function drive(t: TestAuth, body: Record<string, unknown>): Promise<Response> {
  const signIn = await t.api.post(
    "/sign-in/sso",
    { providerId: "acme-oidc", callbackURL: "/", ...body },
    {},
  );
  expect(signIn.status).toBe(200);
  const stateCookie = extractCookie(signIn);
  const { url } = (await signIn.json()) as { url: string };
  const authorize = await getNoRedirect(url);
  return t.auth.handler(
    new Request(authorize.location!, {
      headers: { cookie: stateCookie, origin: "http://localhost:3000" },
    }),
  );
}

describe("existingUsersOnly — the create-hook backstop reached through a real callback", () => {
  it("a forged requestSignUp:true for an unknown address is refused with SSO_SIGNUP_DISABLED, creating nothing and leaving an audit row", async () => {
    const t = await makeAuth({
      trustedOrigins: [issuer.issuerUrl],
      account: { accountLinking: { enabled: false } },
      sso: { existingUsersOnly: true, organizationProvisioning: "off" },
    });
    const owner = await signUpOwner(t, "owner@acme.test");
    const { orgId } = await createOrg(t, owner.cookie, "acme");
    await registerOidcProvider(t, owner.cookie, orgId, issuer, "acme-oidc", "acme.test");
    issuer.setUser({ sub: "sub-ghost", email: "ghost@acme.test", hd: "acme.test" });

    // Without the escape hatch, upstream's own switch refuses first (not our code).
    const plain = await drive(t, {});
    expect(plain.headers.get("location") ?? "").toContain("error=signup+disabled");

    const before = await counts(t);
    const res = await drive(t, { requestSignUp: true });
    expect(res.status).toBe(302);
    expect(res.headers.get("location") ?? "").toContain("error=SSO_SIGNUP_DISABLED");
    expect(extractCookie(res)).not.toContain("session_token");
    expect(await counts(t)).toEqual(before);
    expect(await userRowsFor(t, "ghost@acme.test")).toBe(0);
    const refused = await refusedAuditMetadata(t);
    expect(refused.some((m) => m.code === "SSO_SIGNUP_DISABLED")).toBe(true);
  });
});

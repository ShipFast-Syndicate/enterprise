// Contract for the README's "`./server` runs on Cloudflare Workers/workerd"
// claim: this file runs inside the real workerd runtime (the `workerd` Vitest
// project, `vitest.config.ts`), not under Node. It boots `enterprisePreset`
// on better-auth's memory adapter — no libsql, no filesystem — and drives the
// SSO, SCIM and audit surfaces through the same `auth.handler(Request)` a
// Worker would call from `fetch`.
import { env } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import { betterAuth, type BetterAuthOptions } from "better-auth";
import { getAuthTables } from "better-auth/db";
import { memoryAdapter } from "better-auth/adapters/memory";
import { enterprisePreset } from "../../src/server/preset";
import { flushAuditWrites } from "../../src/server/audit/background";
import type { Feature } from "../../src/server/types";

const ORIGIN = "https://auth.test";
const entitled = new Set<Feature>(["sso", "scim", "audit_log", "enforce_2fa", "api_keys", "teams"]);
const ENTERPRISE_MODELS = ["org_policy", "audit_event", "scim_group", "enterprise_scim_member"];
const IDP_ENTITY_ID = "https://idp.test/entity";

// The memory adapter throws "Model not found" for any model nobody seeded.
// `getAuthTables` lists every upstream/plugin model for these options; the
// four tables the enterprise SQL migration adds (`src/schema/sql`) are not in
// better-auth's registry, so a memory-backed deployment seeds them itself.
function boot() {
  const options: BetterAuthOptions = {
    secret: "x".repeat(32),
    baseURL: ORIGIN,
    emailAndPassword: { enabled: true },
    // No client secret is ever used: `sign-in/social` only builds the
    // authorization URL, it never calls the provider.
    socialProviders: { github: { clientId: "client-id", clientSecret: "client-secret" } },
    plugins: enterprisePreset({
      product: "workerd",
      secretsKey: "s".repeat(32),
      scimCredentialHashSecret: "scim-hash-key-".repeat(3),
      resolveEntitlements: async () => entitled,
    }),
  };
  const store: Record<string, unknown[]> = {};
  for (const table of Object.values(getAuthTables(options))) store[table.modelName] = [];
  for (const model of ENTERPRISE_MODELS) store[model] = [];
  const auth = betterAuth({ ...options, database: memoryAdapter(store) });
  const call = async (path: string, init: RequestInit & { cookie?: string } = {}) => {
    const { cookie, ...rest } = init;
    const res = await auth.handler(
      new Request(`${ORIGIN}/api/auth${path}`, {
        ...rest,
        headers: {
          origin: ORIGIN,
          ...(rest.body ? { "content-type": "application/json" } : {}),
          ...(cookie ? { cookie } : {}),
          ...(rest.headers as Record<string, string> | undefined),
        },
      }),
    );
    // Audit rows about the caller are written off the response path; settle
    // them the way a Worker's `waitUntil` would.
    await flushAuditWrites();
    return res;
  };
  const post = (path: string, body: unknown, headers: Record<string, string> = {}) =>
    call(path, { method: "POST", body: JSON.stringify(body), headers });
  return { auth, call, post };
}

async function ownerWithOrg(t: ReturnType<typeof boot>) {
  const signUp = await t.post("/sign-up/email", {
    name: "Owner",
    email: "owner@acme.test",
    password: "password1234",
  });
  expect(signUp.status, await signUp.clone().text()).toBe(200);
  const cookie = signUp.headers
    .getSetCookie()
    .map((raw) => raw.split(";")[0])
    .join("; ");
  const org = await t.post("/organization/create", { name: "acme", slug: "acme" }, { cookie });
  expect(org.status, await org.clone().text()).toBe(200);
  const { id: orgId } = (await org.json()) as { id: string };
  return { cookie, orgId };
}

describe("enterprisePreset inside workerd", () => {
  it("runs on workerd with the memory adapter", () => {
    expect(navigator.userAgent).toBe("Cloudflare-Workers");
    expect(typeof env.IDP_CERT).toBe("string");
  });

  it("starts a social sign-in", async () => {
    const t = boot();
    const res = await t.post("/sign-in/social", {
      provider: "github",
      callbackURL: `${ORIGIN}/dashboard`,
    });
    expect(res.status, await res.clone().text()).toBe(200);
    const body = (await res.json()) as { url: string; redirect: boolean };
    expect(body.redirect).toBe(true);
    const url = new URL(body.url);
    expect(url.origin + url.pathname).toBe("https://github.com/login/oauth/authorize");
    expect(url.searchParams.get("client_id")).toBe("client-id");
    expect(url.searchParams.get("state")).toBeTruthy();
  });

  it("serves SAML SP metadata for a registered provider", async () => {
    const t = boot();
    const { cookie, orgId } = await ownerWithOrg(t);
    const providerId = "saml-workerd";
    const acsUrl = `${ORIGIN}/api/auth/sso/saml2/sp/acs/${providerId}`;
    const register = await t.post(
      "/sso/register",
      {
        providerId,
        issuer: IDP_ENTITY_ID,
        domain: "acme.test",
        organizationId: orgId,
        samlConfig: {
          entryPoint: `${IDP_ENTITY_ID}/sso`,
          cert: env.IDP_CERT,
          idpMetadata: { entityID: IDP_ENTITY_ID },
          callbackUrl: acsUrl,
          spMetadata: { entityID: `${ORIGIN}/api/auth/sso/saml2/sp/${providerId}` },
        },
      },
      { cookie },
    );
    expect(register.status, await register.clone().text()).toBe(200);
    const metadata = await t.call(`/sso/saml2/sp/metadata?providerId=${providerId}`);
    expect(metadata.status, await metadata.clone().text()).toBe(200);
    const xml = await metadata.text();
    expect(xml).toContain("EntityDescriptor");
    expect(xml).toContain(acsUrl);
  });

  it("answers SCIM ServiceProviderConfig and lists Groups", async () => {
    const t = boot();
    const { cookie, orgId } = await ownerWithOrg(t);
    const token = await t.post(
      "/enterprise/scim/tokens/create",
      { providerId: "okta", orgId },
      { cookie },
    );
    expect(token.status, await token.clone().text()).toBe(200);
    const { scimToken } = (await token.json()) as { scimToken: string };
    const bearer = { authorization: `Bearer ${scimToken}` };

    const config = await t.call("/scim/v2/ServiceProviderConfig", { headers: bearer });
    expect(config.status, await config.clone().text()).toBe(200);
    expect(((await config.json()) as { schemas: string[] }).schemas).toContain(
      "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig",
    );

    const groups = await t.call("/scim/v2/Groups", { headers: bearer });
    expect(groups.status, await groups.clone().text()).toBe(200);
    const list = (await groups.json()) as { schemas: string[]; totalResults: number };
    expect(list.schemas).toContain("urn:ietf:params:scim:api:messages:2.0:ListResponse");
    expect(list.totalResults).toBe(0);
  });

  it("writes an audit event that the audit API reads back", async () => {
    const t = boot();
    const { cookie, orgId } = await ownerWithOrg(t);
    const invite = await t.post(
      "/organization/invite-member",
      { email: "new@acme.test", role: "member", organizationId: orgId },
      { cookie },
    );
    expect(invite.status, await invite.clone().text()).toBe(200);
    const list = await t.call(`/enterprise/audit/list?orgId=${orgId}`, { cookie });
    expect(list.status, await list.clone().text()).toBe(200);
    const { items } = (await list.json()) as { items: { action: string }[] };
    expect(items.map((item) => item.action)).toEqual(["member.invited"]);
    // The hash chain is computed with Web Crypto inside workerd.
    const verify = await t.call(`/enterprise/audit/verify?orgId=${orgId}`, { cookie });
    expect(verify.status, await verify.clone().text()).toBe(200);
    expect(((await verify.json()) as { ok: boolean }).ok).toBe(true);
  });
});

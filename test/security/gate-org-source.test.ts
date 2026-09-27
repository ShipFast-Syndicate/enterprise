// The entitlement gate checks the organization the endpoint acts on, never
// an organization the caller names in a field the endpoint ignores.
//
// - Every `GATED_PATHS` entry has exactly one declared org source
//   (`GATE_ORG_SOURCES`), each cited `file:line` still reads the declared
//   field, and a gated path without a source is refused.
// - For every gated path: the caller is an owner of an entitled org E and of
//   an unentitled org U, the endpoint acts on U, and E is named in every
//   carrier the endpoint ignores (`?orgId`, `?organizationId`, body `orgId` /
//   `organizationId`, and the active organization). Each request answers
//   403, and nothing in the database changes — no team, key, provider,
//   policy, token or audit row. The mirror image (acting on E, U named
//   everywhere else) is not refused.
// - Audit rows follow the same rule: a provider row goes to the provider the
//   route acts on (the `:providerId` parameter where the route has one, else
//   `body.providerId`), a request-org row to the one field the endpoint reads.
//
// Against the parent commit the gate took the first org id in
// `body.organizationId`, `body.orgId`, `?orgId`, then the active org:
// `/organization/create-team` and `/api-key/create` named E in `body.orgId`
// or `?orgId`, passed the gate, and created a team in U (a user key for a
// caller whose active org was U).

import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { baseAuthOptions, createOrg, makeAuth, signUpOwner, type TestAuth } from "../helpers/auth";
import * as gate from "../../src/server/gate";
import type { GateOrgSource } from "../../src/server/gate";
import { AUDITED_PATHS } from "../../src/server/audit/routes";
import * as auditPlugin from "../../src/server/audit/plugin";
import type { Feature } from "../../src/server/types";

const { GATED_PATHS } = gate;
/** The gate's own table (read by namespace so this file also runs where it is missing). */
const GATE_ORG_SOURCES = (gate as { GATE_ORG_SOURCES?: Record<string, GateOrgSource> })
  .GATE_ORG_SOURCES;

type Oracle =
  | { kind: "provider" }
  | {
      kind: "request";
      fields: Array<{ from: "body" | "query"; field: "organizationId" | "orgId" }>;
      activeOrganization: boolean;
    };

const acts = (
  from: "body" | "query",
  field: "organizationId" | "orgId",
  activeOrganization = false,
): Oracle => ({ kind: "request", fields: [{ from, field }], activeOrganization });

/**
 * What each gated endpoint acts on, read off its handler — kept here,
 * independently of the gate's `GATE_ORG_SOURCES`, so a wrong entry there
 * cannot also be the test's expectation.
 *
 * - `@better-auth/sso`: `/sso/register` files the provider under
 *   `body.organizationId`; update/delete/request-domain-verification/
 *   verify-domain act on the stored provider `body.providerId` names
 *   (`checkProviderAccess(ctx, body.providerId)`).
 * - organization plugin `createTeam`: `ctx.body.organizationId ||
 *   session.activeOrganizationId`.
 * - `@better-auth/api-key` create: `ctx.body.organizationId` (org-owned keys);
 *   a user-owned key has no org, and the session's active org is the one
 *   whose entitlement applies.
 * - this package's `/enterprise/*` handlers: the one field each declares.
 */
const ACTED_ON: Record<string, Oracle> = {
  "/sso/register": acts("body", "organizationId"),
  "/sso/request-domain-verification": { kind: "provider" },
  "/sso/verify-domain": { kind: "provider" },
  "/sso/update-provider": { kind: "provider" },
  "/sso/delete-provider": { kind: "provider" },
  "/organization/create-team": acts("body", "organizationId", true),
  "/api-key/create": acts("body", "organizationId", true),
  "/enterprise/audit/list": acts("query", "orgId"),
  "/enterprise/audit/export": acts("query", "orgId"),
  "/enterprise/audit/compact": acts("body", "orgId"),
  "/enterprise/policy/set": acts("body", "orgId"),
  "/enterprise/sso/providers": acts("query", "orgId"),
  "/enterprise/sso/register": acts("body", "organizationId"),
  "/enterprise/sso/test-login/start": acts("body", "orgId"),
  "/enterprise/scim/tokens": acts("query", "orgId"),
  "/enterprise/scim/tokens/create": acts("body", "orgId"),
  "/enterprise/scim/tokens/rotate": acts("body", "orgId"),
  "/enterprise/scim/tokens/revoke": acts("body", "orgId"),
};

const ROOT = resolve(__dirname, "../..");
const ALL_FEATURES: Feature[] = ["sso", "scim", "audit_log", "enforce_2fa", "api_keys", "teams"];
const CARRIERS = [
  { from: "body", field: "organizationId" },
  { from: "body", field: "orgId" },
  { from: "query", field: "organizationId" },
  { from: "query", field: "orgId" },
] as const;

const OIDC = {
  clientId: "client",
  clientSecret: "secret-value",
  skipDiscovery: true,
  authorizationEndpoint: "https://idp.test/authorize",
  tokenEndpoint: "https://idp.test/token",
  jwksEndpoint: "https://idp.test/jwks",
};

/** The HTTP method of every endpoint the preset registers, by path. */
function registeredMethods(): Map<string, string> {
  const methods = new Map<string, string>();
  for (const plugin of baseAuthOptions().plugins ?? []) {
    for (const value of Object.values((plugin as { endpoints?: object }).endpoints ?? {})) {
      const endpoint = value as { path?: string; options?: { method?: string | string[] } };
      if (typeof endpoint?.path !== "string") continue;
      const method = endpoint.options?.method ?? "GET";
      methods.set(endpoint.path, Array.isArray(method) ? method[0]! : method);
    }
  }
  return methods;
}
const METHODS = registeredMethods();

interface World {
  t: TestAuth;
  cookie: string;
  E: string;
  U: string;
  providerOf: Record<string, string>;
}

/**
 * Owner of E (entitled to everything) and U (entitled to nothing), with one
 * OIDC provider in each (registered while U was still entitled).
 */
async function world(): Promise<World> {
  const entitled = new Map<string, Set<Feature>>();
  const t = await makeAuth({
    resolveEntitlements: async (orgId: string) => entitled.get(orgId) ?? new Set(ALL_FEATURES),
  });
  const owner = await signUpOwner(t, "owner@acme.test");
  const { orgId: E } = await createOrg(t, owner.cookie, "entitled");
  const { orgId: U } = await createOrg(t, owner.cookie, "unentitled");
  const providerOf: Record<string, string> = {};
  for (const [org, providerId, domain] of [
    [E, "p-e", "e.test"],
    [U, "p-u", "u.test"],
  ] as const) {
    const res = await t.api.post(
      "/sso/register",
      { providerId, issuer: "https://idp.test", domain, organizationId: org, oidcConfig: OIDC },
      { cookie: owner.cookie },
    );
    expect(res.status, await res.clone().text()).toBe(200);
    providerOf[org] = providerId;
  }
  // Domain ownership is a separate check (`/enterprise/sso/test-login/start`
  // refuses an unverified provider); both providers pass it here.
  await t.client.execute("UPDATE ssoProvider SET domainVerified = 1");
  entitled.set(U, new Set());
  return { t, cookie: owner.cookie, E, U, providerOf };
}

async function setActive(w: World, orgId: string) {
  const res = await w.t.api.post(
    "/organization/set-active",
    { organizationId: orgId },
    { cookie: w.cookie },
  );
  expect(res.status).toBe(200);
}

/** A body the endpoint accepts apart from its org, so a request the gate lets through does something. */
function extraBody(path: string, w: World, org: string): Record<string, unknown> {
  switch (path) {
    case "/sso/register":
    case "/enterprise/sso/register":
      return {
        providerId: "p-new",
        issuer: "https://idp.test",
        domain: "new.test",
        oidcConfig: OIDC,
      };
    case "/organization/create-team":
      return { name: "t-new" };
    case "/api-key/create":
      return { name: "k-new" };
    case "/sso/update-provider":
      return { oidcConfig: { clientId: "client-2" } };
    case "/enterprise/policy/set":
      return { sessionMaxAgeS: 3600 };
    case "/enterprise/sso/test-login/start":
    case "/enterprise/scim/tokens/create":
    case "/enterprise/scim/tokens/rotate":
    case "/enterprise/scim/tokens/revoke":
      return { providerId: w.providerOf[org] };
    default:
      return {};
  }
}

interface Case {
  label: string;
  /** The session's active organization during the request. */
  active: string;
  url: string;
  method: string;
  body?: Record<string, unknown>;
}

/**
 * The requests that make `path` act on `acted` while naming `named` in every
 * carrier the endpoint ignores. A `request` source with an active-org
 * fallback gets a second request that acts on `acted` through the active
 * organization alone.
 */
function cases(path: string, source: Oracle, w: World, acted: string, named: string): Case[] {
  const method = METHODS.get(path) ?? "POST";
  const hasBody = method !== "GET";
  const build = (
    label: string,
    active: string,
    declared: Array<{ from: "body" | "query"; field: string }>,
    base: Record<string, unknown>,
  ): Case => {
    const body: Record<string, unknown> = { ...base };
    const query = new URLSearchParams();
    for (const carrier of CARRIERS) {
      if (carrier.from === "body" && !hasBody) continue;
      const isDeclared = declared.some((d) => d.from === carrier.from && d.field === carrier.field);
      const value = isDeclared ? acted : named;
      if (carrier.from === "body") body[carrier.field] = value;
      else query.set(carrier.field, value);
    }
    return {
      label,
      active,
      url: `${path}?${query.toString()}`,
      method,
      body: hasBody ? body : undefined,
    };
  };
  const base = extraBody(path, w, acted);
  if (source.kind === "provider") {
    return [
      build("provider of the acted-on org", named, [], {
        ...base,
        providerId: w.providerOf[acted],
      }),
    ];
  }
  const out = [build("declared field", named, source.fields.slice(0, 1) as never, base)];
  if (source.activeOrganization) {
    // No declared field: the endpoint acts on the active organization.
    const viaActive = build("active organization", acted, [], base);
    for (const field of source.fields) {
      if (field.from === "body") delete viaActive.body?.[field.field];
      else {
        const url = new URL(viaActive.url, "http://x");
        url.searchParams.delete(field.field);
        viaActive.url = `${url.pathname}${url.search}`;
      }
    }
    out.push(viaActive);
  }
  return out;
}

/** Every row of every table, for a before/after comparison. */
async function snapshot(t: TestAuth): Promise<string> {
  const tables = await t.client.execute(
    `SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name`,
  );
  const out: Record<string, unknown> = {};
  for (const row of tables.rows) {
    const name = String(row.name);
    const rows = await t.client.execute(`SELECT * FROM "${name}" ORDER BY rowid`);
    out[name] = rows.rows;
  }
  return JSON.stringify(out);
}

/** Sends `c`; the caller has already made `c.active` the active organization. */
function send(w: World, c: Case): Promise<Response> {
  return w.t.api.request(c.method, c.url, c.body, { cookie: w.cookie });
}

describe("every gated path has a declared org source, read off the handler", () => {
  it("GATE_ORG_SOURCES covers GATED_PATHS exactly, and each entry is what the handler acts on", () => {
    expect(GATE_ORG_SOURCES, "the gate declares an org source per path").toBeDefined();
    expect(Object.keys(GATE_ORG_SOURCES!).sort()).toEqual(Object.keys(GATED_PATHS).sort());
    expect(Object.keys(ACTED_ON).sort()).toEqual(Object.keys(GATED_PATHS).sort());
    for (const [path, source] of Object.entries(GATE_ORG_SOURCES!)) {
      const declared: Record<string, unknown> = { ...source };
      delete declared.refs;
      expect(declared, path).toEqual(ACTED_ON[path]);
    }
  });

  for (const [path, source] of Object.entries(GATE_ORG_SOURCES ?? {})) {
    it(`${path}: each cited line reads the declared source`, () => {
      expect(source.refs.length).toBeGreaterThan(0);
      for (const ref of source.refs) {
        const at = ref.lastIndexOf(":");
        const file = ref.slice(0, at);
        const line = Number(ref.slice(at + 1));
        const text = readFileSync(resolve(ROOT, file), "utf8").split("\n")[line - 1] ?? "";
        if (source.kind === "provider") {
          expect(text, ref).toMatch(/\bproviderId\b/);
          expect(text, ref).toMatch(/\bbody\b/);
        } else {
          for (const { from, field } of source.fields) {
            expect(text, ref).toMatch(new RegExp(`\\b${field}\\b`));
            expect(text, ref).toMatch(new RegExp(`\\b${from}\\b`));
          }
        }
      }
    });
  }

  it("a gated path without a declared source is refused, and nothing changes", async () => {
    const w = await world();
    await setActive(w, w.E);
    const path = "/organization/update";
    GATED_PATHS[path] = "teams";
    try {
      const before = await snapshot(w.t);
      for (const headers of [{ cookie: w.cookie }, {}]) {
        const res = await w.t.api.post(
          path,
          { organizationId: w.E, data: { name: "renamed" } },
          headers,
        );
        expect(res.status).toBe(403);
        expect(((await res.json()) as { code?: string }).code).toBe("GATE_ORG_SOURCE_UNDECLARED");
      }
      expect(await snapshot(w.t)).toBe(before);
    } finally {
      delete GATED_PATHS[path];
    }
  });
});

describe("the gate checks the org the endpoint acts on, never one named in a field it ignores", () => {
  for (const path of Object.keys(GATED_PATHS).sort()) {
    it(`${path}: acting on the unentitled org with the entitled one named everywhere else → 403, nothing changes`, async () => {
      const source = ACTED_ON[path];
      expect(source, `${path}: the test knows what the endpoint acts on`).toBeDefined();
      const w = await world();
      for (const c of cases(path, source!, w, w.U, w.E)) {
        await setActive(w, c.active);
        const before = await snapshot(w.t);
        const res = await send(w, c);
        expect(res.status, `${c.label}: ${c.method} ${c.url} ${await res.clone().text()}`).toBe(
          403,
        );
        expect(await snapshot(w.t), `${c.label}: database unchanged`).toBe(before);
      }
    });

    it(`${path}: acting on the entitled org with the unentitled one named everywhere else is not refused`, async () => {
      const source = ACTED_ON[path];
      expect(source, `${path}: the test knows what the endpoint acts on`).toBeDefined();
      const w = await world();
      for (const c of cases(path, source!, w, w.E, w.U)) {
        await setActive(w, c.active);
        const res = await send(w, c);
        const text = await res.clone().text();
        expect([401, 403], `${c.label}: ${c.method} ${c.url} ${res.status} ${text}`).not.toContain(
          res.status,
        );
      }
    });
  }

  it("create-team through a caller-named org: the team is not created in the unentitled active org", async () => {
    const w = await world();
    await setActive(w, w.U);
    for (const url of [
      `/organization/create-team?orgId=${w.E}`,
      `/organization/create-team?organizationId=${w.E}`,
    ]) {
      const res = await w.t.api.post(url, { name: "t1" }, { cookie: w.cookie });
      expect(res.status, url).toBe(403);
    }
    const viaBody = await w.t.api.post(
      "/organization/create-team",
      { name: "t1", orgId: w.E },
      { cookie: w.cookie },
    );
    expect(viaBody.status).toBe(403);
    const teams = await w.t.client.execute({
      sql: "SELECT organizationId FROM team WHERE name = 't1'",
      args: [],
    });
    expect(teams.rows).toEqual([]);
  });
});

describe("audit rows go to the org the route acts on", () => {
  it("every provider-scoped audited route reads the provider it acts on: the route parameter, else the body", () => {
    const providerPaths = Object.entries(AUDITED_PATHS)
      .filter(([, entry]) => entry.scope === "provider")
      .map(([path]) => path);
    expect(providerPaths.length).toBeGreaterThan(4);
    const actedOnProviderId = (
      auditPlugin as {
        actedOnProviderId?: (ctx: { body?: unknown; params?: unknown }, path: string) => unknown;
      }
    ).actedOnProviderId;
    expect(typeof actedOnProviderId, "the audit plugin exposes its provider source").toBe(
      "function",
    );
    for (const path of providerPaths) {
      const ctx = { params: { providerId: "from-route" }, body: { providerId: "from-body" } };
      expect(actedOnProviderId!(ctx, path), path).toBe(
        path.includes(":providerId") ? "from-route" : "from-body",
      );
      expect(actedOnProviderId!({ body: { providerId: "from-body" } }, path), path).toBe(
        path.includes(":providerId") ? null : "from-body",
      );
    }
  });

  it("/enterprise/policy/set: the row goes to body.orgId, never to a body.organizationId next to it", async () => {
    const w = await world();
    await setActive(w, w.E);
    const res = await w.t.api.post(
      `/enterprise/policy/set?orgId=${w.U}&organizationId=${w.U}`,
      { orgId: w.E, organizationId: w.U, sessionMaxAgeS: 3600 },
      { cookie: w.cookie },
    );
    expect(res.status, await res.clone().text()).toBe(200);
    const rows = await w.t.client.execute({
      sql: "SELECT org_id FROM audit_event WHERE action = 'policy.updated'",
      args: [],
    });
    expect(rows.rows.map((r) => r.org_id)).toEqual([w.E]);
  });
});

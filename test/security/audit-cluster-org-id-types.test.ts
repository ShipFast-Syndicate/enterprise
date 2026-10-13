// Organization ids from a request are used only when they are ids, and a
// failed query never puts its SQL in the logs.
//
// - A walk over every gated path (`GATED_PATHS`) and every `/enterprise/*`
//   endpoint sends org ids that are not short strings — a duplicated query
//   parameter (which parses to an array), an array, an object, a number, a
//   boolean, `null`, an oversized string — in every field that carries one.
//   Each request that reads an org id answers 4xx, none answers 500, no such
//   value is ever bound to a query, and nothing written to the auth logger or
//   the console contains SQL or the value sent.
// - A query that does fail through the auth adapter (a missing table, a
//   value the driver cannot bind, a unique violation, inside a transaction or
//   not) surfaces as a `DatabaseQueryError` that names the model, the adapter
//   method, the driver code and a missing-table hint, and carries neither the
//   statement nor its parameters.
//
// Every assertion states the fixed behaviour. Against the parent commit the
// gate passed a non-string org id to its membership query: the request
// answered 500 and the failed query, with its parameters, went to the error
// log and to `console.error`.

import { inspect } from "node:util";
import { describe, expect, it, vi } from "vitest";
import { APIError } from "better-auth/api";
import { runWithTransaction } from "@better-auth/core/context";
import { baseAuthOptions, createOrg, makeAuth, signUpOwner, type TestAuth } from "../helpers/auth";
import { GATED_PATHS } from "../../src/server/gate";
import { isUniqueViolation } from "../../src/server/audit/chain";

const SENTINEL = "zz-org-id-sentinel";
const SQL = /failed query|select\s+"|insert\s+into|delete\s+from|update\s+"|\bparams:/i;

interface EndpointLike {
  path?: string;
  options?: {
    method?: string | string[];
    query?: { shape?: Record<string, unknown> };
    body?: { shape?: Record<string, unknown> };
  };
}

/**
 * Every gated path and every `/enterprise/*` endpoint the preset registers,
 * read off the preset's plugins so each one gets its own test case.
 */
function endpoints(): Map<string, EndpointLike> {
  const found = new Map<string, EndpointLike>();
  for (const plugin of baseAuthOptions().plugins ?? []) {
    for (const value of Object.values((plugin as { endpoints?: object }).endpoints ?? {})) {
      const endpoint = value as EndpointLike;
      const path = endpoint?.path;
      if (typeof path !== "string") continue;
      if (path in GATED_PATHS || path.startsWith("/enterprise/")) found.set(path, endpoint);
    }
  }
  return new Map([...found.entries()].sort(([a], [b]) => a.localeCompare(b)));
}

const ENDPOINTS = endpoints();

function methodsOf(endpoint: EndpointLike): string[] {
  const method = endpoint.options?.method ?? "GET";
  const list = Array.isArray(method) ? method : [method];
  return list.filter((m) => m !== "*").length > 0 ? list.filter((m) => m !== "*") : ["POST"];
}

/** Whether the endpoint takes an org id: the gate reads one for every gated path; the others declare it. */
function readsOrgId(path: string, endpoint: EndpointLike): boolean {
  if (path in GATED_PATHS) return true;
  const keys = [
    ...Object.keys(endpoint.options?.query?.shape ?? {}),
    ...Object.keys(endpoint.options?.body?.shape ?? {}),
  ];
  return keys.includes("orgId") || keys.includes("organizationId");
}

/** Everything written to the auth logger or the console while `run` runs, and every value bound to a query. */
async function observe(t: TestAuth, run: () => Promise<void>) {
  const ctx = await t.auth.$context;
  const lines: string[] = [];
  const record = (...args: unknown[]) => {
    lines.push(
      args.map((arg) => (typeof arg === "string" ? arg : inspect(arg, { depth: 6 }))).join(" "),
    );
  };
  const spies = [
    ...(["error", "warn", "info", "debug", "success"] as const)
      .filter((level) => typeof (ctx.logger as Record<string, unknown>)[level] === "function")
      .map((level) => vi.spyOn(ctx.logger, level).mockImplementation(record)),
    ...(["error", "warn", "info", "log", "debug"] as const).map((level) =>
      vi.spyOn(console, level).mockImplementation(record),
    ),
  ];
  const bound: unknown[] = [];
  const original = t.client.execute.bind(t.client);
  const execute = vi.spyOn(t.client, "execute").mockImplementation(((statement: unknown) => {
    if (statement && typeof statement === "object" && "args" in statement) {
      bound.push(...((statement as { args?: unknown[] }).args ?? []));
    }
    return original(statement as never);
  }) as typeof t.client.execute);
  try {
    await run();
  } finally {
    for (const spy of spies) spy.mockRestore();
    execute.mockRestore();
  }
  return { logged: lines.join("\n"), bound };
}

function scalar(value: unknown): boolean {
  return (
    value === null ||
    ["string", "number", "bigint", "boolean"].includes(typeof value) ||
    value instanceof Date ||
    value instanceof Uint8Array ||
    value instanceof ArrayBuffer
  );
}

async function world() {
  const t = await makeAuth();
  const owner = await signUpOwner(t, "owner@acme.test");
  const { orgId } = await createOrg(t, owner.cookie);
  const res = await t.api.post(
    "/organization/set-active",
    { organizationId: orgId },
    { cookie: owner.cookie },
  );
  expect(res.status).toBe(200);
  return { t, cookie: owner.cookie, orgId };
}

const BAD_VALUES: [string, unknown][] = [
  ["an array", [SENTINEL]],
  ["an object", { id: SENTINEL }],
  ["a number", 1],
  ["a boolean", true],
  ["null", null],
  ["an oversized string", `${SENTINEL}${"o".repeat(10_000)}`],
];

describe("every gated path and every /enterprise endpoint refuses an org id that is not one", () => {
  it("the walk covers every gated path and every /enterprise endpoint", () => {
    for (const path of Object.keys(GATED_PATHS)) expect(ENDPOINTS.has(path), path).toBe(true);
    expect(
      [...ENDPOINTS.keys()].filter((p) => p.startsWith("/enterprise/")).length,
    ).toBeGreaterThanOrEqual(16);
  });

  for (const [path, endpoint] of ENDPOINTS) {
    it(`${path}: 4xx where an org id is read, never 500, only scalars bound, no SQL or sent value logged`, async () => {
      const { t, cookie, orgId } = await world();
      const strict = readsOrgId(path, endpoint);
      const wrong: string[] = [];
      const check = (label: string, status: number) => {
        if (status >= 500 || (strict && status < 400)) wrong.push(`${label} → ${status}`);
      };
      const { logged, bound } = await observe(t, async () => {
        for (const method of methodsOf(endpoint)) {
          for (const url of [
            `${path}?orgId=${orgId}&orgId=${SENTINEL}`,
            `${path}?organizationId=${orgId}&organizationId=${SENTINEL}`,
            `${path}?orgId=${SENTINEL}${"o".repeat(10_000)}`,
          ]) {
            const body = method === "GET" ? undefined : { orgId };
            const res = await t.api.request(method, url, body, { cookie });
            check(`${method} ${url.slice(0, 90)}`, res.status);
          }
          if (method === "GET") continue;
          for (const field of ["orgId", "organizationId"]) {
            for (const [label, value] of BAD_VALUES) {
              const res = await t.api.request(method, path, { [field]: value }, { cookie });
              check(`${method} ${field}=${label}`, res.status);
            }
          }
        }
      });
      expect(wrong).toEqual([]);
      // The gate checks the org id before the session lookup: a gated path
      // refuses these requests before any query runs at all.
      if (path in GATED_PATHS) expect(bound).toEqual([]);
      expect(bound.filter((value) => !scalar(value))).toEqual([]);
      expect(
        bound.filter((value) => typeof value === "string" && value.includes(SENTINEL)),
      ).toEqual([]);
      expect(logged).not.toMatch(SQL);
      expect(logged).not.toContain(SENTINEL);
    });
  }

  it("the gate answers 400 ORG_ID_INVALID for each kind of value, before the endpoint runs", async () => {
    const { t, cookie, orgId } = await world();
    for (const [label, value] of BAD_VALUES.filter(([, v]) => v !== null)) {
      const res = await t.api.post("/enterprise/audit/compact", { orgId: value }, { cookie });
      expect(res.status, label).toBe(400);
      expect(((await res.json()) as { code?: string }).code, label).toBe("ORG_ID_INVALID");
    }
    const dup = await t.api.get(`/enterprise/audit/list?orgId=${orgId}&orgId=${orgId}`, {
      cookie,
    });
    expect(dup.status).toBe(400);
    expect(((await dup.json()) as { code?: string }).code).toBe("ORG_ID_INVALID");
  });

  it("an ordinary org id still works on the same endpoints", async () => {
    const { t, cookie, orgId } = await world();
    for (const url of [
      `/enterprise/audit/list?orgId=${orgId}`,
      `/enterprise/audit/export?orgId=${orgId}`,
      `/enterprise/features?orgId=${orgId}`,
      `/enterprise/members?orgId=${orgId}`,
      `/enterprise/policy?orgId=${orgId}`,
      `/enterprise/scim/tokens?orgId=${orgId}`,
    ]) {
      const res = await t.api.get(url, { cookie });
      expect(res.status, url).toBe(200);
    }
    const team = await t.api.post(
      "/organization/create-team",
      { name: "t1", organizationId: orgId },
      { cookie },
    );
    expect(team.status).toBe(200);
  });
});

describe("a query that fails through the auth adapter is logged without its SQL", () => {
  it("an endpoint whose query fails answers 500; the logs name the missing table, not the statement or its values", async () => {
    const { t, cookie, orgId } = await world();
    await t.client.execute("DROP TABLE member");
    const { logged, bound } = await observe(t, async () => {
      const res = await t.api.get(`/enterprise/policy?orgId=${orgId}`, { cookie });
      expect(res.status).toBe(500);
      expect(await res.text()).not.toMatch(SQL);
    });
    // The probe sees both sides: the query ran with the org id bound …
    expect(bound).toContain(orgId);
    // … and what reached the logs names the problem, not the statement.
    expect(logged).toContain("no such table: member");
    expect(logged).toContain("DatabaseQueryError");
    expect(logged).not.toMatch(SQL);
    expect(logged).not.toContain(orgId);
  });

  it("a value the driver cannot bind: the error carries no statement and no parameters", async () => {
    const { t } = await world();
    const ctx = await t.auth.$context;
    const error = await ctx.adapter
      .findOne({
        model: "member",
        where: [{ field: "organizationId", value: [SENTINEL, "b"] as unknown as string }],
      })
      .then(
        () => null,
        (e: unknown) => e,
      );
    expect(error).toBeInstanceOf(Error);
    expect((error as Error).name).toBe("DatabaseQueryError");
    expect((error as Error).message).toContain("member.findOne");
    const printed = inspect(error, { depth: 6 });
    expect(printed).not.toMatch(SQL);
    expect(printed).not.toContain(SENTINEL);
    expect(error).not.toHaveProperty("query");
    expect(error).not.toHaveProperty("params");
    expect((error as { cause?: unknown }).cause).toBeUndefined();
  });

  it("a unique violation keeps the driver code, so unique-violation checks still recognise it", async () => {
    const { t, orgId } = await world();
    const ctx = await t.auth.$context;
    const user = await signUpOwner(t, "second@acme.test");
    const row = {
      id: `dup-${SENTINEL}`,
      organizationId: orgId,
      userId: user.userId,
      role: "member",
      createdAt: new Date(),
    };
    await ctx.adapter.create({ model: "member", data: row, forceAllowId: true });
    const error = await ctx.adapter.create({ model: "member", data: row, forceAllowId: true }).then(
      () => null,
      (e: unknown) => e,
    );
    expect((error as Error).name).toBe("DatabaseQueryError");
    expect(String((error as { code?: unknown }).code)).toMatch(/^SQLITE_CONSTRAINT/);
    expect(isUniqueViolation(error)).toBe(true);
    const printed = inspect(error, { depth: 6 });
    expect(printed).not.toMatch(SQL);
    expect(printed).not.toContain(SENTINEL);
  });

  it("inside a transaction too; an APIError thrown inside one passes through unchanged", async () => {
    const { t } = await world();
    const ctx = await t.auth.$context;
    const failed = await runWithTransaction(ctx.adapter, async () => {
      await ctx.adapter.findOne({
        model: "member",
        where: [{ field: "organizationId", value: { id: SENTINEL } as unknown as string }],
      });
    }).then(
      () => null,
      (e: unknown) => e,
    );
    expect((failed as Error).name).toBe("DatabaseQueryError");
    expect(inspect(failed, { depth: 6 })).not.toMatch(SQL);
    expect(inspect(failed, { depth: 6 })).not.toContain(SENTINEL);

    const refusal = new APIError("FORBIDDEN", { code: "SOME_REFUSAL" });
    const passed = await runWithTransaction(ctx.adapter, async () => {
      throw refusal;
    }).then(
      () => null,
      (e: unknown) => e,
    );
    expect(passed).toBe(refusal);
  });
});

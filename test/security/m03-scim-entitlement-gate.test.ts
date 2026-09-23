// M-03 — `/scim/v2/*` was entirely outside the entitlement gate.
//
// Audit repro: after dropping an org to **zero** entitled features, an
// existing SCIM bearer still created (201) and listed (200) Groups — and
// therefore still drove the C-03 role recompute. The same held for
// upstream's `/scim/v2/Users`. A token minted while entitled outlived the
// downgrade indefinitely.

import { describe, expect, it } from "vitest";
import { makeAuth, signUpOwner, createOrg } from "../helpers/auth";
import type { Feature } from "../../src/server/types";
import { mintScimToken } from "./helpers";

/** Entitlements the test can flip at runtime, so a token can be minted *then* revoked by plan. */
function mutableEntitlements() {
  const state = { features: new Set<Feature>(["sso", "scim", "audit_log", "teams", "api_keys"]) };
  return {
    state,
    resolveEntitlements: async () => state.features,
  };
}

describe("M-03 — SCIM v2 is gated on the token org's `scim` entitlement", () => {
  it("Groups and Users both 403 once the org has zero entitlements", async () => {
    const { state, resolveEntitlements } = mutableEntitlements();
    const t = await makeAuth({ resolveEntitlements });
    const { cookie } = await signUpOwner(t);
    const { orgId } = await createOrg(t, cookie);
    const bearer = await mintScimToken(t, cookie, orgId);

    // Entitled: the bearer works.
    expect((await t.api.get("/scim/v2/Groups", bearer)).status).toBe(200);

    state.features = new Set<Feature>(); // plan downgrade

    const groups = await t.api.get("/scim/v2/Groups", bearer);
    expect(groups.status).toBe(403);
    const groupsBody = (await groups.json()) as { schemas?: string[]; code?: string };
    expect(groupsBody.schemas).toEqual(["urn:ietf:params:scim:api:messages:2.0:Error"]);
    expect(groups.status).toBe(403);

    const create = await t.api.post(
      "/scim/v2/Groups",
      { schemas: ["urn:ietf:params:scim:schemas:core:2.0:Group"], displayName: "Engineers" },
      bearer,
    );
    expect(create.status).toBe(403);

    const users = await t.api.get("/scim/v2/Users", bearer);
    expect(users.status).toBe(403);

    const createUser = await t.api.post(
      "/scim/v2/Users",
      {
        schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"],
        userName: "x@acme.test",
        emails: [{ value: "x@acme.test", primary: true }],
      },
      bearer,
    );
    expect(createUser.status).toBe(403);
  });

  it("an unauthenticated SCIM call still gets the endpoint's own 401, not the gate's 403", async () => {
    const t = await makeAuth({ resolveEntitlements: async () => [] });
    const res = await t.api.get("/scim/v2/Groups", { authorization: "Bearer nonsense" });
    expect(res.status).toBe(401);
  });
});

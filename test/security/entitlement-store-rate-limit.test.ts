// The staff entitlement write is rate limited (20 per minute per client, the
// plugin's own rule — `ENTITLEMENT_SET_RATE_LIMIT`). Its own file: the limiter's
// store is shared by every test of a file, so a count must start from zero.

import { describe, expect, it } from "vitest";
import { createOrg, makeAuth, signUpOwner } from "../helpers/auth";

describe("POST /enterprise/entitlements/set rate limit", () => {
  it("answers 429 once a client exceeds 20 writes in the window", async () => {
    const t = await makeAuth({
      resolveEntitlements: undefined,
      entitlements: { store: "table" },
    });
    const staff = await signUpOwner(t, "staff@platform.test");
    await t.client.execute({
      sql: `UPDATE user SET role = 'admin' WHERE id = ?`,
      args: [staff.userId],
    });
    const owner = await signUpOwner(t);
    const { orgId } = await createOrg(t, owner.cookie);

    const statuses: number[] = [];
    for (let i = 0; i < 25; i++) {
      const res = await t.api.post(
        "/enterprise/entitlements/set",
        { orgId, features: ["sso"] },
        { cookie: staff.cookie, "x-forwarded-for": "198.51.100.77" },
      );
      statuses.push(res.status);
    }

    expect(statuses.filter((status) => status === 200)).toHaveLength(20);
    expect(statuses.slice(20).every((status) => status === 429)).toBe(true);
  });
});

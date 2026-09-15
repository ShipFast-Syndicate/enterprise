// M-04 — ReDoS in `parseFilter` (quadratic on trailing whitespace).
//
// Audit repro: `GET /scim/v2/Groups?filter=displayName eq <64 000 spaces>x y`
// blocked the event loop for **7 597 ms** on one request (8 k → 125 ms,
// 32 k → 2 337 ms, 64 k → 7 597 ms) — a valid SCIM bearer, i.e. a rogue or
// compromised IdP connector, was the only precondition. The parser is a
// hand-written linear tokenizer now, behind a 512-character cap.

import { describe, expect, it } from "vitest";
import {
  applyGroupPatch,
  MAX_FILTER_LENGTH,
  parseFilter,
  parseMembersFilterPath,
  ScimHttpError,
} from "../../src/server/scim-groups/scim";

const PATHOLOGICAL = `displayName eq ${" ".repeat(64_000)}x y`;

describe("M-04 — SCIM filter parsing is linear and length-capped", () => {
  it("the audit's pathological 64k-space input returns in well under 50 ms", () => {
    const started = performance.now();
    expect(() => parseFilter(PATHOLOGICAL)).toThrow(ScimHttpError);
    const elapsed = performance.now() - started;
    expect(elapsed).toBeLessThan(50);
  });

  it("rejects an over-long filter with 400 invalidFilter rather than parsing it", () => {
    let thrown: unknown;
    try {
      parseFilter(`displayName eq "${"a".repeat(MAX_FILTER_LENGTH)}"`);
    } catch (err) {
      thrown = err;
    }
    expect(thrown).toBeInstanceOf(ScimHttpError);
    expect((thrown as ScimHttpError).status).toBe(400);
    expect((thrown as ScimHttpError).scimType).toBe("invalidFilter");
  });

  it("still parses every supported filter exactly as before", () => {
    expect(parseFilter(undefined)).toBeNull();
    expect(parseFilter('displayName eq "Engineers"')).toEqual({
      attr: "displayName",
      op: "eq",
      value: "Engineers",
    });
    expect(parseFilter("  id   eq   team_1  ")).toEqual({ attr: "id", op: "eq", value: "team_1" });
    expect(parseFilter('externalId EQ "grp\\"quoted"')).toEqual({
      attr: "externalId",
      op: "eq",
      value: 'grp"quoted',
    });
    expect(() => parseFilter('displayName co "Eng"')).toThrow(/Unsupported SCIM filter operator/);
    expect(() => parseFilter('nope eq "x"')).toThrow(/Unsupported SCIM filter attribute/);
    expect(() => parseFilter("displayName")).toThrow(/Invalid SCIM filter expression/);
    expect(() => parseFilter('displayName eq "unterminated')).toThrow(
      /Invalid SCIM filter expression/,
    );
  });

  it("the PATCH member-filter path parser is linear and still correct", () => {
    const hostile = `members[${" ".repeat(64_000)}value eq "x"]`;
    const started = performance.now();
    expect(parseMembersFilterPath(hostile)).toBeNull(); // over the cap
    expect(performance.now() - started).toBeLessThan(50);

    expect(parseMembersFilterPath('members[value eq "u1"]')).toBe("u1");
    expect(parseMembersFilterPath('members[ value  eq  "u2" ]')).toBe("u2");
    expect(parseMembersFilterPath('members[value eq "a\\"b"]')).toBe('a"b');
    expect(parseMembersFilterPath("members[value eq u1]")).toBeNull();
    expect(parseMembersFilterPath("displayName")).toBeNull();

    // And the behaviour that path drives is unchanged.
    expect(
      applyGroupPatch({ displayName: "G", members: ["u1", "u2"] }, [
        { op: "remove", path: 'members[value eq "u1"]' },
      ]),
    ).toEqual({ displayName: "G", members: ["u2"] });
  });
});

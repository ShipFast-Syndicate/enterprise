import { describe, expect, it } from "vitest";
import {
  applyGroupPatch,
  buildGroupResource,
  effectiveRole,
  locationFor,
  parseFilter,
  scimError,
  scimJson,
  ScimHttpError,
  type PatchOp,
} from "../../src/server/scim-groups/scim";

describe("parseFilter", () => {
  it("returns null when no filter is given (list-everything)", () => {
    expect(parseFilter(undefined)).toBeNull();
  });

  it('parses displayName eq "x"', () => {
    expect(parseFilter('displayName eq "Engineering"')).toEqual({
      attr: "displayName",
      op: "eq",
      value: "Engineering",
    });
  });

  it('parses externalId eq "y"', () => {
    expect(parseFilter('externalId eq "ext-42"')).toEqual({
      attr: "externalId",
      op: "eq",
      value: "ext-42",
    });
  });

  it('parses id eq "z"', () => {
    expect(parseFilter('id eq "team_abc123"')).toEqual({
      attr: "id",
      op: "eq",
      value: "team_abc123",
    });
  });

  it("is case-insensitive on the eq operator", () => {
    expect(parseFilter('displayName EQ "Engineering"')).toEqual({
      attr: "displayName",
      op: "eq",
      value: "Engineering",
    });
  });

  it('unescapes \\" and \\\\ inside a quoted value', () => {
    expect(parseFilter('displayName eq "Bob\\"s \\\\ Team"')).toEqual({
      attr: "displayName",
      op: "eq",
      value: 'Bob"s \\ Team',
    });
  });

  it("rejects the co operator with a SCIM 400 invalidFilter error", () => {
    expect(() => parseFilter('displayName co "Eng"')).toThrow(ScimHttpError);
    try {
      parseFilter('displayName co "Eng"');
      expect.unreachable();
    } catch (err) {
      expect(err).toBeInstanceOf(ScimHttpError);
      expect((err as ScimHttpError).status).toBe(400);
      expect((err as ScimHttpError).scimType).toBe("invalidFilter");
    }
  });

  it("rejects an unsupported attribute", () => {
    expect(() => parseFilter('userName eq "bob"')).toThrow(ScimHttpError);
  });

  it("rejects a filter that doesn't parse at all", () => {
    expect(() => parseFilter("not a filter")).toThrow(ScimHttpError);
  });
});

describe("applyGroupPatch", () => {
  const base = { displayName: "Engineering", members: ["u1", "u2"] };

  it("replaces displayName", () => {
    const ops: PatchOp[] = [{ op: "replace", path: "displayName", value: "Eng Team" }];
    expect(applyGroupPatch(base, ops)).toEqual({ displayName: "Eng Team", members: ["u1", "u2"] });
  });

  it("adds a member via the members path, ignoring duplicates already present", () => {
    const ops: PatchOp[] = [
      { op: "add", path: "members", value: [{ value: "u2" }, { value: "u3" }] },
    ];
    expect(applyGroupPatch(base, ops)).toEqual({
      displayName: "Engineering",
      members: ["u1", "u2", "u3"],
    });
  });

  it("adding the same member twice across ops does not duplicate it", () => {
    const ops: PatchOp[] = [
      { op: "add", path: "members", value: [{ value: "u3" }] },
      { op: "add", path: "members", value: [{ value: "u3" }] },
    ];
    expect(applyGroupPatch(base, ops).members).toEqual(["u1", "u2", "u3"]);
  });

  it("replaces the whole members set via the members path", () => {
    const ops: PatchOp[] = [{ op: "replace", path: "members", value: [{ value: "u9" }] }];
    expect(applyGroupPatch(base, ops).members).toEqual(["u9"]);
  });

  it("clears all members via remove on the bare members path", () => {
    const ops: PatchOp[] = [{ op: "remove", path: "members" }];
    expect(applyGroupPatch(base, ops).members).toEqual([]);
  });

  it('removes one member via members[value eq "u1"]', () => {
    const ops: PatchOp[] = [{ op: "remove", path: 'members[value eq "u1"]' }];
    expect(applyGroupPatch(base, ops).members).toEqual(["u2"]);
  });

  it('adds one member via members[value eq "u3"]', () => {
    const ops: PatchOp[] = [{ op: "add", path: 'members[value eq "u3"]' }];
    expect(applyGroupPatch(base, ops).members).toEqual(["u1", "u2", "u3"]);
  });

  it('is case-insensitive on op names (Entra sends "Add")', () => {
    const ops = [{ op: "Add", path: "members", value: [{ value: "u3" }] }] as unknown as PatchOp[];
    expect(applyGroupPatch(base, ops).members).toEqual(["u1", "u2", "u3"]);
  });

  it("throws ScimHttpError(400, invalidPath) for an unsupported path", () => {
    const ops: PatchOp[] = [{ op: "replace", path: "externalId", value: "x" }];
    expect(() => applyGroupPatch(base, ops)).toThrow(ScimHttpError);
    try {
      applyGroupPatch(base, ops);
      expect.unreachable();
    } catch (err) {
      expect(err).toBeInstanceOf(ScimHttpError);
      expect((err as ScimHttpError).status).toBe(400);
      expect((err as ScimHttpError).scimType).toBe("invalidPath");
    }
  });
});

describe("effectiveRole", () => {
  it("returns member when no group maps to a role", () => {
    expect(effectiveRole(["Engineering"], {})).toBe("member");
  });

  it("returns member for an empty group list", () => {
    expect(effectiveRole([], { Admins: "admin" })).toBe("member");
  });

  it("returns the mapped role for a single matching group", () => {
    expect(effectiveRole(["Admins"], { Admins: "admin" })).toBe("admin");
  });

  it("the highest-ranked role wins across multiple matching groups", () => {
    expect(
      effectiveRole(["Admins", "Owners", "Engineering"], { Admins: "admin", Owners: "owner" }),
    ).toBe("owner");
    expect(effectiveRole(["Engineering", "Admins"], { Admins: "admin" })).toBe("admin");
  });
});

describe("scimError", () => {
  it("builds a SCIM-shaped error body with application/scim+json content-type", async () => {
    const res = scimError(400, "invalidFilter", "bad filter");
    expect(res.status).toBe(400);
    expect(res.headers.get("content-type")).toBe("application/scim+json");
    const body = (await res.json()) as Record<string, unknown>;
    expect(body).toEqual({
      schemas: ["urn:ietf:params:scim:api:messages:2.0:Error"],
      status: "400",
      detail: "bad filter",
      scimType: "invalidFilter",
    });
  });

  it("omits scimType when not given", async () => {
    const res = scimError(401, undefined, "nope");
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.scimType).toBeUndefined();
    expect(body).toEqual({
      schemas: ["urn:ietf:params:scim:api:messages:2.0:Error"],
      status: "401",
      detail: "nope",
    });
  });
});

describe("scimJson", () => {
  it("uses application/scim+json regardless of extra headers", async () => {
    const res = scimJson(201, { ok: true }, { location: "http://x/y" });
    expect(res.status).toBe(201);
    expect(res.headers.get("content-type")).toBe("application/scim+json");
    expect(res.headers.get("location")).toBe("http://x/y");
    expect(await res.json()).toEqual({ ok: true });
  });

  it("supports a null body (204)", async () => {
    const res = scimJson(204, null);
    expect(res.status).toBe(204);
    expect(await res.text()).toBe("");
  });
});

describe("buildGroupResource / locationFor", () => {
  it("carries schemas and an absolute meta.location built from baseURL", () => {
    const location = locationFor("http://localhost:3000/api/auth", "team_1");
    expect(location).toBe("http://localhost:3000/api/auth/scim/v2/Groups/team_1");

    const resource = buildGroupResource({
      id: "team_1",
      externalId: "ext-1",
      displayName: "Engineering",
      members: [{ value: "u1", display: "u1@acme.test" }],
      createdAt: new Date("2026-01-01T00:00:00.000Z"),
      updatedAt: new Date("2026-01-02T00:00:00.000Z"),
      location,
    });

    expect(resource.schemas).toEqual(["urn:ietf:params:scim:schemas:core:2.0:Group"]);
    expect(resource.id).toBe("team_1");
    expect(resource.externalId).toBe("ext-1");
    expect(resource.displayName).toBe("Engineering");
    expect(resource.members).toEqual([{ value: "u1", display: "u1@acme.test" }]);
    expect(resource.meta).toEqual({
      resourceType: "Group",
      created: "2026-01-01T00:00:00.000Z",
      lastModified: "2026-01-02T00:00:00.000Z",
      location: "http://localhost:3000/api/auth/scim/v2/Groups/team_1",
    });
  });

  it("omits externalId when not given", () => {
    const resource = buildGroupResource({
      id: "team_1",
      displayName: "Engineering",
      members: [],
      createdAt: new Date(),
      updatedAt: new Date(),
      location: "http://x/scim/v2/Groups/team_1",
    });
    expect(resource.externalId).toBeUndefined();
  });
});

// Only an error that carries a statement is redacted.
//
// `withDatabaseErrorRedaction` (`src/server/db-errors.ts`) replaces an error
// that carries a query — a `query`, `sql` or `params` property, or drizzle's
// "Failed query" message, anywhere in its `cause` chain — with a
// `DatabaseQueryError` that has no statement and no values. Every other
// error keeps its own message: better-auth's adapter raises errors that name
// SQL words but no statement ("incrementOne resolved to an empty update:
// every increment/set field …"), and those are the operator's only
// diagnostic.
//
// Against the parent commit a general SQL-keyword pattern matched those
// messages too, and they reached the logs as a generic
// "Database query failed (user.incrementOne)".

import { inspect } from "node:util";
import { describe, expect, it } from "vitest";
import { makeAuth, signUpOwner } from "../helpers/auth";
import { carriesQuery, redactDatabaseError } from "../../src/server/db-errors";

const SENTINEL = "zz-db-errors-sentinel";

describe("adapter errors without a statement keep their message", () => {
  it("better-auth's empty incrementOne error passes through the adapter unchanged", async () => {
    const t = await makeAuth();
    const { userId } = await signUpOwner(t, "owner@acme.test");
    const ctx = await t.auth.$context;
    const adapter = ctx.adapter as unknown as {
      incrementOne: (input: unknown) => Promise<unknown>;
    };
    const error = await adapter
      .incrementOne({
        // `member` has no field that is set on every update, so a `set` of
        // unknown keys resolves to nothing.
        model: "member",
        where: [{ field: "userId", value: userId }],
        increment: {},
        set: { [`not_a_field_${SENTINEL}`]: 1 },
      })
      .then(
        () => null,
        (e: unknown) => e,
      );
    expect(error).toBeInstanceOf(Error);
    expect((error as Error).name).not.toBe("DatabaseQueryError");
    expect((error as Error).message).toContain("incrementOne resolved to an empty update");
  });

  for (const message of [
    "incrementOne resolved to an empty update: every increment/set field was unknown to the schema or transformed away.",
    "Could not update the row: select a different key from the set where it is unique",
    'relation "member" does not exist',
  ]) {
    it(`kept as it is: ${message.slice(0, 48)}…`, () => {
      const error = new Error(message);
      expect(carriesQuery(error)).toBe(false);
      expect(redactDatabaseError(error, { model: "user", method: "update" })).toBe(error);
    });
  }
});

describe("errors that carry a statement are still redacted", () => {
  const cases: [string, () => Error][] = [
    [
      "a drizzle 'Failed query' message with no properties",
      () =>
        new Error(`Failed query: select "id" from "user" where "email" = ?\nparams: ${SENTINEL}`),
    ],
    [
      "a query property",
      () => Object.assign(new Error("boom"), { query: `select 1 -- ${SENTINEL}` }),
    ],
    ["a params property", () => Object.assign(new Error("boom"), { params: [SENTINEL] })],
    [
      "a statement on the cause",
      () =>
        new Error("wrapped", {
          cause: Object.assign(new Error("inner"), { sql: `insert into x values ('${SENTINEL}')` }),
        }),
    ],
  ];
  for (const [label, make] of cases) {
    it(label, () => {
      const redacted = redactDatabaseError(make(), { model: "user", method: "findOne" });
      expect((redacted as Error).name).toBe("DatabaseQueryError");
      expect(inspect(redacted, { depth: 6 })).not.toContain(SENTINEL);
    });
  }
});

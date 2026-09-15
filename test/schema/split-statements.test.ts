// Review round 1, finding 1 — `splitStatements` (`src/schema/migrate.ts`) is
// a character scanner (code / line-comment / block-comment / string
// states), not regex-and-split, specifically so it isn't fooled by a `;`
// that's really inside a comment or a string literal. Each case here is a
// concrete way a future `NNNN_*.sql` migration could break the old
// naive-split approach (and did break it once already — see the task-3
// report's "Two things I fixed beyond the brief's literal file list": a `;`
// in this file's own prose comment caused a comment-only fragment to reach
// `client.execute()` and throw a spurious libsql error).
import { describe, expect, it } from "vitest";
import { splitStatements } from "../../src/schema/migrate";

describe("splitStatements", () => {
  it("does not split on a ; inside a trailing line comment", () => {
    expect(splitStatements("SELECT 1 -- has ; in it\n;")).toEqual(["SELECT 1"]);
  });

  it("does not split on a ; inside a block comment, and drops the comment", () => {
    expect(splitStatements("CREATE TABLE t (a INT /* comment ; still comment */, b INT);")).toEqual(
      ["CREATE TABLE t (a INT , b INT)"],
    );
  });

  it("does not split on a ; inside a single-quoted string literal", () => {
    expect(splitStatements("CREATE TABLE t (a TEXT DEFAULT 'a;b');")).toEqual([
      "CREATE TABLE t (a TEXT DEFAULT 'a;b')",
    ]);
  });

  it("keeps a ; inside a string past an escaped '' quote", () => {
    expect(splitStatements("INSERT INTO t (a) VALUES ('it''s; fine');")).toEqual([
      "INSERT INTO t (a) VALUES ('it''s; fine')",
    ]);
  });

  it("drops empty trailing fragments (bare/whitespace-only ; runs)", () => {
    expect(splitStatements("SELECT 1;   ;\n\n  ;")).toEqual(["SELECT 1"]);
  });

  it("splits multiple real statements", () => {
    expect(splitStatements("CREATE TABLE a (id TEXT);\nCREATE TABLE b (id TEXT);")).toEqual([
      "CREATE TABLE a (id TEXT)",
      "CREATE TABLE b (id TEXT)",
    ]);
  });

  it("returns an empty array for a comment-only / empty input", () => {
    expect(splitStatements("-- just a comment\n/* and a block one */\n")).toEqual([]);
    expect(splitStatements("")).toEqual([]);
  });
});

// The Low findings fixed in the pre-publish pass (the rest are listed as
// deferred in `docs/security.md`).
//
// L-02 the per-org audit mutex `Map` never evicted, growing one permanent
//      entry per distinct org the process ever audited.
// L-03 unique-constraint detection matched on the error *message* only, so a
//      differently-worded or localised driver error turned a benign `seq`
//      race into a hard failure.
// L-05 `content-disposition` interpolated `orgId` unsanitised (covered in
//      `m02-csv-injection.test.ts`).
// L-06 the CLI accepted secrets as `--token`, visible in `ps` and history.
// L-08 `secretsKey`'s documented ">= 32 chars" rule was never enforced
//      (covered in `c04-secrets-at-rest.test.ts`).

import { describe, expect, it } from "vitest";
import { spawnSync } from "node:child_process";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { existsSync } from "node:fs";
import { isUniqueViolation, pendingOrgLockCount, writeAudit } from "../../src/server/audit/chain";
import { makeAuth, signUpOwner, createOrg } from "../helpers/auth";

const repoRoot = fileURLToPath(new URL("../..", import.meta.url));

describe("L-02 — the per-org audit lock map does not grow without bound", () => {
  it("evicts an org's lock once its chain settles", async () => {
    const t = await makeAuth();
    const { cookie } = await signUpOwner(t);
    const { orgId } = await createOrg(t, cookie);
    const ctx = await t.auth.$context;

    await Promise.all(
      Array.from({ length: 5 }, (_, i) =>
        writeAudit(
          // The test only needs the adapter off the live context; the
          // `$context` type is parameterised by the concrete options object,
          // which doesn't structurally match the generic `AuthContext`.
          { context: ctx } as unknown as Parameters<typeof writeAudit>[0],
          {
            orgId: `${orgId}-${i}`,
            actorType: "system",
            action: "test.event",
            targetType: "organization",
          },
        ),
      ),
    );
    // One microtask turn for the eviction callbacks to run.
    await new Promise((resolve) => setTimeout(resolve, 0));

    expect(pendingOrgLockCount()).toBe(0);
  });
});

describe("L-03 — unique-violation detection is code-based, not message-only", () => {
  it("recognises driver codes, and keeps the message fallback", () => {
    expect(
      isUniqueViolation(Object.assign(new Error("boom"), { code: "SQLITE_CONSTRAINT_UNIQUE" })),
    ).toBe(true);
    expect(isUniqueViolation(Object.assign(new Error("duplicate key"), { code: "23505" }))).toBe(
      true,
    );
    expect(isUniqueViolation(new Error("UNIQUE constraint failed: audit_event.seq"))).toBe(true);
    expect(isUniqueViolation(new Error("connection reset"))).toBe(false);
  });
});

describe("L-06 — the CLI warns when a token is passed in argv", () => {
  it("prints a warning naming TURSO_AUTH_TOKEN", () => {
    const cliPath = join(repoRoot, "dist", "cli", "index.js");
    if (!existsSync(cliPath)) return; // `test/cli/cli.test.ts` owns building dist/
    const result = spawnSync(
      process.execPath,
      [cliPath, "verify", "--url", "file:/dev/null/nope", "--token", "sekrit"],
      { encoding: "utf8" },
    );
    expect(result.stderr).toContain("--token is visible");
    expect(result.stderr).toContain("TURSO_AUTH_TOKEN");
    expect(result.stderr).not.toContain("sekrit");
  });
});

// GHSA-8p84-pc7q-69jr — audit gap 2, round 3: the requirement's onset and the
// timestamps it is compared in.
//
// A session stands under `require2fa` for a user who cannot enrol only when it
// was created strictly after the requirement's onset for that user (the latest
// of the requiring orgs' `org_policy.updated_at` and the user's membership in
// them). The columns involved are kept in different units by different
// products, and the 0003 data migration moves the onset of every requiring org
// to the upgrade. These are the pure pieces; the behaviour end to end is in
// `gap2-require2fa-standing.test.ts`.
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { createClient, type Client } from "@libsql/client";
import { applyMigration } from "../../src/schema";
import { twoFactorStanding } from "../../src/server/policy/enforcement";
import { timestampMs } from "../../src/server/policy/store";

describe("timestampMs — one clock for every unit a product keeps", () => {
  it("reads Dates, seconds, milliseconds, numeric strings and ISO strings as epoch milliseconds", () => {
    const ms = Date.UTC(2026, 8, 26, 12, 0, 0, 250);
    expect(timestampMs(new Date(ms))).toBe(ms);
    expect(timestampMs(ms)).toBe(ms);
    expect(timestampMs(Math.floor(ms / 1000))).toBe(Math.floor(ms / 1000) * 1000);
    expect(timestampMs(String(ms))).toBe(ms);
    expect(timestampMs(String(Math.floor(ms / 1000)))).toBe(Math.floor(ms / 1000) * 1000);
    expect(timestampMs(new Date(ms).toISOString())).toBe(ms);
    expect(timestampMs(BigInt(ms))).toBe(ms);
  });

  it("answers null for what it cannot read", () => {
    for (const value of [
      null,
      undefined,
      "",
      "not a date",
      Number.NaN,
      Infinity,
      {},
      new Date("x"),
    ]) {
      expect(timestampMs(value), String(value)).toBeNull();
    }
  });
});

describe("twoFactorStanding — judged means created strictly after the onset", () => {
  const noCredential = { twoFactorEnabled: false, canEnroll: false, enrollmentPending: false };
  const onset = Date.UTC(2026, 8, 26, 12, 0, 0, 500);

  it("a no-password session stands only when created after the onset, in any unit", () => {
    expect(twoFactorStanding({ createdAt: new Date(onset + 1) }, noCredential, onset)).toBe("ok");
    expect(twoFactorStanding({ createdAt: new Date(onset) }, noCredential, onset)).toBe(
      "two-factor-required",
    );
    expect(twoFactorStanding({ createdAt: onset - 1 }, noCredential, onset)).toBe(
      "two-factor-required",
    );
    // A seconds value is the start of its second: 12:00:00 is not after 12:00:00.500.
    expect(twoFactorStanding({ createdAt: Math.floor(onset / 1000) }, noCredential, onset)).toBe(
      "two-factor-required",
    );
    expect(
      twoFactorStanding({ createdAt: Math.floor(onset / 1000) + 1 }, noCredential, onset),
    ).toBe("ok");
    // No readable creation time, or an unknown onset, never stands.
    expect(twoFactorStanding({}, noCredential, onset)).toBe("two-factor-required");
    expect(twoFactorStanding({ createdAt: "garbage" }, noCredential, onset)).toBe(
      "two-factor-required",
    );
    expect(twoFactorStanding({ createdAt: new Date() }, noCredential, Infinity)).toBe(
      "two-factor-required",
    );
  });

  it("an impersonation session is never taken as judged for the impersonated user", () => {
    expect(
      twoFactorStanding(
        { createdAt: new Date(onset + 60_000), impersonatedBy: "admin-1" },
        noCredential,
        onset,
      ),
    ).toBe("two-factor-required");
  });

  it("enrolment settles it first; a password holder who has not enrolled is confined whenever the session was minted", () => {
    const enrolled = { twoFactorEnabled: true, canEnroll: false, enrollmentPending: false };
    const pending = { twoFactorEnabled: false, canEnroll: true, enrollmentPending: true };
    expect(twoFactorStanding({ impersonatedBy: "a" }, enrolled, Infinity)).toBe("ok");
    expect(twoFactorStanding({ createdAt: new Date(onset + 1) }, pending, onset)).toBe(
      "enrollment-required",
    );
    expect(twoFactorStanding({ createdAt: new Date(onset - 1) }, pending, onset)).toBe(
      "enrollment-required",
    );
  });
});

describe("migration 0003 — data only: moves the onset of every requiring org to the upgrade, in the column's own unit", () => {
  const directories: string[] = [];
  const clients: Client[] = [];
  afterEach(() => {
    for (const client of clients.splice(0)) client.close();
    for (const directory of directories.splice(0))
      rmSync(directory, { recursive: true, force: true });
  });

  async function freshDb(): Promise<Client> {
    const directory = mkdtempSync(join(tmpdir(), "enterprise-0003-"));
    directories.push(directory);
    const client = createClient({ url: `file:${join(directory, "db.sqlite")}` });
    clients.push(client);
    await client.batch(
      [
        `CREATE TABLE user (id TEXT PRIMARY KEY)`,
        `CREATE TABLE organization (id TEXT PRIMARY KEY)`,
        `CREATE TABLE session (id TEXT PRIMARY KEY, created_at INTEGER)`,
      ],
      "write",
    );
    return client;
  }

  it("rewrites updated_at of require_2fa rows only — seconds stay seconds, milliseconds stay milliseconds, ISO stays ISO — and changes no schema", async () => {
    const client = await freshDb();
    await applyMigration(client); // install: 0001..0003 on an empty org_policy
    const schemaBefore = await client.execute(
      `SELECT name, sql FROM sqlite_master WHERE type IN ('table', 'index') ORDER BY name`,
    );

    const longAgoMs = Date.UTC(2025, 0, 1);
    const insert = (orgId: string, require2fa: number, updatedAt: number | string) =>
      client.execute({
        sql: `INSERT INTO org_policy (org_id, id, require_2fa, sso_enforced, allowed_methods, group_role_map, updated_at) VALUES (?, ?, ?, 0, '[]', '{}', ?)`,
        args: [orgId, orgId, require2fa, updatedAt],
      });
    await insert("org-ms", 1, longAgoMs);
    await insert("org-s", 1, Math.floor(longAgoMs / 1000));
    await insert("org-iso", 1, new Date(longAgoMs).toISOString());
    await insert("org-off", 0, longAgoMs);

    const before = Date.now();
    await applyMigration(client); // the upgrade
    const after = Date.now();

    const rows = await client.execute(
      `SELECT org_id, updated_at, typeof(updated_at) AS t FROM org_policy ORDER BY org_id`,
    );
    const byOrg = new Map(rows.rows.map((row) => [String(row.org_id), row]));

    const ms = byOrg.get("org-ms")!;
    expect(ms.t).toBe("integer");
    expect(Number(ms.updated_at)).toBeGreaterThan(before);
    expect(Number(ms.updated_at)).toBeLessThanOrEqual(after + 2);

    const s = byOrg.get("org-s")!;
    expect(s.t).toBe("integer");
    expect(Number(s.updated_at)).toBeLessThan(100_000_000_000);
    // Rounded up to the next second: no session of the second it ran in reads as later.
    expect(Number(s.updated_at) * 1000).toBeGreaterThan(before);
    expect(Number(s.updated_at)).toBeLessThanOrEqual(Math.floor(after / 1000) + 1);

    const iso = byOrg.get("org-iso")!;
    expect(iso.t).toBe("text");
    expect(Date.parse(String(iso.updated_at))).toBeGreaterThan(before - 1);
    expect(Date.parse(String(iso.updated_at))).toBeLessThanOrEqual(after + 2);

    expect(Number(byOrg.get("org-off")!.updated_at)).toBe(longAgoMs);

    const schemaAfter = await client.execute(
      `SELECT name, sql FROM sqlite_master WHERE type IN ('table', 'index') ORDER BY name`,
    );
    expect(schemaAfter.rows).toEqual(schemaBefore.rows);
    const sessionColumns = await client.execute(`PRAGMA table_info("session")`);
    expect(sessionColumns.rows.map((row) => String(row.name))).toEqual(["id", "created_at"]);
  });
});

// Alpha Bros enterprise layer — the dialect-independent half of
// `ab-enterprise audit-verify`: turning a stored `audit_event` row into an
// `AuditRow`, parsing `--expect-head`, and checking a chain read from any
// database. `./index.ts` (SQLite/libSQL) and `./pg.ts` (Postgres) only differ
// in how they read the rows.
import {
  RETENTION_COMPACTED_ACTION,
  RETENTION_COMPACTING_ACTION,
  verifyChain,
  verifyChainHeadSignature,
  type AuditRow,
} from "../server/audit/chain";

const nullableString = (value: unknown): string | null =>
  value === null || value === undefined ? null : String(value);

/**
 * `audit_event.metadata` as the driver hands it back: JSON text from SQLite
 * (a `TEXT` column), but an already-parsed object from Postgres, whose `json`
 * column `pg` / PGlite decode themselves. Both end up as the object the writer
 * hashed (`canonical()` stringifies it again).
 */
function metadataOf(value: unknown): Record<string, unknown> {
  if (value === null || value === undefined) return {};
  if (typeof value === "string") return JSON.parse(value || "{}") as Record<string, unknown>;
  return value as Record<string, unknown>;
}

/**
 * `audit_event.created_at` as epoch milliseconds: a number (or bigint, or
 * numeric text) from SQLite's integer column, a `Date` from Postgres'
 * `timestamptz`, or an ISO string where a driver left it as text.
 */
export function epochMs(value: unknown): number {
  if (value instanceof Date) return value.getTime();
  if (typeof value === "number") return value;
  if (typeof value === "bigint") return Number(value);
  const text = String(value);
  if (/^-?\d+$/.test(text)) return Number(text);
  const parsed = Date.parse(text);
  if (Number.isNaN(parsed)) throw new Error(`audit_event.created_at is not a timestamp: ${text}`);
  return parsed;
}

/** One `audit_event` row (snake_case column names, as selected) as an `AuditRow`. */
export function toAuditRow(row: Record<string, unknown>): AuditRow {
  return {
    id: String(row.id),
    orgId: String(row.org_id),
    seq: Number(row.seq),
    actorType: String(row.actor_type),
    actorId: nullableString(row.actor_id),
    action: String(row.action),
    targetType: String(row.target_type),
    targetId: nullableString(row.target_id),
    ip: nullableString(row.ip),
    userAgent: nullableString(row.user_agent),
    metadata: metadataOf(row.metadata),
    createdAt: epochMs(row.created_at),
    prevHash: String(row.prev_hash),
    hash: String(row.hash),
  };
}

/** The query `audit-verify` runs on SQLite/libSQL (`?` placeholder): one org's chain, seq-ascending. */
export const AUDIT_ROWS_SQL_SQLITE =
  "SELECT id, org_id, seq, actor_type, actor_id, action, target_type, target_id, ip, user_agent, metadata, created_at, prev_hash, hash FROM audit_event WHERE org_id = ? ORDER BY seq ASC";

/** The same query on Postgres (`$1` placeholder). */
export const AUDIT_ROWS_SQL_PG =
  "SELECT id, org_id, seq, actor_type, actor_id, action, target_type, target_id, ip, user_agent, metadata, created_at, prev_hash, hash FROM audit_event WHERE org_id = $1 ORDER BY seq ASC";

export interface ExpectedHead {
  seq: number;
  hash: string;
  orgId?: string;
  signature?: string | null;
}

/**
 * `--expect-head` accepts `<seq>:<hash>` or the JSON `GET
 * /enterprise/audit/head` answered (`{ head: { orgId, seq, hash }, signature }`,
 * or just its `head` object with an optional `signature`).
 */
export function parseExpectedHead(raw: string): ExpectedHead | null {
  const trimmed = raw.trim();
  if (trimmed.startsWith("{")) {
    try {
      const parsed = JSON.parse(trimmed) as {
        head?: { orgId?: unknown; seq?: unknown; hash?: unknown } | null;
        orgId?: unknown;
        seq?: unknown;
        hash?: unknown;
        signature?: unknown;
      };
      const head = parsed.head ?? parsed;
      if (typeof head.seq !== "number" || typeof head.hash !== "string") return null;
      return {
        seq: head.seq,
        hash: head.hash,
        orgId: typeof head.orgId === "string" ? head.orgId : undefined,
        signature: typeof parsed.signature === "string" ? parsed.signature : null,
      };
    } catch {
      return null;
    }
  }
  const match = /^(-?\d+):(\S+)$/.exec(trimmed);
  if (!match) return null;
  return { seq: Number(match[1]), hash: match[2]! };
}

/** What a CLI command prints and exits with. `message` goes to stdout, or stderr when `usage`. */
export interface AuditVerifyOutcome {
  code: 0 | 1;
  message: string;
  usage?: boolean;
}

/**
 * Parses `--expect-head` and checks it against `org` and (when signed) the
 * chain key — everything that can be refused before the database is read.
 * `expected` is `null` when no head was asked for.
 */
export async function prepareExpectedHead(
  raw: string | undefined,
  org: string,
  chainKey: string | undefined,
): Promise<
  { expected: ExpectedHead | null; failure?: undefined } | { failure: AuditVerifyOutcome }
> {
  if (raw === undefined) return { expected: null };
  const expected = parseExpectedHead(raw);
  if (!expected) {
    return {
      failure: {
        code: 1,
        usage: true,
        message:
          "ab-enterprise audit-verify: --expect-head takes <seq>:<hash> or the JSON GET /enterprise/audit/head returned",
      },
    };
  }
  if (expected.orgId !== undefined && expected.orgId !== org) {
    return {
      failure: {
        code: 1,
        message: `audit-verify: expected head belongs to org ${expected.orgId}, not ${org}`,
      },
    };
  }
  if (expected.signature) {
    if (!chainKey) {
      return {
        failure: {
          code: 1,
          message:
            "audit-verify: the expected head is signed; set AB_AUDIT_CHAIN_KEY to check its signature",
        },
      };
    }
    const valid = await verifyChainHeadSignature(
      chainKey,
      { orgId: org, seq: expected.seq, hash: expected.hash },
      expected.signature,
    );
    if (!valid) {
      return {
        failure: {
          code: 1,
          message:
            "audit-verify: the expected head's signature does not verify under AB_AUDIT_CHAIN_KEY",
        },
      };
    }
  }
  return { expected };
}

/** Verifies `rows` (one org's chain, seq-ascending) and, when given, that they still hold `expected`. */
export async function verifyAuditRows(
  rows: AuditRow[],
  chainKey: string | undefined,
  expected: ExpectedHead | null,
): Promise<AuditVerifyOutcome> {
  const verdict = await verifyChain(rows, chainKey);
  if (!verdict.ok) {
    return {
      code: 1,
      message:
        verdict.reason === "keyed_row_without_key"
          ? `audit-verify: chain is keyed from seq ${verdict.brokenAtSeq}; set AB_AUDIT_CHAIN_KEY to verify it`
          : `audit-verify: chain broken at seq ${verdict.brokenAtSeq}`,
    };
  }
  if (!expected) return { code: 0, message: `audit-verify: chain ok (${rows.length} rows)` };

  const row = rows.find((r) => r.seq === expected.seq);
  if (row) {
    if (row.hash !== expected.hash) {
      return {
        code: 1,
        message: `audit-verify: the row at seq ${expected.seq} no longer carries the expected head hash — the chain was rewritten`,
      };
    }
  } else {
    // Gone: compacted away (the anchor records the hash of the last
    // compacted row only), or truncated. Either way the head cannot be
    // confirmed — fail closed.
    const anchor = rows.find(
      (r) =>
        (r.action === RETENTION_COMPACTED_ACTION || r.action === RETENTION_COMPACTING_ACTION) &&
        (r.metadata as { compactedThroughSeq?: unknown }).compactedThroughSeq === expected.seq,
    );
    if (!anchor || (anchor.metadata as { lastHash?: unknown }).lastHash !== expected.hash) {
      return {
        code: 1,
        message: `audit-verify: the chain no longer holds the expected head (seq ${expected.seq}) — truncated, or compacted past it`,
      };
    }
  }
  return {
    code: 0,
    message: `audit-verify: chain ok (${rows.length} rows), expected head at seq ${expected.seq} present`,
  };
}

// Alpha Bros enterprise layer — audit log hash chain.
//
// Pure, DB- and framework-agnostic primitives: `canonical`/`hashRow` build
// the tamper-evident per-org hash chain (`hash = sha256(prevHash + "\n" +
// canonical(row))`), `verifyChain` walks a set of rows and reports the first
// broken link, and `writeAudit` is the single write path every plugin hook
// and endpoint in `./plugin.ts` goes through to append a new row.
//
// Hashing uses Web Crypto (`crypto.subtle.digest`) rather than Node's
// `crypto` module so this file — and everything that imports only from it —
// runs unmodified on workerd (Cloudflare Workers), per the controller
// ruling for this task. `crypto.subtle.digest` is inherently async, so
// `hashRow`/`verifyChain` are `Promise`-returning here even though the task
// brief's inline sketch omits the `Promise<...>` wrapper.
//
// `createdAt` is carried as an epoch-ms `number` throughout this module
// (never a `Date`): that keeps `canonical`/`hashRow` pure and portable, and
// pushes the DB-specific `Date <-> number` conversion to the boundary in
// `./plugin.ts` (write) and the callers of `verifyChain` (`./plugin.ts`'s
// verify endpoint, `src/cli/index.ts`'s `audit-verify`) that read rows back
// out of a database and normalize them before verifying.

import type { AuthContext } from "better-auth";
import type { Where } from "@better-auth/core/db/adapter";

type AuditAdapter = AuthContext["adapter"];

export interface AuditInput {
  orgId: string;
  actorType: "user" | "scim" | "system";
  actorId?: string | null;
  action: string;
  targetType: string;
  targetId?: string | null;
  ip?: string | null;
  userAgent?: string | null;
  metadata?: Record<string, unknown>;
}

// The fields that go into the hash — i.e. everything about a row except its
// own identity (`id`) and the hash chain linkage fields themselves
// (`prevHash`/`hash`), which `hashRow` takes/produces separately.
export interface AuditRowForHash {
  orgId: string;
  seq: number;
  actorType: string;
  actorId: string | null;
  action: string;
  targetType: string;
  targetId: string | null;
  ip: string | null;
  userAgent: string | null;
  metadata: Record<string, unknown>;
  /** Epoch milliseconds. */
  createdAt: number;
}

export interface AuditRow extends AuditRowForHash {
  id: string;
  prevHash: string;
  hash: string;
}

const GENESIS = "GENESIS";

/**
 * The action of the single anchor row retention compaction leaves behind in
 * place of the rows it removed (C-02). Its `metadata` carries
 * `{compactedThroughSeq, compactedCount, lastHash}` and its `prevHash` is
 * that same `lastHash` — the hash of the last row that was compacted away —
 * so `verifyChain` can re-anchor the surviving chain on it instead of
 * reporting the (expected, operator-initiated) gap as tampering. See
 * `compactChain` below.
 */
export const RETENTION_COMPACTED_ACTION = "audit.retention_compacted";

/**
 * The action the anchor row carries *while* a compaction is in flight (I-4).
 *
 * Compaction used to delete the expired prefix and only then create the
 * anchor, under the in-process lock alone. A crash, a request timeout or a
 * throwing `create` between those two calls left the prefix gone with nothing
 * to re-anchor on, and `verifyChain` reported `ok:false` for that org from
 * then on — the permanent false positive C-02 was raised to eliminate,
 * reachable again through a crash. The anchor is written **first** now, with
 * this action, and flipped to `RETENTION_COMPACTED_ACTION` once the delete
 * has succeeded, so both crash windows leave a verifiable chain:
 *
 * - crash before/during the delete → a pending anchor sitting in front of the
 *   still-intact original prefix; `verifyChain` ignores it and verifies the
 *   real chain from `GENESIS`.
 * - crash after the delete, before the flip → a pending anchor whose prefix is
 *   gone; `verifyChain` treats it exactly like a completed anchor.
 *
 * Either way the next compaction sweeps the stale pending anchor with the
 * prefix it stands in front of, because it always takes a `seq` below every
 * row the org currently has (see `compactChain`).
 */
export const RETENTION_COMPACTING_ACTION = "audit.retention_compacting";

/**
 * Deterministic JSON serialization of the hashed fields, in the fixed key
 * order `{orgId,seq,actorType,actorId,action,targetType,targetId,ip,
 * userAgent,metadata,createdAt}` — written out explicitly (rather than
 * relying on insertion order of a spread/loop) so the wire format can never
 * silently drift if a field is reordered elsewhere.
 */
export function canonical(row: AuditRowForHash): string {
  return JSON.stringify({
    orgId: row.orgId,
    seq: row.seq,
    actorType: row.actorType,
    actorId: row.actorId,
    action: row.action,
    targetType: row.targetType,
    targetId: row.targetId,
    ip: row.ip,
    userAgent: row.userAgent,
    metadata: row.metadata,
    createdAt: row.createdAt,
  });
}

function toHex(buffer: ArrayBuffer): string {
  return Array.from(new Uint8Array(buffer))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/** sha256 hex of `prevHash + "\n" + canonical(row)`, via Web Crypto. */
export async function hashRow(prevHash: string, row: AuditRowForHash): Promise<string> {
  const bytes = new TextEncoder().encode(`${prevHash}\n${canonical(row)}`);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return toHex(digest);
}

/**
 * Walks `rows` in seq order and checks that each row's `hash` is exactly
 * `hashRow(previous row's hash ?? "GENESIS", row)`. Reports the seq of the
 * first row that doesn't check out.
 *
 * Documented limit: this only certifies internal consistency of the rows
 * it's given. Deleting the *last* row(s) of a chain leaves the remainder
 * fully self-consistent (`ok: true`) — there is nothing left to contradict
 * it. Deleting an *earlier* row is caught: the row after the gap still
 * carries the deleted row's hash as its `prevHash`, which no longer matches
 * the hash of the row now immediately before it in `rows`.
 *
 * The one sanctioned exception is retention compaction (C-02): when the
 * first present row is a `RETENTION_COMPACTED_ACTION` anchor, the chain is
 * re-anchored on its `metadata.lastHash` — the hash of the last row
 * compaction removed — instead of `GENESIS`. The anchor itself still has to
 * hash correctly (`prevHash` = `metadata.lastHash`, `hash` =
 * `hashRow(prevHash, row)`).
 *
 * Honest about the trade: within the limits I-08 already documents (anyone
 * with database *write* can recompute a whole chain, and tail truncation is
 * undetectable), the anchor makes prefix deletion cheaper than it was. Such
 * an attacker no longer has to rewrite every surviving row's hash to hide
 * dropped rows — forging one anchor whose `prevHash`/`metadata.lastHash`
 * equal the next row's `prevHash` suffices, and the `compactedCount` it
 * claims is unverifiable. That is weaker for that one scenario, and much
 * stronger for the scenario that actually occurs: routine retention, which
 * before this reported the chain as tampered forever. The real fix for both
 * is an external anchor (I-08's periodic signed, off-box checkpoint), still
 * the post-v0.1 answer.
 */
export async function verifyChain(
  rows: AuditRow[],
): Promise<{ ok: true } | { ok: false; brokenAtSeq: number }> {
  const result = await verifyChainPage(rows, null);
  return result.ok ? { ok: true } : result;
}

/**
 * One page of `verifyChain`, so a caller can walk a long chain in bounded
 * batches instead of materialising and hashing the whole table at once (I-3
 * — `/enterprise/audit/verify` is a one-click action in `<ab-audit-log>`).
 *
 * `prevHash` is `null` for the **first** page — the anchor rules above apply
 * and the baseline is `GENESIS` — and otherwise the `prevHash` the previous
 * page returned. Pages must be `seq`-ascending, contiguous, and non-empty
 * except possibly the first.
 */
export async function verifyChainPage(
  rows: AuditRow[],
  prevHashIn: string | null,
): Promise<{ ok: true; prevHash: string } | { ok: false; brokenAtSeq: number }> {
  const sorted = [...rows].sort((a, b) => a.seq - b.seq);
  let prevHash = prevHashIn ?? GENESIS;

  const anchor = prevHashIn === null ? sorted[0] : undefined;
  if (
    anchor &&
    (anchor.action === RETENTION_COMPACTED_ACTION || anchor.action === RETENTION_COMPACTING_ACTION)
  ) {
    const metadata = anchor.metadata as
      { lastHash?: unknown; compactedThroughSeq?: unknown } | undefined;
    const lastHash = metadata?.lastHash;
    if (typeof lastHash !== "string" || anchor.prevHash !== lastHash) {
      return { ok: false, brokenAtSeq: anchor.seq };
    }
    if ((await hashRow(anchor.prevHash, anchor)) !== anchor.hash) {
      return { ok: false, brokenAtSeq: anchor.seq };
    }
    // The anchor is never itself a link in the chain — it is a stand-in for
    // the prefix that is (or is about to be) gone, which is why the rows
    // after it carry the *compacted-away* tail's hash, not the anchor's own.
    sorted.shift();
    // A **pending** anchor still standing in front of the rows it was going
    // to replace means the delete never ran (I-4): the original chain is
    // intact all the way back to `GENESIS`, so verify it as such and ignore
    // the anchor entirely. A pending anchor whose prefix is already gone —
    // the crash between the delete and the flip — is a completed anchor in
    // every way that matters here.
    const compactedThroughSeq = metadata?.compactedThroughSeq;
    const prefixStillPresent =
      anchor.action === RETENTION_COMPACTING_ACTION &&
      typeof compactedThroughSeq === "number" &&
      sorted[0] !== undefined &&
      sorted[0].seq <= compactedThroughSeq;
    prevHash = prefixStillPresent ? GENESIS : lastHash;
  }

  for (const row of sorted) {
    if (row.prevHash !== prevHash) {
      return { ok: false, brokenAtSeq: row.seq };
    }
    const expected = await hashRow(prevHash, row);
    if (expected !== row.hash) {
      return { ok: false, brokenAtSeq: row.seq };
    }
    prevHash = row.hash;
  }
  return { ok: true, prevHash };
}

// Driver error codes that mean "a row with this unique key already exists"
// (L-03): libsql/sqlite (`SQLITE_CONSTRAINT_UNIQUE`/`…_PRIMARYKEY`),
// postgres (`23505`), mysql (`ER_DUP_ENTRY`/1062). Checked *in addition to*
// — not instead of — the message heuristic: adapters differ in whether they
// preserve the driver's code at all (the drizzle/libsql path this package is
// tested on frequently rewraps the error), so dropping the regex would turn
// a real race into a hard failure on those. The code check is what makes the
// common cases exact rather than wording-dependent.
const UNIQUE_VIOLATION_CODES = new Set([
  "SQLITE_CONSTRAINT_UNIQUE",
  "SQLITE_CONSTRAINT_PRIMARYKEY",
  "SQLITE_CONSTRAINT",
  "23505",
  "ER_DUP_ENTRY",
  "1062",
]);

export function isUniqueViolation(err: unknown): boolean {
  const code = (err as { code?: unknown } | null)?.code;
  if (
    (typeof code === "string" || typeof code === "number") &&
    UNIQUE_VIOLATION_CODES.has(String(code))
  ) {
    return true;
  }
  const message = err instanceof Error ? err.message : String(err);
  return /unique/i.test(message);
}

// Per-org in-process async mutex: serializes `seq` allocation + write for a
// given org across concurrent `writeAudit` calls within this process. A
// second process (or a second `betterAuth()` instance in this one) racing
// on the same org is instead caught by the `audit_event_org_seq` unique
// index and handled by the one retry below.
const orgLocks = new Map<string, Promise<unknown>>();

function withOrgLock<T>(orgId: string, task: () => Promise<T>): Promise<T> {
  const previous = orgLocks.get(orgId) ?? Promise.resolve();
  const result = previous.then(task, task);
  const settled = result.catch(() => undefined);
  orgLocks.set(orgId, settled);
  // Evict once this org's chain has settled and nothing newer has queued
  // behind it (L-02) — without this the map grows one permanent entry per
  // distinct org ever audited in the process. Note (documented, unchanged):
  // this mutex is per *process*; on workerd or any multi-instance deployment
  // the `audit_event_org_seq` unique index plus the retry below is the real
  // guard.
  void settled.then(() => {
    if (orgLocks.get(orgId) === settled) orgLocks.delete(orgId);
  });
  return result;
}

/**
 * Number of orgs currently holding an in-flight audit-chain lock — exported
 * for `test/server/audit-chain.test.ts`'s eviction assertion (L-02) only.
 */
export function pendingOrgLockCount(): number {
  return orgLocks.size;
}

// The row shape as the adapter sees it — `createdAt` is a real `Date` here
// (matching the plugin's `schema` declaration in `./plugin.ts`, `type:
// "date"`), unlike `AuditRow`/`AuditRowForHash` above which keep epoch-ms
// numbers throughout for the pure hashing functions.
interface AuditEventDbRow {
  id: string;
  orgId: string;
  seq: number;
  actorType: string;
  actorId: string | null;
  action: string;
  targetType: string;
  targetId: string | null;
  ip: string | null;
  userAgent: string | null;
  metadata: Record<string, unknown>;
  createdAt: Date;
  prevHash: string;
  hash: string;
}

/**
 * When `row` is a compaction anchor (completed or still-pending — see
 * `RETENTION_COMPACTING_ACTION`), the hash that chains *from* it is not its
 * own `hash` but `metadata.lastHash` — the hash of the last row compaction
 * removed. `verifyChainPage` re-anchors on exactly this value (see its own
 * anchor handling above); `insertNextRow` has to agree, or the first write
 * after a compaction that swept an org's *entire* chain permanently breaks
 * `verifyChain` for that org, since the anchor is then also the row
 * `insertNextRow` selects as "last". Falls back to `row.hash` when
 * `metadata.lastHash` isn't the string it's supposed to be, which only
 * matters for an already-corrupt anchor that `verifyChain` will flag on its
 * own.
 */
function chainedHashOf(row: {
  action: string;
  hash: string;
  metadata: Record<string, unknown>;
}): string {
  if (row.action !== RETENTION_COMPACTED_ACTION && row.action !== RETENTION_COMPACTING_ACTION) {
    return row.hash;
  }
  const lastHash = (row.metadata as { lastHash?: unknown } | undefined)?.lastHash;
  return typeof lastHash === "string" ? lastHash : row.hash;
}

/**
 * The `seq` a new row is numbered *from* when `row` is a compaction anchor.
 * An anchor's own `seq` sits below every row the org holds (`compactChain`
 * marches anchors downward: 0, then -1, …), so naively continuing from
 * `anchor.seq + 1` after a full-chain wipe hands the very next row a `seq`
 * that falls inside `[minSeq, compactedThroughSeq]` — the same range a
 * still-undeleted expired prefix would occupy if compaction had crashed
 * *before* its delete. `verifyChainPage`'s pending-anchor disambiguation
 * (`prefixStillPresent`) tells the two cases apart only by comparing the
 * next present row's `seq` to `metadata.compactedThroughSeq`, so a
 * low-`seq` new row masquerades as "the delete never ran" and gets verified
 * from `GENESIS` — wrongly, since it's a fresh row chained off
 * `metadata.lastHash`. Continuing from `max(anchor.seq, compactedThroughSeq)
 * + 1` instead keeps every post-anchor `seq` strictly above that range, so
 * it can never be confused with a surviving pre-compaction prefix — without
 * touching `verifyChainPage` itself.
 */
function nextSeqBaseOf(row: {
  seq: number;
  action: string;
  metadata: Record<string, unknown>;
}): number {
  if (row.action !== RETENTION_COMPACTED_ACTION && row.action !== RETENTION_COMPACTING_ACTION) {
    return row.seq;
  }
  const compactedThroughSeq = (row.metadata as { compactedThroughSeq?: unknown } | undefined)
    ?.compactedThroughSeq;
  return typeof compactedThroughSeq === "number" ? Math.max(row.seq, compactedThroughSeq) : row.seq;
}

async function insertNextRow(adapter: AuditAdapter, input: AuditInput): Promise<AuditRow> {
  const last = await adapter.findMany<{
    seq: number;
    hash: string;
    action: string;
    metadata: Record<string, unknown>;
  }>({
    model: "auditEvent",
    where: [{ field: "orgId", value: input.orgId }],
    sortBy: { field: "seq", direction: "desc" },
    limit: 1,
  });
  const seq = (last[0] ? nextSeqBaseOf(last[0]) : 0) + 1;
  const prevHash = last[0] ? chainedHashOf(last[0]) : GENESIS;
  const createdAt = Date.now();

  const rowForHash: AuditRowForHash = {
    orgId: input.orgId,
    seq,
    actorType: input.actorType,
    actorId: input.actorId ?? null,
    action: input.action,
    targetType: input.targetType,
    targetId: input.targetId ?? null,
    ip: input.ip ?? null,
    userAgent: input.userAgent ?? null,
    metadata: input.metadata ?? {},
    createdAt,
  };
  const hash = await hashRow(prevHash, rowForHash);

  const created = await adapter.create<AuditEventDbRow>({
    model: "auditEvent",
    data: {
      orgId: rowForHash.orgId,
      seq: rowForHash.seq,
      actorType: rowForHash.actorType,
      actorId: rowForHash.actorId,
      action: rowForHash.action,
      targetType: rowForHash.targetType,
      targetId: rowForHash.targetId,
      ip: rowForHash.ip,
      userAgent: rowForHash.userAgent,
      metadata: rowForHash.metadata,
      createdAt: new Date(createdAt),
      prevHash,
      hash,
    },
  });

  return { ...rowForHash, id: created.id, prevHash, hash };
}

/**
 * Appends one row to `input.orgId`'s chain: `seq` = max(seq)+1 for the org,
 * `prevHash` = the org's last row's hash (or `"GENESIS"` for the first
 * row). Serialized per org via `withOrgLock`; on a unique-index violation
 * (`audit_event_org_seq`, meaning another process/instance won the race for
 * this `seq`) retries once with a freshly recomputed `seq`, then rethrows.
 */
export async function writeAudit(
  ctx: { context: Pick<AuthContext, "adapter"> },
  input: AuditInput,
): Promise<AuditRow> {
  const adapter = ctx.context.adapter as unknown as AuditAdapter;
  return withOrgLock(input.orgId, async () => {
    try {
      return await insertNextRow(adapter, input);
    } catch (err) {
      if (!isUniqueViolation(err)) throw err;
      return await insertNextRow(adapter, input);
    }
  });
}

export interface CompactionResult {
  /** The highest `seq` that was compacted away. The anchor row itself sits *below* every surviving row (see `compactChain`), not at this `seq`. */
  compactedThroughSeq: number;
  /** How many rows were removed (the anchor row itself replaces them all). */
  compactedCount: number;
  /** The `hash` of the last compacted row — the anchor's `prevHash`, and where the surviving chain resumes. */
  lastHash: string;
}

/**
 * Retention as **archival compaction** rather than a bare delete (C-02).
 *
 * Every row of `orgId`'s chain at or below the highest `seq` older than
 * `cutoff` is removed and replaced by a single anchor row carrying
 * `{compactedThroughSeq, compactedCount, lastHash}` in its metadata and the
 * removed tail's hash as its `prevHash`. `verifyChain` knows how to re-anchor
 * on it, so a chain that has been compacted still verifies `ok` — where the
 * pre-C-02 hard delete left it permanently reporting `ok:false,
 * brokenAtSeq:<first surviving row>`.
 *
 * The anchor is written **before** the delete and in three phases (I-4), so
 * neither crash window can leave the chain unverifiable — see
 * `RETENTION_COMPACTING_ACTION`. It takes the `seq` one below the org's
 * current lowest rather than the compacted-through `seq`, because that one is
 * still occupied while the anchor is being written and `(org_id, seq)` is
 * unique.
 *
 * Rows are selected by `seq <= <highest expired seq>` rather than by
 * `createdAt` alone so that a *previous* anchor row (whose `createdAt` is
 * its own compaction time, i.e. much newer than the rows it stands for) is
 * always swept up by the next compaction instead of being stranded before
 * newer rows and breaking the re-anchoring invariant.
 *
 * Returns `null` when nothing was old enough to compact. Runs under the same
 * per-org lock as `writeAudit`, so it can never interleave with an append.
 */
export async function compactChain(
  ctx: { context: Pick<AuthContext, "adapter"> },
  orgId: string,
  cutoff: Date,
): Promise<CompactionResult | null> {
  const adapter = ctx.context.adapter as unknown as AuditAdapter;
  return withOrgLock(orgId, async () => {
    const expired = await adapter.findMany<{ seq: number; hash: string }>({
      model: "auditEvent",
      where: [
        { field: "orgId", value: orgId },
        { field: "createdAt", value: cutoff, operator: "lt" },
      ],
      sortBy: { field: "seq", direction: "desc" },
      limit: 1,
    });
    const through = expired[0];
    if (!through) return null;

    // The lowest `seq` the org currently holds, including any anchor a
    // previous compaction left behind. The new anchor goes one below it,
    // which is the only way to write it **before** the delete: `seq` is an
    // integer and `audit_event_org_seq` is unique per `(org_id, seq)`, so the
    // compacted-through `seq` this anchor stands for is still occupied at
    // that point. Anchors therefore march downward — 0, then -1, … — one step
    // per compaction, and each one is swept by the next compaction's delete
    // because it always sits inside `[minSeq, through.seq]`.
    const lowest = await adapter.findMany<{ seq: number }>({
      model: "auditEvent",
      where: [{ field: "orgId", value: orgId }],
      sortBy: { field: "seq", direction: "asc" },
      limit: 1,
    });
    const minSeq = lowest[0]?.seq ?? 1;
    const anchorSeq = minSeq - 1;

    const doomedWhere: Where[] = [
      { field: "orgId", value: orgId },
      { field: "seq", value: minSeq, operator: "gte" },
      { field: "seq", value: through.seq, operator: "lte" },
    ];
    // Counted, not fetched: the rows are about to be deleted and only their
    // number is recorded, so there is no reason to materialise them (the
    // sibling of I-3's unbounded read, on the write path).
    const compactedCount = await adapter.count({ model: "auditEvent", where: doomedWhere });

    const createdAt = Date.now();
    const rowForHash: AuditRowForHash = {
      orgId,
      seq: anchorSeq,
      actorType: "system",
      actorId: null,
      action: RETENTION_COMPACTING_ACTION,
      targetType: "organization",
      targetId: orgId,
      ip: null,
      userAgent: null,
      metadata: {
        compactedThroughSeq: through.seq,
        compactedCount,
        lastHash: through.hash,
      },
      createdAt,
    };

    // Phase 1 — write the anchor, marked pending.
    const pendingHash = await hashRow(through.hash, rowForHash);
    const anchorRow = await adapter.create<AuditEventDbRow>({
      model: "auditEvent",
      data: {
        ...rowForHash,
        createdAt: new Date(createdAt),
        prevHash: through.hash,
        hash: pendingHash,
      },
    });

    // Phase 2 — remove the prefix the anchor now stands for.
    await adapter.deleteMany({ model: "auditEvent", where: doomedWhere });

    // Phase 3 — mark the anchor complete. `action` is part of the hashed
    // payload (`canonical`), so the hash is recomputed rather than carried
    // over; `prevHash` is unchanged.
    const completed: AuditRowForHash = { ...rowForHash, action: RETENTION_COMPACTED_ACTION };
    await adapter.update({
      model: "auditEvent",
      where: [{ field: "id", value: anchorRow.id }],
      update: {
        action: RETENTION_COMPACTED_ACTION,
        hash: await hashRow(through.hash, completed),
      },
    });

    return {
      compactedThroughSeq: through.seq,
      compactedCount,
      lastHash: through.hash,
    };
  });
}

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
// Keyed chains (`audit.chainKey`, opt-in): the unkeyed chain only certifies
// internal consistency — whoever holds database *write* (the attacker the
// log is meant to catch) can rewrite an org's whole chain consistently and
// `verify` says `ok`. With a `chainKey`, every link becomes
// `"hmac:" + HMAC-SHA256(chainKey, prevHash + "\n" + canonical(row))`, which
// a DB-write holder without the key cannot recompute. Adoption is
// **monotonic**: a chain may go from unkeyed rows to keyed rows once (the
// day the operator sets the key), never back — a bare row *after* a keyed
// one is reported as a break, since silently accepting it would let that
// same attacker downgrade the chain to the hash they *can* compute. A keyed
// row verified without the key is `keyed_row_without_key`, never `ok`.
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

/**
 * Who performed an audited action. `impersonated` is a user action taken
 * through an impersonation session (`admin` plugin): `actorId` is the user
 * being impersonated and `metadata.impersonatedBy` the staff member actually
 * driving the session, so the row never reads as the user's own act.
 */
export type AuditActorType = "user" | "scim" | "system" | "impersonated";

export interface AuditInput {
  orgId: string;
  actorType: AuditActorType;
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

/** Prefix that marks a row hash as keyed (`hmac:` + hex HMAC-SHA256) rather than a bare sha256 hex. */
export const KEYED_HASH_PREFIX = "hmac:";

/** Whether a stored `hash` (or a carried `prevHash`) was produced under a `chainKey`. */
export function isKeyedHash(hash: string): boolean {
  return hash.startsWith(KEYED_HASH_PREFIX);
}

// Imported HMAC keys are cached per key string: `importKey` is not free and
// a process only ever sees one or two distinct keys (the configured one, and
// a rotated one during a `--expect-head` verification).
const hmacKeys = new Map<string, Promise<CryptoKey>>();

function hmacKeyFor(key: string): Promise<CryptoKey> {
  let imported = hmacKeys.get(key);
  if (!imported) {
    imported = crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(key),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"],
    );
    hmacKeys.set(key, imported);
  }
  return imported;
}

/**
 * The hash of one link: sha256 hex of `prevHash + "\n" + canonical(row)`
 * when unkeyed; `"hmac:" + HMAC-SHA256(key, same bytes)` hex when a
 * `key` (`audit.chainKey`) is given. Web Crypto in both cases.
 */
export async function hashRow(
  prevHash: string,
  row: AuditRowForHash,
  key?: string,
): Promise<string> {
  const bytes = new TextEncoder().encode(`${prevHash}\n${canonical(row)}`);
  if (key === undefined) {
    const digest = await crypto.subtle.digest("SHA-256", bytes);
    return toHex(digest);
  }
  const signature = await crypto.subtle.sign("HMAC", await hmacKeyFor(key), bytes);
  return `${KEYED_HASH_PREFIX}${toHex(signature)}`;
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
export async function verifyChain(rows: AuditRow[], key?: string): Promise<VerifyResult> {
  const result = await verifyChainPage(rows, null, key);
  return result.ok ? { ok: true } : result;
}

/**
 * Why a chain failed to verify beyond "the hash didn't match":
 * `keyed_row_without_key` — the row at `brokenAtSeq` is keyed and the
 * verifier was not given the `chainKey`, so it cannot be checked at all
 * (as opposed to having been checked and found wrong).
 */
export type VerifyFailureReason = "keyed_row_without_key";

export type VerifyFailure = { ok: false; brokenAtSeq: number; reason?: VerifyFailureReason };
export type VerifyResult = { ok: true } | VerifyFailure;
export type VerifyPageResult = { ok: true; prevHash: string } | VerifyFailure;

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
  key?: string,
): Promise<VerifyPageResult> {
  const sorted = [...rows].sort((a, b) => a.seq - b.seq);
  let prevHash = prevHashIn ?? GENESIS;

  // One link, under the monotonic-upgrade rule. The keyed/unkeyed state of
  // the chain *so far* is exactly whether `prevHash` is keyed (`GENESIS` and
  // every bare sha256 are not; every HMAC link is) — no extra state has to
  // survive a page boundary.
  const checkLink = async (row: AuditRow, prev: string): Promise<VerifyFailure | null> => {
    const keyedSoFar = isKeyedHash(prev);
    const rowKeyed = isKeyedHash(row.hash);
    if (keyedSoFar && !rowKeyed) return { ok: false, brokenAtSeq: row.seq };
    if (rowKeyed && key === undefined) {
      return { ok: false, brokenAtSeq: row.seq, reason: "keyed_row_without_key" };
    }
    const expected = await hashRow(prev, row, rowKeyed ? key : undefined);
    return expected === row.hash ? null : { ok: false, brokenAtSeq: row.seq };
  };

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
    const anchorFailure = await checkLink(anchor, anchor.prevHash);
    if (anchorFailure) return anchorFailure;
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
    const failure = await checkLink(row, prevHash);
    if (failure) return failure;
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

/**
 * Options shared by the two chain writers. `chainKey` (`audit.chainKey`)
 * makes every link this call produces an HMAC link — see the header.
 *
 * A caller that passes no `chainKey` gets the one the deployment is
 * configured with (`auditChainKeyOf`, read off the auth context the call
 * runs in), not an unkeyed link: once an org's chain holds a keyed row, one
 * unkeyed row after it breaks verification for good (monotonic rule), so no
 * writer may be able to forget the key. Only a context without a configured
 * key — no enterprise plugin carrying `audit.chainKey` — writes unkeyed.
 *
 * `actor` is the caller a compaction anchor is attributed to (the operator
 * or admin who ran it); without one the anchor is a `system` row.
 */
export interface ChainWriteOptions {
  chainKey?: string;
  actor?: { actorType: AuditActorType; actorId: string | null };
}

/** Plugin ids whose `options` carry the deployment's `EnterpriseOptions` (and so `audit.chainKey`). */
const OPTION_CARRYING_PLUGIN_IDS = ["enterprise-audit", "enterprise-gate"] as const;

/**
 * The `audit.chainKey` the running auth instance is configured with, read
 * from the enterprise plugins mounted on it (the same way `requireFeature`
 * reads `resolveEntitlements` back off `ctx.context.options.plugins`), or
 * `undefined` when none carries one.
 */
export function auditChainKeyOf(context: unknown): string | undefined {
  const plugins = (context as { options?: { plugins?: unknown } } | null | undefined)?.options
    ?.plugins;
  if (!Array.isArray(plugins)) return undefined;
  for (const id of OPTION_CARRYING_PLUGIN_IDS) {
    const plugin = plugins.find((p: unknown) => (p as { id?: unknown } | null)?.id === id) as
      { options?: { audit?: { chainKey?: unknown } } } | undefined;
    const key = plugin?.options?.audit?.chainKey;
    if (typeof key === "string" && key.length > 0) return key;
  }
  return undefined;
}

/** The context shape the chain writers need: the adapter, and the options they read `chainKey` from. */
export interface AuditWriteContext {
  context: Pick<AuthContext, "adapter"> & { options?: unknown };
}

function effectiveChainKey(ctx: AuditWriteContext, options: ChainWriteOptions): string | undefined {
  return options.chainKey ?? auditChainKeyOf(ctx.context);
}

async function insertNextRow(
  adapter: AuditAdapter,
  input: AuditInput,
  chainKey: string | undefined,
): Promise<AuditRow> {
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
  const hash = await hashRow(prevHash, rowForHash, chainKey);

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
  ctx: AuditWriteContext,
  input: AuditInput,
  options: ChainWriteOptions = {},
): Promise<AuditRow> {
  const adapter = ctx.context.adapter as unknown as AuditAdapter;
  const chainKey = effectiveChainKey(ctx, options);
  return withOrgLock(input.orgId, async () => {
    try {
      return await insertNextRow(adapter, input, chainKey);
    } catch (err) {
      if (!isUniqueViolation(err)) throw err;
      return await insertNextRow(adapter, input, chainKey);
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
  ctx: AuditWriteContext,
  orgId: string,
  cutoff: Date,
  options: ChainWriteOptions = {},
): Promise<CompactionResult | null> {
  const adapter = ctx.context.adapter as unknown as AuditAdapter;
  const chainKey = effectiveChainKey(ctx, options);
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
      // The caller who ran the compaction (F-13): an anchor that stands in
      // for deleted rows must say who deleted them.
      actorType: options.actor?.actorType ?? "system",
      actorId: options.actor?.actorId ?? null,
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
    const pendingHash = await hashRow(through.hash, rowForHash, chainKey);
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
        hash: await hashRow(through.hash, completed, chainKey),
      },
    });

    return {
      compactedThroughSeq: through.seq,
      compactedCount,
      lastHash: through.hash,
    };
  });
}

/**
 * The newest row of an org's chain — what an operator exports off-box to
 * detect a later truncation or a consistent rewrite of the whole chain
 * (`GET /enterprise/audit/head`, `ab-enterprise audit-verify
 * --expect-head`). `null` for an org without rows.
 */
export interface ChainHead {
  orgId: string;
  seq: number;
  hash: string;
  /** Epoch milliseconds. */
  createdAt: number;
}

export async function readChainHead(
  ctx: { context: Pick<AuthContext, "adapter"> },
  orgId: string,
): Promise<ChainHead | null> {
  const adapter = ctx.context.adapter as unknown as AuditAdapter;
  const rows = await adapter.findMany<{ seq: number; hash: string; createdAt: Date | number }>({
    model: "auditEvent",
    where: [{ field: "orgId", value: orgId }],
    sortBy: { field: "seq", direction: "desc" },
    limit: 1,
  });
  const row = rows[0];
  if (!row) return null;
  const createdAt = row.createdAt instanceof Date ? row.createdAt.getTime() : Number(row.createdAt);
  return { orgId, seq: Number(row.seq), hash: row.hash, createdAt };
}

/** Domain separation for head signatures, so a head signature can never double as a chain link. */
const HEAD_SIGNATURE_CONTEXT = "ab-enterprise-audit-head:v1";

function headSignaturePayload(head: Pick<ChainHead, "orgId" | "seq" | "hash">): string {
  return `${HEAD_SIGNATURE_CONTEXT}\n${head.orgId}\n${head.seq}\n${head.hash}`;
}

/**
 * `hmac:` + hex HMAC-SHA256 under `chainKey` over the org id, `seq` and
 * `hash` of a head — binds an exported head to its org and position, so a
 * holder of the key can later prove the value was issued by the deployment
 * (and was not, say, copied from another org's chain).
 */
export async function signChainHead(
  key: string,
  head: Pick<ChainHead, "orgId" | "seq" | "hash">,
): Promise<string> {
  const signature = await crypto.subtle.sign(
    "HMAC",
    await hmacKeyFor(key),
    new TextEncoder().encode(headSignaturePayload(head)),
  );
  return `${KEYED_HASH_PREFIX}${toHex(signature)}`;
}

/** Constant-time comparison of a presented head signature with the one `key` produces. */
export async function verifyChainHeadSignature(
  key: string,
  head: Pick<ChainHead, "orgId" | "seq" | "hash">,
  signature: string,
): Promise<boolean> {
  const expected = await signChainHead(key, head);
  if (expected.length !== signature.length) return false;
  let diff = 0;
  for (let i = 0; i < expected.length; i++)
    diff |= expected.charCodeAt(i) ^ signature.charCodeAt(i);
  return diff === 0;
}

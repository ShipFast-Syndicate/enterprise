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
 */
export async function verifyChain(
  rows: AuditRow[],
): Promise<{ ok: true } | { ok: false; brokenAtSeq: number }> {
  const sorted = [...rows].sort((a, b) => a.seq - b.seq);
  let prevHash = GENESIS;
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
  return { ok: true };
}

function isUniqueViolation(err: unknown): boolean {
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
  orgLocks.set(
    orgId,
    result.catch(() => undefined),
  );
  return result;
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

async function insertNextRow(adapter: AuditAdapter, input: AuditInput): Promise<AuditRow> {
  const last = await adapter.findMany<{ seq: number; hash: string }>({
    model: "auditEvent",
    where: [{ field: "orgId", value: input.orgId }],
    sortBy: { field: "seq", direction: "desc" },
    limit: 1,
  });
  const seq = (last[0]?.seq ?? 0) + 1;
  const prevHash = last[0]?.hash ?? GENESIS;
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

// Alpha Bros enterprise layer — sign-in refusal audit rows.
//
// `auditRefusal()` is what a real `hooks.before` handler calls right before
// it throws a policy refusal (`SSO_REQUIRED`, `METHOD_NOT_ALLOWED`,
// `TWO_FACTOR_REQUIRED`, …). better-auth does not run `hooks.after` when a
// `hooks.before` handler throws (`runBeforeHooks` rethrows before the
// endpoint and the after-hooks ever run, `better-auth/dist/api/
// dispatch.mjs`), so the audit plugin's after-hook — which does observe
// endpoint `APIError`s, including the ones thrown from `databaseHooks`
// inside the endpoint — never sees those refusals, and the log would show
// nothing for them.
//
// De-duplication rule: only `hooks.before` handlers call this, never the
// `databaseHooks.session.create.before` backstop (whose throw the after-hook
// *does* observe and classifies by code, `./plugin.ts`). A handler that
// wrote a row flags it on the request's audit stash so the after-hook does
// not write a second one if the refusal reaches it anyway.

import type { GenericEndpointContext } from "better-auth";
import { getIP, type APIError } from "better-auth/api";
import { tryGetCurrentAuthEndpointContext } from "@better-auth/core/context";
import { auditInBackground } from "./background";
import { auditEmail, auditUserAgent } from "./bounds";
import { writeAudit } from "./chain";

/** Per-request scratch the audit hooks share (kept on the request's own `ctx.context`). */
export interface EnterpriseAuditStash {
  /** Set once a `hooks.before` handler already wrote the refusal row for this request. */
  refusalWritten?: boolean;
  /** Policy codes this package's own code refused the request with (`policyRefusal`). */
  policyRefusalCodes?: Set<string>;
  /** Anything the audit plugin's own `hooks.before` resolved before the endpoint ran. */
  [key: string]: unknown;
}

/** Where the stash lives on `ctx.context` — per request (better-auth builds a fresh context object per dispatch). */
export const AUDIT_STASH_KEY = "enterpriseAuditStash";

/** The request's audit stash, created on first use. */
export function auditStashOf(ctx: { context: unknown }): EnterpriseAuditStash {
  const context = ctx.context as Record<string, unknown>;
  let stash = context[AUDIT_STASH_KEY] as EnterpriseAuditStash | undefined;
  if (!stash || typeof stash !== "object") {
    stash = {};
    context[AUDIT_STASH_KEY] = stash;
  }
  return stash;
}

/**
 * Marks `error` — a policy refusal this package raises — on the audit stash
 * of the request it is raised in, and returns it unchanged. The audit
 * after-hook records a failure as a refusal (`auth.sign_in_refused`) only
 * when its code was marked this way during the same request, never because
 * a code appears in a redirect URL or an error body: callers can put any
 * `error=` they like into a callback URL or an IdP error response, but only
 * this package's own code can mark the stash. The request is the one
 * better-auth is dispatching (`tryGetCurrentAuthEndpointContext`, the
 * endpoint context the hooks and `databaseHooks` of that request share).
 */
export function policyRefusal<E extends APIError>(error: E): E {
  const code = (error.body as { code?: unknown } | undefined)?.code;
  if (typeof code === "string") notePolicyRefusal(code);
  return error;
}

/** `policyRefusal` for a refusal this package hands to upstream as a code (the SSO `resolveUser` hook). */
export function notePolicyRefusal(code: string): void {
  const endpointCtx = tryGetCurrentAuthEndpointContext();
  if (!endpointCtx?.context) return;
  const stash = auditStashOf(endpointCtx);
  (stash.policyRefusalCodes ??= new Set()).add(code);
}

/** Whether this package's own code refused the request with `code` (see `policyRefusal`). */
export function isNotedPolicyRefusal(ctx: { context: unknown }, code: string): boolean {
  return auditStashOf(ctx).policyRefusalCodes?.has(code) === true;
}

/** A refused **sign-in** (no session was minted). */
export const SIGN_IN_REFUSED_ACTION = "auth.sign_in_refused";
/** A refused **use of an existing session** (the `require2fa` enrolment/standing gate on any other path). */
export const SESSION_REFUSED_ACTION = "auth.session_refused";

export interface RefusalInput {
  /** Request path the refusal was raised on (`/magic-link/verify`, …). */
  path: string;
  /** The policy error code being thrown (`SSO_REQUIRED`, …). */
  code: string;
  /** The orgs whose policy produced the refusal — one row per org. */
  orgIds: readonly string[];
  /** Known user, if the request resolved one; `null` for a pre-auth refusal of an unknown address. */
  userId?: string | null;
  /** The address the sign-in was for, when known (recorded only when no user id is). */
  email?: string | null;
  /** The classified sign-in method, when known. */
  method?: string | null;
  /**
   * `"sign-in"` (default): the refusal stops a sign-in — `auth.sign_in_refused`.
   * `"session"`: it stops a request made with an existing session —
   * `auth.session_refused`, at most one row per user, code and org every
   * `SESSION_REFUSAL_THROTTLE_MS` per process (a confined session's client
   * may retry the same call in a loop; the first refusal is the event).
   */
  kind?: "sign-in" | "session";
  metadata?: Record<string, unknown>;
}

/** De-noising window for `kind: "session"` refusal rows, per process. */
export const SESSION_REFUSAL_THROTTLE_MS = 10 * 60 * 1000;
const SESSION_REFUSAL_THROTTLE_MAX_KEYS = 10_000;
const recentSessionRefusals = new Map<string, number>();

function throttledSessionRefusal(key: string, now: number): boolean {
  const last = recentSessionRefusals.get(key);
  if (last !== undefined && now - last < SESSION_REFUSAL_THROTTLE_MS) return true;
  recentSessionRefusals.delete(key);
  recentSessionRefusals.set(key, now);
  if (recentSessionRefusals.size > SESSION_REFUSAL_THROTTLE_MAX_KEYS) {
    const oldest = recentSessionRefusals.keys().next().value;
    if (oldest !== undefined) recentSessionRefusals.delete(oldest);
  }
  return false;
}

/** Test hook: forget the per-process session-refusal throttle. */
export function resetSessionRefusalThrottleForTest(): void {
  recentSessionRefusals.clear();
}

/**
 * Records a policy refusal: one `auth.sign_in_refused` (or, for `kind:
 * "session"`, `auth.session_refused`) row in the chain of every org whose
 * policy produced it, keyed with the deployment's `audit.chainKey`. Never
 * throws — a failure to audit must not turn a refusal into a success — and
 * must be awaited *before* the caller throws its `APIError`. Sets the
 * request's `refusalWritten` flag.
 *
 * A refused sign-in is about an address the caller chose, so its rows are
 * written off the response path (`auditInBackground`). An address that is
 * not a valid e-mail address (`auditEmail`) names no subject: with no known
 * user, nothing is written.
 */
export async function auditRefusal(
  ctx: GenericEndpointContext,
  input: RefusalInput,
): Promise<void> {
  const kind = input.kind ?? "sign-in";
  const action = kind === "session" ? SESSION_REFUSED_ACTION : SIGN_IN_REFUSED_ACTION;
  const userId = input.userId ?? null;
  const email = auditEmail(input.email);
  if (userId === null && input.email != null && email === null) {
    ctx.context.logger.debug(
      `enterprise-audit: ${action} (${input.code}) on ${input.path} names no valid address; nothing written`,
    );
    return;
  }
  const request = ctx.request;
  const ip = request ? (getIP(request, ctx.context.options) ?? null) : null;
  const userAgent = auditUserAgent(request?.headers.get("user-agent"));
  const metadata: Record<string, unknown> = {
    ...input.metadata,
    code: input.code,
    path: input.path,
    ...(input.method ? { method: input.method } : {}),
    ...(userId === null && email ? { email } : {}),
  };
  const orgIds = [...new Set(input.orgIds)];
  const write = async (orgId: string): Promise<boolean> => {
    try {
      await writeAudit(ctx, {
        orgId,
        actorType: "system",
        actorId: null,
        action,
        targetType: "user",
        targetId: userId,
        ip,
        userAgent,
        metadata,
      });
      return true;
    } catch (err) {
      ctx.context.logger.error(
        `enterprise-audit: failed to write ${action} (${input.code}) for org ${orgId}`,
        err,
      );
      return false;
    }
  };
  if (kind === "sign-in") {
    if (orgIds.length === 0) return;
    auditStashOf(ctx).refusalWritten = true;
    auditInBackground(ctx, async () => {
      for (const orgId of orgIds) await write(orgId);
    });
    return;
  }
  const now = Date.now();
  let wrote = false;
  for (const orgId of orgIds) {
    if (throttledSessionRefusal(`${orgId}\n${userId}\n${input.code}`, now)) {
      wrote = true; // already on record for this window — the request still counts as audited
      continue;
    }
    if (await write(orgId)) wrote = true;
  }
  if (wrote) auditStashOf(ctx).refusalWritten = true;
}

// Alpha Bros enterprise layer — sign-in refusal audit rows.
//
// `auditRefusal()` is what a real `hooks.before` handler calls right before
// it throws a policy refusal (`SSO_REQUIRED`, `METHOD_NOT_ALLOWED`,
// `TWO_FACTOR_REQUIRED`, …) on a sign-in path. It exists because better-auth
// does not run `hooks.after` when a `hooks.before` handler throws, so the
// audit plugin's after-hook — which does observe endpoint `APIError`s,
// including the ones thrown from `databaseHooks` inside the endpoint —
// never sees those refusals and the log would show nothing for them.
//
// De-duplication rule: only `hooks.before` handlers call this, never the
// `databaseHooks.session.create.before` backstop (whose throw the after-hook
// *does* observe and classifies by code). A handler that wrote a row flags
// it on the request's audit stash so the after-hook does not write a second
// one if the refusal somehow reaches it anyway.
//
// This module is the typed contract; the write itself is not implemented
// yet — the current body logs at debug and returns, so the enforcement hooks
// can wire the call now and the audit plugin can fill it in with the
// `chainKey`-aware writer when its resolver is rebuilt.

import type { GenericEndpointContext } from "better-auth";

/** Per-request scratch the audit after-hook consults before writing. */
export interface EnterpriseAuditStash {
  /** Set once a `hooks.before` handler already wrote the refusal row for this request. */
  refusalWritten?: boolean;
}

export interface RefusalInput {
  /** Request path the refusal was raised on (`/magic-link/verify`, …). */
  path: string;
  /** The policy error code being thrown (`SSO_REQUIRED`, …). */
  code: string;
  /** The orgs whose policy produced the refusal — one row per org, when written. */
  orgIds: readonly string[];
  /** Known user, if the request resolved one; `null` for a pre-auth refusal of an unknown address. */
  userId?: string | null;
  /** The address the sign-in was for, when known. */
  email?: string | null;
  /** The classified sign-in method, when known. */
  method?: string | null;
  metadata?: Record<string, unknown>;
}

/**
 * Records a policy refusal on a sign-in path. Never throws — a failure to
 * audit must not turn a refusal into a success — and must be awaited
 * *before* the caller throws its `APIError`.
 */
export async function auditRefusal(
  ctx: GenericEndpointContext,
  input: RefusalInput,
): Promise<void> {
  ctx.context.logger.debug(
    `enterprise-audit: sign-in refusal ${input.code} on ${input.path} for orgs [${input.orgIds.join(", ")}] (refusal rows not yet written by this build)`,
  );
}

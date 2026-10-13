// Alpha Bros enterprise layer — audit rows written off the response path.
//
// A failed, refused or 2FA-pending sign-in, and a magic-link or
// password-reset request, are about an address the caller chose. How many
// rows they produce depends on whether that address has an account and how
// many organizations it belongs to, so writing them before the response
// would let response time tell a caller whether an address has an account —
// which better-auth itself equalises on these paths. They are therefore
// always handed to better-auth's `runInBackground`, whatever the product
// configures: `advanced.backgroundTasks.handler` when the product sets one
// (e.g. `waitUntil` on a serverless host), else a detached promise.
//
// A detached promise can be cut short when a serverless runtime freezes the
// instance after the response; products on such hosts set
// `advanced.backgroundTasks` (docs/security.md, "Audit log coverage").
// `flushAuditWrites()` waits for the ones still running in this process —
// for graceful shutdown and for tests.

import type { GenericEndpointContext } from "better-auth";

const inflight = new Set<Promise<void>>();

/**
 * Runs `task` off the response path through `ctx.context.runInBackground`.
 * Never throws and never rejects: a failure is logged (audit writes on these
 * paths are soft).
 */
export function auditInBackground(ctx: GenericEndpointContext, task: () => Promise<void>): void {
  const logger = ctx.context.logger;
  const settled: Promise<void> = Promise.resolve()
    .then(task)
    .catch((err: unknown) => {
      logger.error("enterprise-audit: failed to write a background audit row", err);
    })
    .finally(() => {
      inflight.delete(settled);
    });
  inflight.add(settled);
  try {
    ctx.context.runInBackground(settled);
  } catch (err) {
    // A product handler that throws must not turn into a failed request;
    // the task is already running and tracked.
    logger.error("enterprise-audit: advanced.backgroundTasks.handler threw", err);
  }
}

/** Resolves once every audit row this process handed to the background has been written (or failed). */
export async function flushAuditWrites(): Promise<void> {
  while (inflight.size > 0) {
    await Promise.allSettled([...inflight]);
  }
}

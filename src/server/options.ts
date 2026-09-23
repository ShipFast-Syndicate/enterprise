// Alpha Bros enterprise layer — `EnterpriseOptions` validation.
//
// One place every entry point calls, so a misconfiguration fails at
// construction time rather than at the first request that happens to depend
// on it. Called from `enterprisePreset` (`./preset.ts`) *and* from
// `enterpriseGate` (`./gate.ts`) — a product that hand-composes the plugin
// list instead of using the preset still gets the checks, since the gate is
// the one plugin the rest of the layer cannot work without
// (`requireFeature` reads its `options` back off the auth context).

import type { EnterpriseOptions } from "./types";
import { assertSecretsKey } from "./secrets";

/**
 * Validates the options that are load-bearing for security or for data
 * retention:
 *
 * - `secretsKey` — `>= 32` characters (L-08); it derives the AES-256-GCM key
 *   that encrypts IdP secrets at rest (C-04), so a short or missing key is a
 *   silent downgrade of that protection.
 * - `audit.retentionDays` — at least 1. `0` or a negative value puts the
 *   retention cutoff at or after "now", so the very next
 *   `GET /enterprise/audit/list` would compact the org's entire chain down to
 *   a single anchor row — a total, irreversible loss of the compliance log
 *   from a typo.
 * - `audit.exportMaxRows` — at least 1, since the export cap is compared
 *   against a row count.
 */
export function assertEnterpriseOptions(opts: EnterpriseOptions): void {
  assertSecretsKey(opts.secretsKey);
  if (
    typeof opts.scimCredentialHashSecret !== "string" ||
    opts.scimCredentialHashSecret.length < 32 ||
    opts.scimCredentialHashSecret === opts.secretsKey
  ) {
    throw new Error(
      "scimCredentialHashSecret must be an independent secret of at least 32 characters",
    );
  }

  const retentionDays = opts.audit?.retentionDays;
  if (retentionDays !== undefined && (!Number.isFinite(retentionDays) || retentionDays < 1)) {
    throw new Error(
      `@alphabros/enterprise: "audit.retentionDays" must be a finite number >= 1 (got ${String(retentionDays)}) — a smaller value would compact an organization's entire audit chain on the next read.`,
    );
  }

  const exportMaxRows = opts.audit?.exportMaxRows;
  if (exportMaxRows !== undefined && (!Number.isFinite(exportMaxRows) || exportMaxRows < 1)) {
    throw new Error(
      `@alphabros/enterprise: "audit.exportMaxRows" must be a finite number >= 1 (got ${String(exportMaxRows)}).`,
    );
  }
}

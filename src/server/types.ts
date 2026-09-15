// Alpha Bros enterprise layer — shared server-side types.
//
// `Feature` is the entitlement vocabulary the gate plugin (`./gate.ts`) and
// `requireFeature` (`./entitlements.ts`) speak. `EnterpriseOptions` is the
// single config object every consumer (preset, gate, and — in later tasks —
// the audit/policy/scimGroups plugins) is constructed from.

import type { sso } from "@better-auth/sso";

export type Feature = "sso" | "scim" | "audit_log" | "enforce_2fa" | "api_keys" | "teams";

export type ResolveEntitlements = (orgId: string) => Promise<Iterable<Feature>>;

export interface EnterpriseOptions {
  /** Product slug this deployment belongs to, e.g. "klar". */
  product: string;
  /** Resolves the set of features an org is entitled to (billing/plan lookup). */
  resolveEntitlements: ResolveEntitlements;
  samlSpKeys?: { cert: string; privateKey: string };
  /** Symmetric key used to encrypt stored secrets. Must be >= 32 chars. */
  secretsKey: string;
  /** Audit log retention. @default retentionDays 365 */
  audit?: { retentionDays?: number };
  /** SCIM Groups behavior. @default groupRoleMap {} */
  scim?: { groupRoleMap?: Record<string, "owner" | "admin" | "member"> };
  /**
   * Forwarded verbatim to `sso()` in the preset (`./preset.ts`) so callers
   * configure JIT user provisioning in one place.
   */
  provisionUser?: NonNullable<Parameters<typeof sso>[0]>["provisionUser"];
}

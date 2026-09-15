// Alpha Bros enterprise layer — server entry point.

export type { Feature, ResolveEntitlements, EnterpriseOptions } from "./types";
export { FeatureNotEntitledError, requireFeature } from "./entitlements";
export { enterpriseGate, GATED_PATHS } from "./gate";
export { enterprisePreset } from "./preset";
export { auditLog, AUDITED_PATHS } from "./audit/plugin";
export {
  canonical,
  hashRow,
  verifyChain,
  writeAudit,
  type AuditInput,
  type AuditRow,
  type AuditRowForHash,
} from "./audit/chain";

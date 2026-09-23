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
export { orgPolicy, getPolicyPreconditions, type OrgPolicy } from "./policy/plugin";
export { findOrgByEmailDomain, HOME_REALM_PATH } from "./policy/home-realm";
export { enterpriseScim, scimMembershipSchema } from "./scim";
export {
  parseFilter,
  applyGroupPatch,
  effectiveRole,
  scimError,
  ScimHttpError,
  type ScimGroupResource,
  type PatchOp,
} from "./scim-groups/scim";
export { enterpriseApi } from "./enterprise-api/plugin";

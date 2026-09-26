// Alpha Bros enterprise layer — server entry point.

export type { Feature, ResolveEntitlements, EnterpriseOptions } from "./types";
export { FeatureNotEntitledError, requireFeature } from "./entitlements";
export { enterpriseGate, GATED_PATHS } from "./gate";
export { enterprisePreset, API_KEY_LIFECYCLE_PLUGIN_ID } from "./preset";
export { auditLog, AUDITED_PATHS } from "./audit/plugin";
export {
  canonical,
  hashRow,
  isKeyedHash,
  KEYED_HASH_PREFIX,
  verifyChain,
  writeAudit,
  type AuditInput,
  type AuditRow,
  type AuditRowForHash,
  type ChainWriteOptions,
  type VerifyFailureReason,
  type VerifyResult,
} from "./audit/chain";
export { orgPolicy, getPolicyPreconditions, type OrgPolicy } from "./policy/plugin";
export { getEffectivePolicy, type EffectivePolicy } from "./policy/store";
export {
  findOrgByEmailDomain,
  findOrgsByEmailDomain,
  HOME_REALM_PATH,
  type EmailDomainMatch,
} from "./policy/home-realm";
export { normalizeProviderDomains, domainMatches, emailDomain } from "./policy/domains";
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

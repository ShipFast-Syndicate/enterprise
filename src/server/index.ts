// Alpha Bros enterprise layer — server entry point.

export type { Feature, ResolveEntitlements, EnterpriseOptions } from "./types";
export { FeatureNotEntitledError, requireFeature } from "./entitlements";
export { enterpriseGate, GATED_PATHS } from "./gate";
export { enterprisePreset } from "./preset";
export {
  API_KEY_ALLOWED_PATHS,
  API_KEY_ERROR,
  API_KEY_HEADERS,
  API_KEY_LIFECYCLE_PLUGIN_ID,
  apiKeyLifecycle,
  assertNotApiKeyRequest,
  enterpriseApiKeyValidator,
  isApiKeyAllowedPath,
  isApiKeyRefusedPath,
  isApiKeyVerifyCall,
  isServerOnlyPath,
  SERVER_ONLY_PATHS,
  revokeUserApiKeys,
  type ApiKeyRevocationActor,
  type ApiKeyRevocationContext,
} from "./api-keys";
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

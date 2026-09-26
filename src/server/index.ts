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
  API_KEY_STANDING_PLUGIN_ID,
  apiKeyLifecycle,
  apiKeyOwnerTwoFactorStanding,
  apiKeySessionStanding,
  assertNotApiKeyRequest,
  enterpriseApiKeyValidator,
  isApiKeyAllowedPath,
  isApiKeyRefusedPath,
  isApiKeyVerifyCall,
  isServerOnlyCall,
  isServerOnlyPath,
  SERVER_ONLY_PATHS,
  revokeUserApiKeys,
  type ApiKeyRevocationActor,
  type ApiKeyRevocationContext,
} from "./api-keys";
export {
  auditLog,
  AUDITED_PATHS,
  POLICY_REFUSAL_CODES,
  SELF_AUDITED_PATHS,
  UNAUDITED_PATHS,
  UNAUDITED_SERVER_ONLY_ENDPOINTS,
  sessionActor,
  type AuditActor,
  type AuditedPath,
  type AuditScope,
} from "./audit/plugin";
export { flushAuditWrites } from "./audit/background";
export {
  auditRefusal,
  SESSION_REFUSED_ACTION,
  SIGN_IN_REFUSED_ACTION,
  type RefusalInput,
} from "./audit/refusal";
export {
  auditChainKeyOf,
  canonical,
  hashRow,
  isKeyedHash,
  KEYED_HASH_PREFIX,
  readChainHead,
  signChainHead,
  verifyChain,
  verifyChainHeadSignature,
  writeAudit,
  type AuditActorType,
  type AuditInput,
  type AuditRow,
  type AuditRowForHash,
  type ChainHead,
  type ChainWriteOptions,
  type VerifyFailureReason,
  type VerifyResult,
} from "./audit/chain";
export { orgPolicy, getPolicyPreconditions, type OrgPolicy } from "./policy/plugin";
export {
  getEffectivePolicy,
  twoFactorEnrollmentState,
  type EffectivePolicy,
  type TwoFactorEnrollmentState,
} from "./policy/store";
export {
  DEFAULT_TWO_FACTOR_SATISFIED_BY,
  TWO_FACTOR_ENROLLMENT_ALLOWED_PATHS,
  twoFactorEnrollmentAllowedPaths,
} from "./policy/enforcement";
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

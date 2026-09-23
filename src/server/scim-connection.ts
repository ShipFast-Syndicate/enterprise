import type { SCIMManagedConnection } from "@better-auth/scim";

/** Portal label is bound to the provisioning domain in the immutable catalog correlation. */
export function scimConnectionLabel(connection: SCIMManagedConnection): string {
  try {
    const parts: unknown = JSON.parse(connection.creationRequestId);
    if (
      Array.isArray(parts) &&
      parts[0] === "enterprise" &&
      parts[1] === connection.provisioningDomainId &&
      typeof parts[2] === "string"
    )
      return parts[2];
  } catch {
    /* External server-created connections use their opaque connection ID. */
  }
  return connection.connectionId;
}

// Alpha Bros enterprise layer — admin portal entry point (Task 10).
//
// Registers every `<ab-*>` element this package defines so far (Tasks
// 11-12 add `ab-sso-wizard`/`ab-scim-tokens`/`ab-security-policy`/
// `ab-api-keys`/`ab-audit-log` alongside their own `customElements.define`
// call here) and re-exports the classes/types a consumer might want
// directly (e.g. `PortalError` to catch/inspect a failed mutation itself,
// rather than only ever seeing this package's own rendered error UI).
//
// `define()` guards every registration against a double `customElements.
// define` for the same tag name — importing this module twice (e.g. once
// directly, once transitively through another `@alphabros/enterprise/*`
// import) would otherwise throw `NotSupportedError: this name has already
// been used with this registry`.

import { AbMembers } from "./ab-members";
import { AbSecuritySettings } from "./ab-security-settings";

function define(name: string, ctor: CustomElementConstructor): void {
  if (!customElements.get(name)) {
    customElements.define(name, ctor);
  }
}

define("ab-members", AbMembers);
define("ab-security-settings", AbSecuritySettings);

export { AbElement } from "./base";
export { PortalApi, PortalError, type PortalErrorShape } from "./api";
export { AbMembers } from "./ab-members";
export { AbSecuritySettings } from "./ab-security-settings";

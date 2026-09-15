// Alpha Bros enterprise layer — admin portal entry point (Task 10; the
// Task 11 elements' own `define()` calls were added here alongside them —
// Task 12 adds the remaining three).
//
// Registers every `<ab-*>` element this package defines and re-exports the
// classes/types a consumer might want directly (e.g. `PortalError` to
// catch/inspect a failed mutation itself, rather than only ever seeing this
// package's own rendered error UI).
//
// `define()` guards every registration against a double `customElements.
// define` for the same tag name — importing this module twice (e.g. once
// directly, once transitively through another `@alphabros/enterprise/*`
// import) would otherwise throw `NotSupportedError: this name has already
// been used with this registry`.

import { AbMembers } from "./ab-members";
import { AbSecuritySettings } from "./ab-security-settings";
import { AbSsoWizard } from "./ab-sso-wizard";
import { AbScimTokens } from "./ab-scim-tokens";

function define(name: string, ctor: CustomElementConstructor): void {
  if (!customElements.get(name)) {
    customElements.define(name, ctor);
  }
}

define("ab-members", AbMembers);
define("ab-security-settings", AbSecuritySettings);
define("ab-sso-wizard", AbSsoWizard);
define("ab-scim-tokens", AbScimTokens);

export { AbElement } from "./base";
export { PortalApi, PortalError, type PortalErrorShape } from "./api";
export { AbMembers } from "./ab-members";
export { AbSecuritySettings } from "./ab-security-settings";
export { AbSsoWizard, type WizardStep } from "./ab-sso-wizard";
export { AbScimTokens } from "./ab-scim-tokens";

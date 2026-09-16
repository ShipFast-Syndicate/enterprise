// Alpha Bros enterprise layer — `<ab-security-settings>` (Task 10).
//
// The portal's tab shell: fetches `GET /enterprise/features` (the org's
// entitled feature set — `../server/enterprise-api/plugin.ts`'s
// `buildFeaturesEndpoint`, session + membership only, never gated) and
// renders a `role="tablist"` over the `tabs` attribute's comma list
// (default every tab this package knows about). A tab whose mapped
// `Feature` (`../server/types.ts`) is absent from the response renders
// locked (`aria-disabled`, a lock marker, disabled button) — `members` has
// no mapped feature and is never locked, matching `../server/gate.ts`'s
// `GATED_PATHS` (`/enterprise/members` is deliberately absent there).
//
// The selected tab's child element is looked up by tag name in
// `TAB_ELEMENTS` and stamped via `lit/static-html.js`'s `unsafeStatic` —
// `ab-sso-wizard`/`ab-scim-tokens`/`ab-security-policy`/`ab-api-keys`/
// `ab-audit-log` (Tasks 11-12, `./ab-sso-wizard.ts` etc.) were built after
// this file; stamping them by tag name rather than importing their classes
// directly (an un-upgraded custom element is a completely inert, harmless
// DOM node until its class is registered) is exactly what let this shell
// ship ahead of them, per the task brief. `unsafeStatic`'s input here is
// always one of `TAB_ELEMENTS`'s own literal values, never anything derived
// from user input, so there's no injection concern despite the name.
//
// Keyboard tab navigation (Left/Right arrows) and the `aria-controls`/
// `role="tabpanel"`/`aria-labelledby` wiring between each tab button and
// the panel below were added alongside the Task 11/12 elements, per that
// batch's controller ruling (g) — an accessibility minor deferred from
// Task 10, not part of that task's original scope.

import { html, css, type TemplateResult } from "lit";
import { html as staticHtml, unsafeStatic } from "lit/static-html.js";
import { AbElement } from "./base";

interface FeaturesResponse {
  features: string[];
}

const DEFAULT_TABS = "members,sso,scim,policy,api-keys,audit";

const TAB_LABELS: Record<string, string> = {
  members: "Members",
  sso: "SSO",
  scim: "SCIM",
  policy: "Security policy",
  "api-keys": "API keys",
  audit: "Audit log",
};

/** Tab id -> `Feature` (`../server/types.ts`) it requires. `undefined` = never locked. */
const TAB_FEATURES: Record<string, string | undefined> = {
  members: undefined,
  sso: "sso",
  scim: "scim",
  policy: "enforce_2fa",
  "api-keys": "api_keys",
  audit: "audit_log",
};

/** Tab id -> the `<ab-*>` element it renders. */
const TAB_ELEMENTS: Record<string, string> = {
  members: "ab-members",
  sso: "ab-sso-wizard",
  scim: "ab-scim-tokens",
  policy: "ab-security-policy",
  "api-keys": "ab-api-keys",
  audit: "ab-audit-log",
};

export class AbSecuritySettings extends AbElement {
  static properties = {
    ...AbElement.properties,
    tabs: { type: String },
    features: { state: true },
    loading: { state: true },
    error: { state: true },
    selected: { state: true },
  };

  /** Comma-separated tab list. @default "members,sso,scim,policy,api-keys,audit" */
  declare tabs: string;
  declare features: Set<string>;
  declare loading: boolean;
  declare error: unknown;
  declare selected: string;

  static styles = [
    AbElement.baseStyles,
    css`
      [role="tablist"] {
        display: flex;
        gap: var(--ab-space-2);
      }
      button[role="tab"] {
        background: var(--ab-color-surface);
        color: var(--ab-color-text);
      }
      button[role="tab"][aria-selected="true"] {
        background: var(--ab-color-primary);
        color: var(--ab-color-on-primary);
      }
      button[role="tab"][aria-disabled="true"] {
        border-color: var(--ab-color-border);
      }
      .ab-lock {
        margin-left: var(--ab-space-1);
      }
      .ab-panel {
        margin-top: var(--ab-space-4);
        box-shadow: var(--ab-shadow);
      }
    `,
  ];

  constructor() {
    super();
    this.tabs = DEFAULT_TABS;
    this.features = new Set();
    this.loading = true;
    this.error = undefined;
    this.selected = "";
  }

  override connectedCallback(): void {
    super.connectedCallback();
    void this.load();
  }

  private get tabList(): string[] {
    return this.tabs
      .split(",")
      .map((t) => t.trim())
      .filter(Boolean);
  }

  private isLocked(tab: string): boolean {
    const feature = TAB_FEATURES[tab];
    if (!feature) return false;
    return !this.features.has(feature);
  }

  private async load(): Promise<void> {
    this.loading = true;
    this.error = undefined;
    try {
      const data = await this.api.get<FeaturesResponse>("/enterprise/features", {
        orgId: this.orgId,
      });
      this.features = new Set(data.features);
      if (!this.selected) {
        const tabs = this.tabList;
        this.selected = tabs.find((t) => !this.isLocked(t)) ?? tabs[0] ?? "";
      }
    } catch (e) {
      this.error = e;
    } finally {
      this.loading = false;
    }
  }

  private selectTab(tab: string): void {
    if (this.isLocked(tab)) return;
    this.selected = tab;
  }

  /**
   * Left/Right arrow key navigation across the tablist (ruling (g),
   * deferred from Task 10): wraps around, skips locked tabs, and moves
   * focus to the newly selected tab's button — matching the WAI-ARIA
   * Authoring Practices tab pattern.
   */
  private handleTabsKeydown(e: KeyboardEvent): void {
    if (e.key !== "ArrowRight" && e.key !== "ArrowLeft") return;
    const tabs = this.tabList;
    if (tabs.length === 0) return;
    e.preventDefault();
    const step = e.key === "ArrowRight" ? 1 : -1;
    const currentIndex = Math.max(tabs.indexOf(this.selected), 0);
    for (let i = 1; i <= tabs.length; i++) {
      const nextIndex = (((currentIndex + step * i) % tabs.length) + tabs.length) % tabs.length;
      const next = tabs[nextIndex]!;
      if (!this.isLocked(next)) {
        this.selected = next;
        void this.updateComplete.then(() => {
          this.shadowRoot?.querySelector<HTMLButtonElement>(`button[data-tab="${next}"]`)?.focus();
        });
        return;
      }
    }
  }

  private renderTabContent(tab: string): TemplateResult {
    const tag = TAB_ELEMENTS[tab];
    if (!tag) return html``;
    const tagName = unsafeStatic(tag);
    return staticHtml`<${tagName} org-id=${this.orgId} base-path=${this.basePath}></${tagName}>`;
  }

  override render(): TemplateResult {
    if (this.error) return this.renderError(this.error);
    if (this.loading) return this.renderLoading();

    const tabs = this.tabList;
    const selectedLocked = this.selected !== "" && this.isLocked(this.selected);

    return html`
      <div role="tablist" @keydown=${(e: KeyboardEvent) => this.handleTabsKeydown(e)}>
        ${tabs.map((t) => {
          const locked = this.isLocked(t);
          return html`
            <button
              type="button"
              role="tab"
              id="ab-tab-${t}"
              data-tab=${t}
              aria-selected=${t === this.selected ? "true" : "false"}
              aria-disabled=${locked ? "true" : "false"}
              aria-controls="ab-panel-${t}"
              tabindex=${t === this.selected ? "0" : "-1"}
              ?disabled=${locked}
              @click=${() => this.selectTab(t)}
            >
              ${TAB_LABELS[t] ?? t}${
                locked ? html`<span class="ab-lock" aria-hidden="true">🔒</span>` : ""
              }
            </button>
          `;
        })}
      </div>
      <div
        class="ab-panel"
        id="ab-panel-${this.selected}"
        role="tabpanel"
        aria-labelledby="ab-tab-${this.selected}"
        tabindex="0"
      >
        ${
          this.selected === ""
            ? ""
            : selectedLocked
              ? html`<p class="ab-muted">This feature is not included in your plan.</p>`
              : this.renderTabContent(this.selected)
        }
      </div>
    `;
  }
}

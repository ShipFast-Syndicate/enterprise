// Alpha Bros enterprise layer — admin portal base element (Task 10).
//
// `AbElement` is the one shared base every `<ab-*>` portal component
// extends: the `org-id`/`base-path` attributes every one of them needs, a
// `PortalApi` (`./api.ts`) instance scoped to `basePath`, the shared
// `baseStyles` theming primitives (buttons, host text/background — every
// value `var(--ab-*)`, per `./tokens.md`'s contract), and the
// `renderError`/`renderLoading`/`emitChange` helpers every component reuses
// rather than reimplementing its own error/loading UI and change-event
// wiring.
//
// No decorators (`tsconfig.json` has `experimentalDecorators: false`) and
// `useDefineForClassFields: false` — `static properties` + `declare` fields
// is the plain-JS-class Lit pattern that combination requires (decorator
// accessors, or `static properties` + real class fields under
// `useDefineForClassFields: true`, would each redefine the property and
// shadow Lit's own reactive accessor instead of using it — see Lit's
// "Avoiding issues with class fields" docs for the general hazard).

import { LitElement, css, html, type PropertyValues, type TemplateResult } from "lit";
import { PortalApi, PortalError } from "./api";

export class AbElement extends LitElement {
  static properties = {
    orgId: { type: String, attribute: "org-id" },
    basePath: { type: String, attribute: "base-path" },
  };

  /** The organization this component operates on. No default — every consumer must set it. */
  declare orgId: string;
  /** better-auth mount path. @default "/api/auth" — better-auth's own default mount path. */
  declare basePath: string;

  /** Scoped to `basePath`; rebuilt in `willUpdate` whenever `basePath` changes. */
  protected api: PortalApi;

  /**
   * Shared theming primitives every `<ab-*>` component composes into its own
   * `static styles` (e.g. `static styles = [AbElement.baseStyles, css\`...\`]`).
   * Every value below is `var(--ab-*)` with no fallback, per `./tokens.md`'s
   * contract (enforced by `test/portal/theming.test.ts`'s source scan) —
   * `display`/`cursor` are structural, not themed, and exempt from that scan.
   */
  protected static baseStyles = css`
    :host {
      display: block;
      font-family: var(--ab-font-family);
      font-size: var(--ab-font-size);
      color: var(--ab-color-text);
      background: var(--ab-color-bg);
    }
    button {
      font: inherit;
      background: var(--ab-color-primary);
      color: var(--ab-color-on-primary);
      border: var(--ab-border);
      border-radius: var(--ab-radius);
      padding: var(--ab-space-2) var(--ab-space-3);
      cursor: pointer;
    }
    button:disabled {
      opacity: 0.6;
      cursor: default;
    }
    .ab-muted {
      color: var(--ab-color-text-muted);
    }
    .ab-error {
      color: var(--ab-color-danger);
    }
    .ab-loading {
      color: var(--ab-color-text-muted);
    }
    .ab-copy-box {
      background: var(--ab-color-surface);
      border: var(--ab-border);
      border-radius: var(--ab-radius);
      padding: var(--ab-space-3);
    }
    .ab-copy-box code {
      font: inherit;
      word-break: break-all;
    }
  `;

  /**
   * Shared table primitives (`<ab-members>`, `<ab-scim-tokens>`,
   * `<ab-api-keys>`, `<ab-audit-log>` each compose this into their own
   * `static styles` array alongside `baseStyles`) — every one of them
   * rendered an identical `table`/`th`/`td` block before this was factored
   * out.
   */
  protected static tableStyles = css`
    table {
      width: 100%;
      border-collapse: collapse;
    }
    th,
    td {
      text-align: left;
      padding: var(--ab-space-2);
    }
  `;

  constructor() {
    super();
    this.orgId = "";
    this.basePath = "/api/auth";
    this.api = new PortalApi(this.basePath);
  }

  protected override willUpdate(changed: PropertyValues): void {
    super.willUpdate(changed);
    if (changed.has("basePath")) {
      this.api = new PortalApi(this.basePath);
    }
  }

  /** A minimal, consistent loading indicator every component can render while its first fetch is in flight. */
  protected renderLoading(): TemplateResult {
    return html`<p class="ab-loading" role="status">Loading…</p>`;
  }

  /**
   * Maps a caught error to a `TemplateResult`. `PortalError`'s
   * `FEATURE_NOT_ENTITLED` code (thrown for a 403 from a gated
   * `/enterprise/*` endpoint — see `../server/entitlements.ts`) renders a
   * `not-entitled` slot so the embedding product can override the default
   * upsell copy; every other error renders its own message.
   */
  protected renderError(e: unknown): TemplateResult {
    if (e instanceof PortalError && e.code === "FEATURE_NOT_ENTITLED") {
      return html`
        <slot name="not-entitled">
          <p class="ab-error">This feature is not included in your plan</p>
        </slot>
      `;
    }
    const message =
      e instanceof PortalError
        ? e.message
        : e instanceof Error
          ? e.message
          : "Something went wrong.";
    return html`<p class="ab-error" role="alert">${message}</p>`;
  }

  /**
   * The inner content of a "shown once" secret copy box — `<ab-scim-tokens>`'s
   * SCIM token and `<ab-api-keys>`'s raw API key are each returned exactly
   * once by their create endpoint and never persisted, so both render this
   * same message + label/value pair inside their own `.ab-copy-box` (styled
   * by `baseStyles` above) wrapper. `extra` renders between the message and
   * the value line for a caller that needs another field shown alongside it
   * (e.g. SCIM's `baseUrl`, or API keys' `name`) — the caller still owns the
   * surrounding `.ab-copy-box` `<div>` and its own "Done" button, since both
   * of those differ per component (SCIM re-fetches tokens, API keys
   * re-fetches keys).
   */
  protected renderShownOnce(label: string, value: string, extra?: TemplateResult): TemplateResult {
    return html`
      <p>This ${label} is shown once. Store it securely.</p>
      ${extra ?? ""}
      <p><strong>${label}:</strong> <code>${value}</code></p>
    `;
  }

  /** Dispatches a bubbling, composed `ab-change` `CustomEvent` — every mutating component fires this after each write. */
  protected emitChange(detail?: unknown): void {
    this.dispatchEvent(new CustomEvent("ab-change", { detail, bubbles: true, composed: true }));
  }
}

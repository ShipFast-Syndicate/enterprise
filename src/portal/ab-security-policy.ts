// Alpha Bros enterprise layer — `<ab-security-policy>` (Task 12).
//
// A form bound to `GET`/`POST /enterprise/policy` (`../server/policy/
// plugin.ts`, `OrgPolicy` shape from `../server/policy/store.ts`).
// Deliberately never touches `ssoEnforced`/`breakGlassUserId` — those are
// `<ab-sso-wizard>`'s `enforce` step's job (Task 11); this component only
// ever reads them back from the loaded policy (so a diff against them stays
// a no-op) and never renders a control for either. On submit, only fields
// that actually differ from the last-loaded policy are sent — never the
// full record — since `POST /enterprise/policy/set` treats every field as
// an independent partial update (`patch.x ?? current.x` in `plugin.ts`) and
// sending an unchanged field back is functionally harmless but would make
// this component's own tests (and any audit-log reader) unable to tell
// which field an admin actually touched.

import { html, css, type TemplateResult } from "lit";
import { AbElement } from "./base";

type Role = "owner" | "admin" | "member";

interface OrgPolicy {
  orgId: string;
  require2fa: boolean;
  ssoEnforced: boolean;
  breakGlassUserId: string | null;
  sessionMaxAgeS: number | null;
  allowedMethods: string[];
  groupRoleMap: Record<string, Role>;
}

/** The closed set of sign-in methods `allowedMethods` may name (spec order). */
const ALLOWED_METHODS = [
  "sso",
  "magic_link",
  "password",
  "passkey",
  "google",
  "github",
  "linkedin",
  "microsoft",
] as const;

const ROLES: Role[] = ["owner", "admin", "member"];

const SESSION_MAX_AGE_OPTIONS: Array<{ label: string; value: number | null }> = [
  { label: "Off (use the default)", value: null },
  { label: "1 hour", value: 3600 },
  { label: "8 hours", value: 28800 },
  { label: "24 hours", value: 86400 },
  { label: "7 days", value: 604800 },
];

function sortedJson(value: unknown): string {
  if (Array.isArray(value)) return JSON.stringify([...value].sort());
  if (value && typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>).sort(([a], [b]) =>
      a.localeCompare(b),
    );
    return JSON.stringify(entries);
  }
  return JSON.stringify(value);
}

export class AbSecurityPolicy extends AbElement {
  static properties = {
    ...AbElement.properties,
    loading: { state: true },
    error: { state: true },
    submitError: { state: true },
    noChangesMessage: { state: true },
    policy: { state: true },
    require2fa: { state: true },
    sessionMaxAgeS: { state: true },
    allowedMethods: { state: true },
    groupRoleMap: { state: true },
    newRowName: { state: true },
    newRowRole: { state: true },
  };

  declare loading: boolean;
  /** Fatal load error — replaces the whole view (`./base.ts`'s `renderError`). */
  declare error: unknown;
  /** Inline save error — rendered within the form, load state untouched. */
  declare submitError: unknown;
  /** Set instead of `submitError` when a submit's diff against `policy` is empty — a no-op, not a failure. */
  declare noChangesMessage: string | undefined;
  /** The last-loaded policy — the diff baseline for the next submit. */
  declare policy: OrgPolicy | null;
  declare require2fa: boolean;
  declare sessionMaxAgeS: number | null;
  declare allowedMethods: Set<string>;
  declare groupRoleMap: Record<string, Role>;
  declare newRowName: string;
  declare newRowRole: Role;

  static styles = [
    AbElement.baseStyles,
    css`
      form {
        display: flex;
        flex-direction: column;
        gap: var(--ab-space-3);
      }
      fieldset {
        border: var(--ab-border);
        border-radius: var(--ab-radius);
        padding: var(--ab-space-3);
      }
      .ab-methods {
        display: flex;
        flex-wrap: wrap;
        gap: var(--ab-space-2);
      }
      table {
        width: 100%;
        border-collapse: collapse;
      }
      th,
      td {
        text-align: left;
        padding: var(--ab-space-2);
      }
      .ab-row-add {
        display: flex;
        gap: var(--ab-space-2);
      }
    `,
  ];

  constructor() {
    super();
    this.loading = true;
    this.error = undefined;
    this.submitError = undefined;
    this.noChangesMessage = undefined;
    this.policy = null;
    this.require2fa = false;
    this.sessionMaxAgeS = null;
    this.allowedMethods = new Set();
    this.groupRoleMap = {};
    this.newRowName = "";
    this.newRowRole = "member";
  }

  override connectedCallback(): void {
    super.connectedCallback();
    void this.load();
  }

  private applyPolicy(policy: OrgPolicy): void {
    this.policy = policy;
    this.require2fa = policy.require2fa;
    this.sessionMaxAgeS = policy.sessionMaxAgeS;
    this.allowedMethods = new Set(policy.allowedMethods);
    this.groupRoleMap = { ...policy.groupRoleMap };
  }

  private async load(): Promise<void> {
    this.loading = true;
    this.error = undefined;
    try {
      const data = await this.api.get<OrgPolicy>("/enterprise/policy", { orgId: this.orgId });
      this.applyPolicy(data);
    } catch (e) {
      this.error = e;
    } finally {
      this.loading = false;
    }
  }

  private toggleMethod(method: string, checked: boolean): void {
    const next = new Set(this.allowedMethods);
    if (checked) next.add(method);
    else next.delete(method);
    this.allowedMethods = next;
  }

  private addGroupRow(): void {
    const name = this.newRowName.trim();
    if (!name || name in this.groupRoleMap) return;
    this.groupRoleMap = { ...this.groupRoleMap, [name]: this.newRowRole };
    this.newRowName = "";
    this.newRowRole = "member";
  }

  private removeGroupRow(name: string): void {
    const next = { ...this.groupRoleMap };
    delete next[name];
    this.groupRoleMap = next;
  }

  private changeGroupRole(name: string, role: Role): void {
    this.groupRoleMap = { ...this.groupRoleMap, [name]: role };
  }

  private buildPatch(): Record<string, unknown> {
    if (!this.policy) return {};
    const patch: Record<string, unknown> = {};
    if (this.require2fa !== this.policy.require2fa) patch.require2fa = this.require2fa;
    if (this.sessionMaxAgeS !== this.policy.sessionMaxAgeS) {
      patch.sessionMaxAgeS = this.sessionMaxAgeS;
    }
    const nextMethods = [...this.allowedMethods];
    if (sortedJson(nextMethods) !== sortedJson(this.policy.allowedMethods)) {
      patch.allowedMethods = nextMethods;
    }
    if (sortedJson(this.groupRoleMap) !== sortedJson(this.policy.groupRoleMap)) {
      patch.groupRoleMap = this.groupRoleMap;
    }
    return patch;
  }

  private async handleSubmit(e: SubmitEvent): Promise<void> {
    e.preventDefault();
    this.noChangesMessage = undefined;
    const patch = this.buildPatch();
    if (Object.keys(patch).length === 0) {
      this.noChangesMessage = "Nothing to save.";
      return;
    }
    this.submitError = undefined;
    try {
      await this.api.post("/enterprise/policy/set", { orgId: this.orgId, ...patch });
      await this.load();
      this.emitChange({ type: "policy-updated", patch });
    } catch (e) {
      this.submitError = e;
    }
  }

  override render(): TemplateResult {
    if (this.error) return this.renderError(this.error);
    if (this.loading) return this.renderLoading();

    return html`
      <form @submit=${(e: SubmitEvent) => void this.handleSubmit(e)}>
        <label>
          <input
            type="checkbox"
            name="require2fa"
            .checked=${this.require2fa}
            @change=${(e: Event) => (this.require2fa = (e.target as HTMLInputElement).checked)}
          />
          Require two-factor authentication
        </label>

        <label>
          Session max age
          <select
            name="sessionMaxAgeS"
            @change=${(e: Event) => {
              const raw = (e.target as HTMLSelectElement).value;
              this.sessionMaxAgeS = raw === "" ? null : Number(raw);
            }}
          >
            ${SESSION_MAX_AGE_OPTIONS.map(
              (opt) => html`
                <option value=${opt.value ?? ""} ?selected=${opt.value === this.sessionMaxAgeS}>
                  ${opt.label}
                </option>
              `,
            )}
          </select>
        </label>

        <fieldset>
          <legend>Allowed sign-in methods</legend>
          <div class="ab-methods">
            ${ALLOWED_METHODS.map(
              (method) => html`
                <label>
                  <input
                    type="checkbox"
                    name="allowedMethods"
                    value=${method}
                    .checked=${this.allowedMethods.has(method)}
                    @change=${(e: Event) =>
                      this.toggleMethod(method, (e.target as HTMLInputElement).checked)}
                  />
                  ${method}
                </label>
              `,
            )}
          </div>
        </fieldset>

        <fieldset>
          <legend>Group → role mapping</legend>
          <table>
            <thead>
              <tr>
                <th>Group</th>
                <th>Role</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              ${Object.entries(this.groupRoleMap).map(
                ([name, role]) => html`
                  <tr>
                    <td>${name}</td>
                    <td>
                      <select
                        @change=${(e: Event) =>
                          this.changeGroupRole(name, (e.target as HTMLSelectElement).value as Role)}
                      >
                        ${ROLES.map(
                          (r) => html`<option value=${r} ?selected=${r === role}>${r}</option>`,
                        )}
                      </select>
                    </td>
                    <td>
                      <button type="button" @click=${() => this.removeGroupRow(name)}>
                        Remove
                      </button>
                    </td>
                  </tr>
                `,
              )}
            </tbody>
          </table>
          <div class="ab-row-add">
            <input
              placeholder="Group display name"
              .value=${this.newRowName}
              @input=${(e: Event) => (this.newRowName = (e.target as HTMLInputElement).value)}
            />
            <select
              .value=${this.newRowRole}
              @change=${(e: Event) => (this.newRowRole = (e.target as HTMLSelectElement).value as Role)}
            >
              ${ROLES.map((r) => html`<option value=${r}>${r}</option>`)}
            </select>
            <button type="button" @click=${() => this.addGroupRow()}>Add</button>
          </div>
        </fieldset>

        ${this.submitError ? this.renderError(this.submitError) : ""}
        ${this.noChangesMessage ? html`<p class="ab-muted">${this.noChangesMessage}</p>` : ""}
        <button type="submit">Save changes</button>
      </form>
    `;
  }
}

// Alpha Bros enterprise layer — `<ab-scim-tokens>` (Task 11).
//
// SCIM provisioning token lifecycle: `GET /enterprise/scim/tokens` (list —
// `providerId` only, `createdAt`/`lastUsedAt` always `null` in v0.1, see
// `../server/enterprise-api/scim.ts`'s header comment), `POST .../create`
// (returns the token once — never persisted or re-fetchable, so it's held
// only in `newToken` state until the admin dismisses the copy box), and
// `POST .../revoke` behind `confirm` (same stubbable-confirm pattern as
// `./ab-members.ts`).

import { html, css, type TemplateResult } from "lit";
import { AbElement } from "./base";

interface ScimToken {
  providerId: string;
  createdAt: string | null;
  lastUsedAt: string | null;
}

interface TokensResponse {
  tokens: ScimToken[];
}

interface NewToken {
  providerId: string;
  scimToken: string;
  baseUrl: string;
}

export class AbScimTokens extends AbElement {
  static properties = {
    ...AbElement.properties,
    tokens: { state: true },
    loading: { state: true },
    loadError: { state: true },
    submitError: { state: true },
    newToken: { state: true },
  };

  declare tokens: ScimToken[];
  declare loading: boolean;
  /** Fatal load error — replaces the whole view (`./base.ts`'s `renderError`). */
  declare loadError: unknown;
  /** Inline mutation error (create/revoke) — rendered above the table/form; the loaded token list is left untouched. */
  declare submitError: unknown;
  declare newToken: NewToken | null;

  /** Confirmation gate before revoking a token. @default window.confirm */
  confirm: (message?: string) => boolean = (message) => window.confirm(message);

  static styles = [
    AbElement.baseStyles,
    AbElement.tableStyles,
    css`
      form {
        display: flex;
        gap: var(--ab-space-2);
        margin-top: var(--ab-space-4);
      }
    `,
  ];

  constructor() {
    super();
    this.tokens = [];
    this.loading = true;
    this.loadError = undefined;
    this.submitError = undefined;
    this.newToken = null;
  }

  override connectedCallback(): void {
    super.connectedCallback();
    void this.load();
  }

  private async load(): Promise<void> {
    this.loading = true;
    this.loadError = undefined;
    try {
      const data = await this.api.get<TokensResponse>("/enterprise/scim/tokens", {
        orgId: this.orgId,
      });
      this.tokens = data.tokens ?? [];
    } catch (e) {
      this.loadError = e;
    } finally {
      this.loading = false;
    }
  }

  private async handleCreate(e: SubmitEvent): Promise<void> {
    e.preventDefault();
    const form = e.currentTarget as HTMLFormElement;
    const providerId = String(new FormData(form).get("providerId") ?? "").trim();
    if (!providerId) return;
    this.submitError = undefined;
    try {
      const data = await this.api.post<{ scimToken: string; baseUrl: string }>(
        "/enterprise/scim/tokens/create",
        { orgId: this.orgId, providerId },
      );
      this.newToken = { providerId, scimToken: data.scimToken, baseUrl: data.baseUrl };
      this.emitChange({ type: "scim-token-created", providerId });
    } catch (e) {
      this.submitError = e;
    }
  }

  private handleDone(): void {
    this.newToken = null;
    void this.load();
  }

  private async handleRevoke(token: ScimToken): Promise<void> {
    const ok = this.confirm(`Revoke the SCIM token for provider "${token.providerId}"?`);
    if (!ok) return;
    this.submitError = undefined;
    try {
      await this.api.post("/enterprise/scim/tokens/revoke", {
        orgId: this.orgId,
        providerId: token.providerId,
      });
      await this.load();
      this.emitChange({ type: "scim-token-revoked", providerId: token.providerId });
    } catch (e) {
      this.submitError = e;
    }
  }

  private defaultProviderId(): string {
    return `scim-${this.orgId}`;
  }

  override render(): TemplateResult {
    if (this.loadError) return this.renderError(this.loadError);
    if (this.loading) return this.renderLoading();

    if (this.newToken) {
      return html`
        <div class="ab-copy-box">
          ${this.renderShownOnce(
            "Token",
            this.newToken.scimToken,
            html`<p><strong>Base URL:</strong> <code>${this.newToken.baseUrl}</code></p>`,
          )}
          <button type="button" @click=${() => this.handleDone()}>Done</button>
        </div>
      `;
    }

    return html`
      ${this.submitError ? this.renderError(this.submitError) : ""}
      <table>
        <thead>
          <tr>
            <th>Provider id</th>
            <th>Created</th>
            <th>Last used</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          ${this.tokens.map(
            (t) => html`
              <tr>
                <td>${t.providerId}</td>
                <td>${t.createdAt ?? "—"}</td>
                <td>${t.lastUsedAt ?? "—"}</td>
                <td>
                  <button type="button" @click=${() => void this.handleRevoke(t)}>Revoke</button>
                </td>
              </tr>
            `,
          )}
        </tbody>
      </table>
      ${this.tokens.length === 0 ? html`<p class="ab-muted">No SCIM tokens yet.</p>` : ""}
      <form @submit=${(e: SubmitEvent) => void this.handleCreate(e)}>
        <input name="providerId" .value=${this.defaultProviderId()} required />
        <button type="submit">Create token</button>
      </form>
    `;
  }
}

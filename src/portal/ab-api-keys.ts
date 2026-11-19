// Alpha Bros enterprise layer — `<ab-api-keys>` (Task 12).
//
// Thin admin UI over the upstream `@better-auth/api-key` plugin's own
// endpoints (`GET /api-key/list`, `POST /api-key/create`, `POST
// /api-key/delete` — exact fields per `node_modules/@better-auth/api-key/
// dist/index.mjs`), not one of this package's own `/enterprise/*` wrappers
// — there isn't one, since the preset mounts `apiKey()` with its default
// (per-user, not per-org) `references` option, so no `organizationId` is
// sent on any of the three calls. The created key's raw value is returned
// exactly once by `/api-key/create` and never persisted anywhere — held
// only in `newKey` state until the admin dismisses the copy box, same
// pattern as `./ab-scim-tokens.ts`'s token-shown-once flow.

import { html, css, type TemplateResult } from "lit";
import { AbElement } from "./base";
import type { MessageKey } from "./i18n";

interface ApiKey {
  id: string;
  name: string | null;
  start: string | null;
  prefix: string | null;
  enabled: boolean;
  createdAt: string;
  expiresAt: string | null;
}

interface ListResponse {
  apiKeys: ApiKey[];
  total: number;
}

interface NewKey {
  id: string;
  name: string | null;
  key: string;
}

/**
 * `expiresIn` select options, in seconds; the first entry is the form's
 * default. `""` omits `expiresIn` from the POST body entirely, which leaves
 * the lifetime to the server's own default (`apiKeys.defaultExpiresInS`, 90
 * days unless the product changed it) — never "no expiry" any more.
 */
const EXPIRES_IN_OPTIONS: Array<{ label: MessageKey; value: number | "" }> = [
  { label: "apiKeys.expires.90d", value: 90 * 24 * 60 * 60 },
  { label: "apiKeys.expires.30d", value: 30 * 24 * 60 * 60 },
  { label: "apiKeys.expires.1y", value: 365 * 24 * 60 * 60 },
  { label: "apiKeys.expires.default", value: "" },
];

export class AbApiKeys extends AbElement {
  static properties = {
    ...AbElement.properties,
    keys: { state: true },
    loading: { state: true },
    loadError: { state: true },
    submitError: { state: true },
    newKey: { state: true },
  };

  declare keys: ApiKey[];
  declare loading: boolean;
  /** Fatal load error — replaces the whole view (`./base.ts`'s `renderError`). */
  declare loadError: unknown;
  /** Inline mutation error (create/delete) — rendered above the table/form; the loaded key list is left untouched. */
  declare submitError: unknown;
  declare newKey: NewKey | null;

  /** Confirmation gate before deleting a key. @default window.confirm */
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
    this.keys = [];
    this.loading = true;
    this.loadError = undefined;
    this.submitError = undefined;
    this.newKey = null;
  }

  override connectedCallback(): void {
    super.connectedCallback();
    void this.load();
  }

  private async load(): Promise<void> {
    this.loading = true;
    this.loadError = undefined;
    try {
      const data = await this.api.get<ListResponse>("/api-key/list");
      this.keys = data.apiKeys ?? [];
    } catch (e) {
      this.loadError = e;
    } finally {
      this.loading = false;
    }
  }

  private async handleCreate(e: SubmitEvent): Promise<void> {
    e.preventDefault();
    const form = e.currentTarget as HTMLFormElement;
    const data = new FormData(form);
    const name = String(data.get("name") ?? "").trim();
    const expiresInRaw = String(data.get("expiresIn") ?? "");
    const body: Record<string, unknown> = {};
    if (name) body.name = name;
    if (expiresInRaw) body.expiresIn = Number(expiresInRaw);
    this.submitError = undefined;
    try {
      const created = await this.api.post<{ id: string; name: string | null; key: string }>(
        "/api-key/create",
        body,
      );
      this.newKey = { id: created.id, name: created.name, key: created.key };
      this.emitChange({ type: "api-key-created", id: created.id });
    } catch (e) {
      this.submitError = e;
    }
  }

  private handleDone(): void {
    this.newKey = null;
    void this.load();
  }

  private async handleDelete(key: ApiKey): Promise<void> {
    const ok = this.confirm(this.t("apiKeys.confirmDelete", { name: key.name ?? key.id }));
    if (!ok) return;
    this.submitError = undefined;
    try {
      await this.api.post("/api-key/delete", { keyId: key.id });
      await this.load();
      this.emitChange({ type: "api-key-deleted", id: key.id });
    } catch (e) {
      this.submitError = e;
    }
  }

  override render(): TemplateResult {
    if (this.loadError) return this.renderError(this.loadError);
    if (this.loading) return this.renderLoading();

    if (this.newKey) {
      return html`
        <div class="ab-copy-box">
          ${this.renderShownOnce(
            this.t("apiKeys.shownOnce"),
            this.t("apiKeys.keyLabel"),
            this.newKey.key,
            html`<p><strong>${this.t("apiKeys.nameLabel")}</strong> ${this.newKey.name ?? "—"}</p>`,
          )}
          <button type="button" @click=${() => this.handleDone()}>${this.t("common.done")}</button>
        </div>
      `;
    }

    return html`
      ${this.submitError ? this.renderError(this.submitError) : ""}
      <table>
        <thead>
          <tr>
            <th>${this.t("apiKeys.col.name")}</th>
            <th>${this.t("apiKeys.col.prefix")}</th>
            <th>${this.t("apiKeys.col.created")}</th>
            <th>${this.t("apiKeys.col.expires")}</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          ${this.keys.map(
            (k) => html`
              <tr>
                <td>${k.name ?? "—"}</td>
                <td>${k.start ?? k.prefix ?? "—"}</td>
                <td>${k.createdAt}</td>
                <td>${k.expiresAt ?? this.t("apiKeys.never")}</td>
                <td>
                  <button type="button" @click=${() => void this.handleDelete(k)}>
                    ${this.t("apiKeys.delete")}
                  </button>
                </td>
              </tr>
            `,
          )}
        </tbody>
      </table>
      ${this.keys.length === 0 ? html`<p class="ab-muted">${this.t("apiKeys.noKeys")}</p>` : ""}
      <form @submit=${(e: SubmitEvent) => void this.handleCreate(e)}>
        <input name="name" placeholder=${this.t("apiKeys.name")} />
        <select name="expiresIn">
          ${EXPIRES_IN_OPTIONS.map(
            (opt) => html`<option value=${opt.value}>${this.t(opt.label)}</option>`,
          )}
        </select>
        <button type="submit">${this.t("apiKeys.create")}</button>
      </form>
    `;
  }
}

// Alpha Bros enterprise layer — `<ab-audit-log>` (Task 12).
//
// `GET /enterprise/audit/list` (filtered, cursor-paginated — `../server/
// audit/plugin.ts`), a plain `<a download>` to `GET /enterprise/audit/
// export` carrying the same filters (a CSV download, not a `fetch` —
// letting the browser's own navigation carry the session cookie and honor
// the server's `content-disposition` filename), and `GET /enterprise/audit/
// verify` for the hash-chain integrity badge.

import { html, css, type TemplateResult } from "lit";
import { AbElement } from "./base";

interface AuditEvent {
  id: string;
  seq: number;
  createdAt: string;
  actorType: string;
  actorId: string | null;
  action: string;
  targetType: string;
  targetId: string | null;
}

interface ListResponse {
  items: AuditEvent[];
  nextCursor: string | null;
}

interface VerifyResponse {
  ok: boolean;
  brokenAtSeq?: number;
}

interface Filters {
  action: string;
  actorId: string;
  from: string;
  to: string;
}

const EMPTY_FILTERS: Filters = { action: "", actorId: "", from: "", to: "" };

function toEpochMs(dateValue: string): string | undefined {
  if (!dateValue) return undefined;
  const ms = Date.parse(dateValue);
  return Number.isNaN(ms) ? undefined : String(ms);
}

export class AbAuditLog extends AbElement {
  static properties = {
    ...AbElement.properties,
    items: { state: true },
    nextCursor: { state: true },
    loading: { state: true },
    loadingMore: { state: true },
    error: { state: true },
    filters: { state: true },
    verifyResult: { state: true },
    verifying: { state: true },
  };

  declare items: AuditEvent[];
  declare nextCursor: string | null;
  declare loading: boolean;
  declare loadingMore: boolean;
  declare error: unknown;
  declare filters: Filters;
  declare verifyResult: VerifyResponse | null;
  declare verifying: boolean;

  static styles = [
    AbElement.baseStyles,
    css`
      table {
        width: 100%;
        border-collapse: collapse;
      }
      th,
      td {
        text-align: left;
        padding: var(--ab-space-2);
      }
      form {
        display: flex;
        flex-wrap: wrap;
        gap: var(--ab-space-2);
        margin-bottom: var(--ab-space-3);
      }
      .ab-toolbar {
        display: flex;
        gap: var(--ab-space-2);
        align-items: center;
        margin-top: var(--ab-space-3);
      }
      .ab-badge-ok {
        color: var(--ab-color-success);
      }
      .ab-badge-broken {
        color: var(--ab-color-danger);
      }
      a[download] {
        color: var(--ab-color-primary);
      }
    `,
  ];

  constructor() {
    super();
    this.items = [];
    this.nextCursor = null;
    this.loading = true;
    this.loadingMore = false;
    this.error = undefined;
    this.filters = { ...EMPTY_FILTERS };
    this.verifyResult = null;
    this.verifying = false;
  }

  override connectedCallback(): void {
    super.connectedCallback();
    void this.load(true);
  }

  private queryFromFilters(): Record<string, string | undefined> {
    return {
      orgId: this.orgId,
      action: this.filters.action || undefined,
      actorId: this.filters.actorId || undefined,
      from: toEpochMs(this.filters.from),
      to: toEpochMs(this.filters.to),
    };
  }

  private async load(reset: boolean): Promise<void> {
    if (reset) {
      this.loading = true;
      this.error = undefined;
    } else {
      this.loadingMore = true;
    }
    try {
      const query = this.queryFromFilters();
      if (!reset && this.nextCursor) query.cursor = this.nextCursor;
      const data = await this.api.get<ListResponse>("/enterprise/audit/list", query);
      this.items = reset ? (data.items ?? []) : [...this.items, ...(data.items ?? [])];
      this.nextCursor = data.nextCursor ?? null;
    } catch (e) {
      this.error = e;
    } finally {
      this.loading = false;
      this.loadingMore = false;
    }
  }

  private handleFilterSubmit(e: SubmitEvent): void {
    e.preventDefault();
    const form = e.currentTarget as HTMLFormElement;
    const data = new FormData(form);
    this.filters = {
      action: String(data.get("action") ?? ""),
      actorId: String(data.get("actorId") ?? "").trim(),
      from: String(data.get("from") ?? ""),
      to: String(data.get("to") ?? ""),
    };
    void this.load(true);
  }

  private async handleVerify(): Promise<void> {
    this.verifying = true;
    try {
      this.verifyResult = await this.api.get<VerifyResponse>("/enterprise/audit/verify", {
        orgId: this.orgId,
      });
    } catch (e) {
      this.error = e;
    } finally {
      this.verifying = false;
    }
  }

  private get exportHref(): string {
    const query = this.queryFromFilters();
    const params = new URLSearchParams();
    for (const [key, value] of Object.entries(query)) {
      if (value !== undefined) params.set(key, value);
    }
    return `${this.basePath}/enterprise/audit/export?${params.toString()}`;
  }

  private get knownActions(): string[] {
    return [...new Set(this.items.map((i) => i.action))].sort();
  }

  override render(): TemplateResult {
    if (this.error) return this.renderError(this.error);
    if (this.loading) return this.renderLoading();

    return html`
      <form @submit=${(e: SubmitEvent) => this.handleFilterSubmit(e)}>
        <select name="action">
          <option value="">All actions</option>
          ${this.knownActions.map(
            (a) => html`<option value=${a} ?selected=${a === this.filters.action}>${a}</option>`,
          )}
        </select>
        <input name="actorId" placeholder="Actor id" .value=${this.filters.actorId} />
        <input name="from" type="date" .value=${this.filters.from} />
        <input name="to" type="date" .value=${this.filters.to} />
        <button type="submit">Filter</button>
      </form>

      <table>
        <thead>
          <tr>
            <th>Time</th>
            <th>Actor</th>
            <th>Action</th>
            <th>Target</th>
          </tr>
        </thead>
        <tbody>
          ${this.items.map(
            (i) => html`
              <tr>
                <td>${i.createdAt}</td>
                <td>${i.actorId ?? i.actorType}</td>
                <td>${i.action}</td>
                <td>${i.targetType}${i.targetId ? `:${i.targetId}` : ""}</td>
              </tr>
            `,
          )}
        </tbody>
      </table>
      ${this.items.length === 0 ? html`<p class="ab-muted">No audit events.</p>` : ""}

      <div class="ab-toolbar">
        ${
          this.nextCursor
            ? html`
                <button
                  type="button"
                  ?disabled=${this.loadingMore}
                  @click=${() => void this.load(false)}
                >
                  Load more
                </button>
              `
            : ""
        }
        <a href=${this.exportHref} download>Export CSV</a>
        <button type="button" ?disabled=${this.verifying} @click=${() => void this.handleVerify()}>
          Verify chain
        </button>
        ${
          this.verifyResult
            ? this.verifyResult.ok
              ? html`<span class="ab-badge-ok">Chain intact</span>`
              : html`<span class="ab-badge-broken"
                  >Broken at seq ${this.verifyResult.brokenAtSeq}</span
                >`
            : ""
        }
      </div>
    `;
  }
}

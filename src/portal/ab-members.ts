// Alpha Bros enterprise layer — `<ab-members>` (Task 10).
//
// Org roster + pending invitations, backed by `GET /enterprise/members`
// (`../server/enterprise-api/members.ts` — session + membership only, never
// gated). Every mutation goes straight to the *upstream* better-auth
// `organization` plugin endpoints (`/organization/invite-member`,
// `/organization/update-member-role`, `/organization/remove-member` —
// exact body shapes confirmed against `node_modules/better-auth/dist/
// plugins/organization/routes/crud-members.mjs` and exercised in
// `test/server/enterprise-api.test.ts`), not through this package's own
// `/enterprise/*` wrappers — there isn't one for member management, `GET
// /enterprise/members` is a read-model built for this component, not a
// full CRUD wrapper. After every mutation: re-fetch (so the row reflects
// whatever the server actually persisted, not an optimistic guess) then
// `emitChange` (`../base.ts`) so an embedding page can react (e.g. refresh
// a seat count elsewhere on screen).

import { html, css, type TemplateResult } from "lit";
import { AbElement } from "./base";

interface Member {
  id: string;
  userId: string;
  email: string | null;
  name: string | null;
  role: string;
  teams: string[];
}

interface Invitation {
  id: string;
  email: string;
  role: string | null;
  status: string;
  expiresAt: string;
}

interface MembersResponse {
  members: Member[];
  invitations: Invitation[];
}

/** Roles offered on both the per-row role select and the invite form. */
const ROLES = ["member", "admin", "owner"];

export class AbMembers extends AbElement {
  static properties = {
    ...AbElement.properties,
    members: { state: true },
    invitations: { state: true },
    loading: { state: true },
    error: { state: true },
  };

  declare members: Member[];
  declare invitations: Invitation[];
  declare loading: boolean;
  declare error: unknown;

  /**
   * Confirmation gate before `/organization/remove-member` is called.
   * Defaults to `window.confirm`; a test (or an embedder wanting a custom
   * dialog) can replace this with any `(message?) => boolean`.
   */
  confirm: (message?: string) => boolean = (message) => window.confirm(message);

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
        gap: var(--ab-space-2);
        margin-top: var(--ab-space-4);
      }
      .ab-invitations {
        margin-top: var(--ab-space-4);
      }
      .ab-status-accepted {
        color: var(--ab-color-success);
      }
    `,
  ];

  constructor() {
    super();
    this.members = [];
    this.invitations = [];
    this.loading = true;
    this.error = undefined;
  }

  override connectedCallback(): void {
    super.connectedCallback();
    void this.load();
  }

  private async load(): Promise<void> {
    this.loading = true;
    this.error = undefined;
    try {
      const data = await this.api.get<MembersResponse>("/enterprise/members", {
        orgId: this.orgId,
      });
      this.members = data.members ?? [];
      this.invitations = data.invitations ?? [];
    } catch (e) {
      this.error = e;
    } finally {
      this.loading = false;
    }
  }

  private async handleInvite(e: SubmitEvent): Promise<void> {
    e.preventDefault();
    const form = e.currentTarget as HTMLFormElement;
    const data = new FormData(form);
    const email = String(data.get("email") ?? "").trim();
    const role = String(data.get("role") ?? "member");
    if (!email) return;
    try {
      await this.api.post("/organization/invite-member", {
        email,
        role,
        organizationId: this.orgId,
      });
      form.reset();
      await this.load();
      this.emitChange({ type: "invite", email, role });
    } catch (e) {
      this.error = e;
    }
  }

  private async handleRoleChange(member: Member, e: Event): Promise<void> {
    const role = (e.target as HTMLSelectElement).value;
    try {
      await this.api.post("/organization/update-member-role", {
        memberId: member.id,
        role,
        organizationId: this.orgId,
      });
      await this.load();
      this.emitChange({ type: "role", memberId: member.id, role });
    } catch (e) {
      this.error = e;
    }
  }

  private async handleRemove(member: Member): Promise<void> {
    const ok = this.confirm(`Remove ${member.email ?? member.userId} from this organization?`);
    if (!ok) return;
    try {
      await this.api.post("/organization/remove-member", {
        memberIdOrEmail: member.id,
        organizationId: this.orgId,
      });
      await this.load();
      this.emitChange({ type: "remove", memberId: member.id });
    } catch (e) {
      this.error = e;
    }
  }

  override render(): TemplateResult {
    if (this.error) return this.renderError(this.error);
    if (this.loading) return this.renderLoading();

    return html`
      <table>
        <thead>
          <tr>
            <th>Email</th>
            <th>Name</th>
            <th>Role</th>
            <th>Teams</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          ${this.members.map(
            (m) => html`
              <tr>
                <td>${m.email ?? m.userId}</td>
                <td>${m.name ?? ""}</td>
                <td>
                  <select @change=${(e: Event) => void this.handleRoleChange(m, e)}>
                    ${ROLES.map(
                      (r) => html`<option value=${r} ?selected=${r === m.role}>${r}</option>`,
                    )}
                  </select>
                </td>
                <td>${m.teams.join(", ")}</td>
                <td>
                  <button type="button" @click=${() => void this.handleRemove(m)}>Remove</button>
                </td>
              </tr>
            `,
          )}
        </tbody>
      </table>

      <div class="ab-invitations">
        <h3>Pending invitations</h3>
        ${
          this.invitations.length === 0
            ? html`<p class="ab-muted">No pending invitations.</p>`
            : html`
                <ul>
                  ${this.invitations.map(
                    (i) => html`
                      <li class=${i.status === "accepted" ? "ab-status-accepted" : ""}>
                        ${i.email} — ${i.role ?? "member"} (${i.status})
                      </li>
                    `,
                  )}
                </ul>
              `
        }
      </div>

      <form @submit=${(e: SubmitEvent) => void this.handleInvite(e)}>
        <input type="email" name="email" placeholder="email@example.com" required />
        <select name="role">
          ${ROLES.map((r) => html`<option value=${r}>${r}</option>`)}
        </select>
        <button type="submit">Invite</button>
      </form>
    `;
  }
}

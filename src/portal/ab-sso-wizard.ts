// Alpha Bros enterprise layer — `<ab-sso-wizard>` (Task 11).
//
// A one-`step` state machine walking an org admin through registering an
// SSO provider end to end: `choose` (SAML metadata paste or OIDC issuer +
// client id/secret) → `register` (`POST /enterprise/sso/register`, a
// transient in-flight step) → `verify-domain` (shows the TXT record from
// `GET /enterprise/sso/providers`'s `verificationRecord`, "Check DNS" ->
// `POST /sso/verify-domain`, auto-polled every `pollIntervalMs` up to
// `maxPollMs`) → `test-login` (opens `POST /enterprise/sso/test-login/
// start`'s `url` via the overridable `openWindow`, then either a `storage`
// event keyed `ab_sso_test` — written by the finish redirect's landing page,
// out of this component's scope — or "I completed the test" re-fetches
// providers and reads `testLoginPassedAt`) → `enforce` (toggle ->
// `POST /enterprise/policy/set { ssoEnforced, breakGlassUserId }`, defaulted
// to the signed-in admin's own id via `GET /get-session`, disabled until
// `testLoginPassedAt` is set) → `done`.
//
// `/sso/verify-domain` is called directly against upstream (not one of this
// package's own `/enterprise/*` wrappers — there isn't one), and succeeds
// with a bare `204 No Content` (`node_modules/@better-auth/sso/dist/
// index.mjs`'s `verifyDomain`) — `PortalApi.post`'s unconditional
// `res.json()` would throw on that empty body, so this file's own
// `postAllowingEmptyBody` mirrors the empty-body tolerance `../server/
// enterprise-api/forward.ts`'s `forwardJson` already relies on
// (`res.json().catch(() => null)`) rather than reaching into `./api.ts` to
// change every caller's contract for one endpoint.
//
// Per the controller ruling: raw error diagnostics (status/code, not just
// `.message`) are shown only in the `test-login` step — every other step
// uses `renderError` (`./base.ts`), same as every other portal component.

import { html, css, type TemplateResult } from "lit";
import { AbElement } from "./base";
import { PortalError } from "./api";

export type WizardStep =
  "choose" | "register" | "verify-domain" | "test-login" | "enforce" | "done";

interface SsoProvider {
  providerId: string;
  type: "oidc" | "saml";
  issuer: string;
  domain: string;
  domainVerified: boolean;
  verificationRecord: { name: string; value: string | null };
  spMetadataUrl: string;
  acsUrl: string;
  redirectUri: string;
  testLoginPassedAt: string | null;
  enforced: boolean;
}

interface ProvidersResponse {
  providers: SsoProvider[];
}

interface SessionResponse {
  user: { id: string } | null;
}

/** `POST`, tolerating a `204`/empty-body success response — see header comment. */
async function postAllowingEmptyBody(basePath: string, path: string, body: unknown): Promise<void> {
  const res = await fetch(`${basePath}${path}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    credentials: "include",
    body: JSON.stringify(body),
  });
  if (res.ok) return;
  const parsed = (await res.json().catch(() => null)) as { code?: string; message?: string } | null;
  throw new PortalError({
    status: res.status,
    code: parsed?.code,
    message: parsed?.message ?? `Request failed with status ${res.status}`,
  });
}

function resolveStep(provider: SsoProvider | null): WizardStep {
  if (!provider) return "choose";
  if (!provider.domainVerified) return "verify-domain";
  if (!provider.testLoginPassedAt) return "test-login";
  if (!provider.enforced) return "enforce";
  return "done";
}

export class AbSsoWizard extends AbElement {
  static properties = {
    ...AbElement.properties,
    step: { state: true },
    loading: { state: true },
    error: { state: true },
    provider: { state: true },
    ssoType: { state: true },
    currentUserId: { state: true },
    breakGlassUserId: { state: true },
    testLoginError: { state: true },
    polling: { state: true },
  };

  declare step: WizardStep;
  declare loading: boolean;
  declare error: unknown;
  declare provider: SsoProvider | null;
  declare ssoType: "oidc" | "saml";
  declare currentUserId: string;
  declare breakGlassUserId: string;
  declare testLoginError: unknown;
  declare polling: boolean;

  /** Auto-poll interval for domain verification. @default 10000 (10s) */
  pollIntervalMs = 10000;
  /** Total time to auto-poll before giving up (manual "Check DNS" still works after). @default 300000 (5min) */
  maxPollMs = 300000;
  /** Opens the test-login URL. Defaults to `window.open`; overridable for tests/embedders. */
  openWindow: (url: string) => unknown = (url) => window.open(url, "_blank");

  private pollTimer: ReturnType<typeof setInterval> | null = null;
  private pollElapsedMs = 0;
  private readonly handleStorage = (e: StorageEvent): void => {
    if (e.key === "ab_sso_test") void this.checkTestLogin();
  };

  static styles = [
    AbElement.baseStyles,
    css`
      form {
        display: flex;
        flex-direction: column;
        gap: var(--ab-space-2);
      }
      .ab-record {
        background: var(--ab-color-surface);
        border: var(--ab-border);
        border-radius: var(--ab-radius);
        padding: var(--ab-space-3);
        margin: var(--ab-space-2) 0;
      }
      .ab-record code {
        font: inherit;
        word-break: break-all;
      }
      .ab-actions {
        display: flex;
        gap: var(--ab-space-2);
        margin-top: var(--ab-space-2);
      }
      .ab-diagnostic {
        color: var(--ab-color-danger);
        background: var(--ab-color-surface);
        border-radius: var(--ab-radius);
        padding: var(--ab-space-2);
      }
    `,
  ];

  constructor() {
    super();
    this.step = "choose";
    this.loading = true;
    this.error = undefined;
    this.provider = null;
    this.ssoType = "oidc";
    this.currentUserId = "";
    this.breakGlassUserId = "";
    this.testLoginError = undefined;
    this.polling = false;
  }

  override connectedCallback(): void {
    super.connectedCallback();
    window.addEventListener("storage", this.handleStorage);
    void this.initialLoad();
  }

  override disconnectedCallback(): void {
    super.disconnectedCallback();
    window.removeEventListener("storage", this.handleStorage);
    this.stopPolling();
  }

  private async fetchProviders(): Promise<void> {
    const data = await this.api.get<ProvidersResponse>("/enterprise/sso/providers", {
      orgId: this.orgId,
    });
    this.provider = data.providers?.[0] ?? null;
  }

  private async ensureCurrentUser(): Promise<void> {
    if (this.currentUserId) return;
    try {
      const session = await this.api.get<SessionResponse | null>("/get-session");
      this.currentUserId = session?.user?.id ?? "";
      if (!this.breakGlassUserId) this.breakGlassUserId = this.currentUserId;
    } catch {
      // Best-effort default only — the admin can still type an id in by hand.
    }
  }

  private async initialLoad(): Promise<void> {
    this.loading = true;
    this.error = undefined;
    try {
      await this.fetchProviders();
      this.step = resolveStep(this.provider);
      if (this.step === "verify-domain") this.startPolling();
      if (this.step === "enforce") await this.ensureCurrentUser();
    } catch (e) {
      this.error = e;
    } finally {
      this.loading = false;
    }
  }

  // --- choose / register -------------------------------------------------

  /** Reads an uploaded IdP metadata XML file into the `idpMetadata` textarea — an alternative to pasting it directly. */
  private async handleMetadataFile(e: Event): Promise<void> {
    const input = e.target as HTMLInputElement;
    const file = input.files?.[0];
    if (!file) return;
    const text = await file.text();
    const textarea = this.shadowRoot?.querySelector<HTMLTextAreaElement>(
      'textarea[name="idpMetadata"]',
    );
    if (textarea) textarea.value = text;
  }

  private async handleChooseSubmit(e: SubmitEvent): Promise<void> {
    e.preventDefault();
    const form = e.currentTarget as HTMLFormElement;
    const data = new FormData(form);
    const field = (name: string) => String(data.get(name) ?? "").trim();

    const body: Record<string, unknown> = {
      organizationId: this.orgId,
      providerId: field("providerId"),
      issuer: field("issuer"),
      domain: field("domain"),
    };
    if (this.ssoType === "oidc") {
      body.oidcConfig = { clientId: field("clientId"), clientSecret: field("clientSecret") };
    } else {
      const callbackUrl = field("callbackUrl");
      const entityId = field("spEntityId");
      body.samlConfig = {
        entryPoint: field("entryPoint"),
        cert: field("cert"),
        ...(callbackUrl ? { callbackUrl } : {}),
        idpMetadata: { metadata: field("idpMetadata") },
        ...(entityId ? { spMetadata: { entityID: entityId } } : {}),
      };
    }

    this.error = undefined;
    this.step = "register";
    try {
      await this.api.post("/enterprise/sso/register", body);
      await this.fetchProviders();
      this.step = "verify-domain";
      this.startPolling();
      this.emitChange({ type: "sso-register", providerId: body.providerId });
    } catch (e) {
      this.error = e;
      this.step = "choose";
    }
  }

  // --- verify-domain -------------------------------------------------------

  private startPolling(): void {
    this.stopPolling();
    this.pollElapsedMs = 0;
    this.polling = true;
    this.pollTimer = setInterval(() => {
      this.pollElapsedMs += this.pollIntervalMs;
      if (this.pollElapsedMs >= this.maxPollMs) {
        this.stopPolling();
        return;
      }
      void this.checkDns();
    }, this.pollIntervalMs);
  }

  private stopPolling(): void {
    if (this.pollTimer !== null) clearInterval(this.pollTimer);
    this.pollTimer = null;
    this.polling = false;
  }

  private async checkDns(): Promise<void> {
    if (!this.provider) return;
    this.error = undefined;
    try {
      await postAllowingEmptyBody(this.basePath, "/sso/verify-domain", {
        providerId: this.provider.providerId,
      });
      await this.fetchProviders();
      if (this.provider?.domainVerified) {
        this.stopPolling();
        this.step = "test-login";
      }
    } catch (e) {
      this.error = e;
    }
  }

  // --- test-login ----------------------------------------------------------

  private async startTestLogin(): Promise<void> {
    if (!this.provider) return;
    this.testLoginError = undefined;
    try {
      const { url } = await this.api.post<{ url: string }>("/enterprise/sso/test-login/start", {
        orgId: this.orgId,
        providerId: this.provider.providerId,
      });
      this.openWindow(url);
    } catch (e) {
      this.testLoginError = e;
    }
  }

  private async checkTestLogin(): Promise<void> {
    this.testLoginError = undefined;
    try {
      await this.fetchProviders();
      if (this.provider?.testLoginPassedAt) {
        await this.ensureCurrentUser();
        this.step = "enforce";
      } else {
        this.testLoginError = new Error(
          "Test login not detected yet. Complete sign-in in the opened window, then try again.",
        );
      }
    } catch (e) {
      this.testLoginError = e;
    }
  }

  // --- enforce ---------------------------------------------------------------

  private handleBreakGlassInput(e: Event): void {
    this.breakGlassUserId = (e.target as HTMLInputElement).value;
  }

  private async handleEnforce(): Promise<void> {
    this.error = undefined;
    try {
      await this.api.post("/enterprise/policy/set", {
        orgId: this.orgId,
        ssoEnforced: true,
        breakGlassUserId: this.breakGlassUserId,
      });
      this.step = "done";
      this.emitChange({ type: "sso-enforced" });
    } catch (e) {
      this.error = e;
    }
  }

  // --- render ----------------------------------------------------------------

  private renderChoose(): TemplateResult {
    return html`
      ${this.error ? this.renderError(this.error) : ""}
      <label>
        <input
          type="radio"
          name="ssoType"
          value="oidc"
          ?checked=${this.ssoType === "oidc"}
          @change=${() => (this.ssoType = "oidc")}
        />
        OIDC
      </label>
      <label>
        <input
          type="radio"
          name="ssoType"
          value="saml"
          ?checked=${this.ssoType === "saml"}
          @change=${() => (this.ssoType = "saml")}
        />
        SAML
      </label>
      <form @submit=${(e: SubmitEvent) => void this.handleChooseSubmit(e)}>
        <input name="providerId" placeholder="Provider id (e.g. okta)" required />
        <input name="issuer" placeholder="Issuer URL" required />
        <input name="domain" placeholder="Domain (e.g. acme.com)" required />
        ${
          this.ssoType === "oidc"
            ? html`
                <input name="clientId" placeholder="Client id" required />
                <input name="clientSecret" type="password" placeholder="Client secret" required />
              `
            : html`
                <input name="entryPoint" placeholder="SAML entry point URL" required />
                <textarea
                  name="cert"
                  placeholder="SAML signing certificate (PEM)"
                  required
                ></textarea>
                <textarea name="idpMetadata" placeholder="IdP metadata XML" required></textarea>
                <label>
                  or upload an IdP metadata XML file
                  <input
                    type="file"
                    accept=".xml,text/xml,application/xml"
                    @change=${(e: Event) => void this.handleMetadataFile(e)}
                  />
                </label>
                <input name="spEntityId" placeholder="SP entity id (optional)" />
                <input name="callbackUrl" placeholder="Callback URL (optional)" />
              `
        }
        <button type="submit">Register provider</button>
      </form>
    `;
  }

  private renderVerifyDomain(): TemplateResult {
    const record = this.provider?.verificationRecord;
    return html`
      ${this.error ? this.renderError(this.error) : ""}
      <p>Add this TXT record to your DNS to prove domain ownership:</p>
      <div class="ab-record">
        <p><strong>Name:</strong> <code>${record?.name ?? ""}</code></p>
        <p><strong>Value:</strong> <code>${record?.value ?? ""}</code></p>
      </div>
      <p class="ab-muted">
        ${this.polling ? "Checking automatically…" : "Automatic checking has stopped."}
      </p>
      <div class="ab-actions">
        <button type="button" @click=${() => void this.checkDns()}>Check DNS</button>
      </div>
    `;
  }

  private renderTestLogin(): TemplateResult {
    return html`
      ${
        this.testLoginError
          ? html`<p class="ab-diagnostic" role="alert">
              ${diagnosticMessage(this.testLoginError)}
            </p>`
          : ""
      }
      <p>Sign in through this provider once to confirm it works before enforcing it.</p>
      <div class="ab-actions">
        <button type="button" @click=${() => void this.startTestLogin()}>Start test login</button>
        <button type="button" @click=${() => void this.checkTestLogin()}>
          I completed the test
        </button>
      </div>
    `;
  }

  private renderEnforce(): TemplateResult {
    const enabled = !!this.provider?.testLoginPassedAt;
    return html`
      ${this.error ? this.renderError(this.error) : ""}
      <p class=${enabled ? "" : "ab-muted"}>
        ${enabled ? "Test login passed." : "Complete a test login before enforcing SSO."}
      </p>
      <label>
        Break-glass user id (keeps password sign-in for this owner)
        <input
          name="breakGlassUserId"
          .value=${this.breakGlassUserId}
          @input=${(e: Event) => this.handleBreakGlassInput(e)}
        />
      </label>
      <div class="ab-actions">
        <button
          type="button"
          data-testid="enforce-toggle"
          ?disabled=${!enabled}
          @click=${() => void this.handleEnforce()}
        >
          Enforce SSO for this organization
        </button>
      </div>
    `;
  }

  private renderDone(): TemplateResult {
    return html`<p>SSO is enforced for this organization.</p>`;
  }

  override render(): TemplateResult {
    if (this.loading) return this.renderLoading();
    switch (this.step) {
      case "choose":
        return this.renderChoose();
      case "register":
        return this.renderLoading();
      case "verify-domain":
        return this.renderVerifyDomain();
      case "test-login":
        return this.renderTestLogin();
      case "enforce":
        return this.renderEnforce();
      case "done":
        return this.renderDone();
    }
  }
}

/** Raw status+code+message diagnostic — `test-login` step only, per the controller ruling. */
function diagnosticMessage(e: unknown): string {
  if (e instanceof PortalError) {
    return `${e.status}${e.code ? ` ${e.code}` : ""}: ${e.message}`;
  }
  return e instanceof Error ? e.message : "Something went wrong.";
}

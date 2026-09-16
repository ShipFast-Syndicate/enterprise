// Alpha Bros enterprise layer — `<ab-sso-wizard>` (Task 11).
//
// Pure DOM tests against a mocked, URL-aware `globalThis.fetch`: each test
// drives the real custom element and asserts on the actual requests and
// rendered DOM, following `test/portal/members.test.ts`'s pattern. Polling
// tests use fake timers with `pollIntervalMs`/`maxPollMs` set low so a test
// never waits on the real 10s/5min defaults.

import { afterEach, describe, expect, it, vi } from "vitest";
import "../../src/portal/index";
import type { AbSsoWizard } from "../../src/portal/ab-sso-wizard";

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

function emptyResponse(status: number): Response {
  return new Response(null, { status });
}

function provider(overrides: Partial<Record<string, unknown>> = {}) {
  return {
    providerId: "okta",
    type: "oidc",
    issuer: "https://idp.test",
    domain: "acme.test",
    domainVerified: false,
    verificationRecord: { name: "_better-auth-token-okta.acme.test", value: "tok123" },
    spMetadataUrl: "https://app.test/api/auth/sso/saml2/sp/metadata?providerId=okta",
    acsUrl: "https://app.test/api/auth/sso/saml2/sp/acs/okta",
    redirectUri: "https://app.test/api/auth/sso/callback/okta",
    testLoginPassedAt: null,
    enforced: false,
    ...overrides,
  };
}

function makeEl(orgId = "org_1"): AbSsoWizard {
  const el = document.createElement("ab-sso-wizard") as AbSsoWizard;
  el.orgId = orgId;
  el.pollIntervalMs = 10;
  el.maxPollMs = 35;
  return el;
}

function routeJson(routes: Record<string, unknown>) {
  return vi.fn<typeof fetch>(async (input) => {
    const url = String(input);
    for (const [path, body] of Object.entries(routes)) {
      if (url.includes(path)) return jsonResponse(200, body);
    }
    throw new Error(`unmocked fetch: ${url}`);
  });
}

afterEach(() => {
  document.body.innerHTML = "";
  vi.unstubAllGlobals();
  vi.useRealTimers();
});

describe("<ab-sso-wizard>", () => {
  it("upgrades with a shadow root and starts on the choose step with no providers", async () => {
    vi.stubGlobal("fetch", routeJson({ "/enterprise/sso/providers": { providers: [] } }));
    const el = makeEl();
    document.body.appendChild(el);
    await vi.waitFor(() => expect(el.shadowRoot!.querySelector("form")).not.toBeNull());
    expect(el.step).toBe("choose");
  });

  it("resumes at verify-domain when a provider is already registered but unverified", async () => {
    // Large pollIntervalMs/maxPollMs — this test asserts the *resumed* step
    // and DNS record, not the auto-poll behavior (covered separately below).
    vi.stubGlobal("fetch", routeJson({ "/enterprise/sso/providers": { providers: [provider()] } }));
    const el = makeEl();
    el.pollIntervalMs = 10_000_000;
    document.body.appendChild(el);
    await vi.waitFor(() =>
      expect(el.shadowRoot!.textContent).toContain("_better-auth-token-okta.acme.test"),
    );
    expect(el.shadowRoot!.textContent).toContain("tok123");
    expect(el.step).toBe("verify-domain");
  });

  it("submitting the OIDC form registers, then advances to verify-domain", async () => {
    let registered = false;
    const fetchMock = vi.fn<typeof fetch>(async (input, init) => {
      const url = String(input);
      if (url.includes("/enterprise/sso/register")) {
        const body = JSON.parse((init as RequestInit).body as string);
        expect(body).toEqual({
          organizationId: "org_1",
          providerId: "okta",
          issuer: "https://idp.test",
          domain: "acme.test",
          oidcConfig: { clientId: "client-id", clientSecret: "secret" },
        });
        registered = true;
        return jsonResponse(200, { providerId: "okta" });
      }
      if (url.includes("/enterprise/sso/providers")) {
        return jsonResponse(200, {
          providers: registered ? [provider({ domainVerified: false })] : [],
        });
      }
      throw new Error(`unmocked fetch: ${url}`);
    });
    vi.stubGlobal("fetch", fetchMock);

    const el = makeEl();
    document.body.appendChild(el);
    await vi.waitFor(() => expect(el.shadowRoot!.querySelector("form")).not.toBeNull());

    const form = el.shadowRoot!.querySelector("form")!;
    form.querySelector<HTMLInputElement>('[name="providerId"]')!.value = "okta";
    form.querySelector<HTMLInputElement>('[name="issuer"]')!.value = "https://idp.test";
    form.querySelector<HTMLInputElement>('[name="domain"]')!.value = "acme.test";
    form.querySelector<HTMLInputElement>('[name="clientId"]')!.value = "client-id";
    form.querySelector<HTMLInputElement>('[name="clientSecret"]')!.value = "secret";
    form.dispatchEvent(new SubmitEvent("submit", { bubbles: true, cancelable: true }));

    await vi.waitFor(() => expect(el.step).toBe("verify-domain"));
    expect(fetchMock.mock.calls.some(([u]) => String(u).includes("/enterprise/sso/register"))).toBe(
      true,
    );
  });

  it("SAML: uploading an IdP metadata XML file fills the textarea, then registers with samlConfig", async () => {
    let registered = false;
    const fetchMock = vi.fn<typeof fetch>(async (input, init) => {
      const url = String(input);
      if (url.includes("/enterprise/sso/register")) {
        const body = JSON.parse((init as RequestInit).body as string);
        expect(body).toEqual({
          organizationId: "org_1",
          providerId: "okta-saml",
          issuer: "https://idp.test",
          domain: "acme.test",
          samlConfig: {
            entryPoint: "https://idp.test/sso",
            cert: "-----BEGIN CERTIFICATE-----",
            idpMetadata: { metadata: "<EntityDescriptor/>" },
          },
        });
        registered = true;
        return jsonResponse(200, { providerId: "okta-saml" });
      }
      if (url.includes("/enterprise/sso/providers")) {
        return jsonResponse(200, {
          providers: registered ? [provider({ domainVerified: false })] : [],
        });
      }
      throw new Error(`unmocked fetch: ${url}`);
    });
    vi.stubGlobal("fetch", fetchMock);

    const el = makeEl();
    document.body.appendChild(el);
    await vi.waitFor(() => expect(el.shadowRoot!.querySelector("form")).not.toBeNull());

    const samlRadio = el.shadowRoot!.querySelector<HTMLInputElement>('input[value="saml"]')!;
    samlRadio.click();
    await el.updateComplete;

    const form = el.shadowRoot!.querySelector("form")!;
    form.querySelector<HTMLInputElement>('[name="providerId"]')!.value = "okta-saml";
    form.querySelector<HTMLInputElement>('[name="issuer"]')!.value = "https://idp.test";
    form.querySelector<HTMLInputElement>('[name="domain"]')!.value = "acme.test";
    form.querySelector<HTMLInputElement>('[name="entryPoint"]')!.value = "https://idp.test/sso";
    form.querySelector<HTMLTextAreaElement>('[name="cert"]')!.value = "-----BEGIN CERTIFICATE-----";

    const fileInput = form.querySelector<HTMLInputElement>('input[type="file"]')!;
    const file = new File(["<EntityDescriptor/>"], "metadata.xml", { type: "text/xml" });
    Object.defineProperty(fileInput, "files", { value: [file] });
    fileInput.dispatchEvent(new Event("change", { bubbles: true }));

    await vi.waitFor(() =>
      expect(form.querySelector<HTMLTextAreaElement>('[name="idpMetadata"]')!.value).toBe(
        "<EntityDescriptor/>",
      ),
    );

    form.dispatchEvent(new SubmitEvent("submit", { bubbles: true, cancelable: true }));
    await vi.waitFor(() => expect(el.step).toBe("verify-domain"));
  });

  it("a failed register renders inline and stays on choose", async () => {
    const fetchMock = vi.fn<typeof fetch>(async (input) => {
      const url = String(input);
      if (url.includes("/enterprise/sso/register")) {
        return jsonResponse(422, { code: "PROVIDER_EXISTS", message: "Provider already exists" });
      }
      if (url.includes("/enterprise/sso/providers")) return jsonResponse(200, { providers: [] });
      throw new Error(`unmocked fetch: ${url}`);
    });
    vi.stubGlobal("fetch", fetchMock);

    const el = makeEl();
    document.body.appendChild(el);
    await vi.waitFor(() => expect(el.shadowRoot!.querySelector("form")).not.toBeNull());

    const form = el.shadowRoot!.querySelector("form")!;
    form.querySelector<HTMLInputElement>('[name="providerId"]')!.value = "okta";
    form.querySelector<HTMLInputElement>('[name="issuer"]')!.value = "https://idp.test";
    form.querySelector<HTMLInputElement>('[name="domain"]')!.value = "acme.test";
    form.querySelector<HTMLInputElement>('[name="clientId"]')!.value = "client-id";
    form.querySelector<HTMLInputElement>('[name="clientSecret"]')!.value = "secret";
    form.dispatchEvent(new SubmitEvent("submit", { bubbles: true, cancelable: true }));

    await vi.waitFor(() => expect(el.shadowRoot!.textContent).toContain("Provider already exists"));
    expect(el.step).toBe("choose");
  });

  it('"Check DNS" verifies the domain and advances to test-login on success', async () => {
    let verified = false;
    const fetchMock = vi.fn<typeof fetch>(async (input) => {
      const url = String(input);
      if (url.includes("/sso/verify-domain")) {
        verified = true;
        return emptyResponse(204);
      }
      if (url.includes("/enterprise/sso/providers")) {
        return jsonResponse(200, { providers: [provider({ domainVerified: verified })] });
      }
      throw new Error(`unmocked fetch: ${url}`);
    });
    vi.stubGlobal("fetch", fetchMock);

    const el = makeEl();
    el.pollIntervalMs = 10_000_000; // disable auto-poll interference — this test drives the manual button only
    document.body.appendChild(el);
    await vi.waitFor(() => expect(el.step).toBe("verify-domain"));

    const button = [...el.shadowRoot!.querySelectorAll("button")].find((b) =>
      b.textContent?.includes("Check DNS"),
    )!;
    button.click();

    await vi.waitFor(() => expect(el.step).toBe("test-login"));
    const [, init] = fetchMock.mock.calls.find(([u]) => String(u).includes("/sso/verify-domain"))!;
    expect(JSON.parse((init as RequestInit).body as string)).toEqual({ providerId: "okta" });
  });

  it("polls verify-domain automatically up to maxPollMs, then stops", async () => {
    vi.useFakeTimers();
    let calls = 0;
    const fetchMock = vi.fn<typeof fetch>(async (input) => {
      const url = String(input);
      if (url.includes("/sso/verify-domain")) {
        calls++;
        return emptyResponse(404);
      }
      if (url.includes("/enterprise/sso/providers")) {
        return jsonResponse(200, { providers: [provider({ domainVerified: false })] });
      }
      throw new Error(`unmocked fetch: ${url}`);
    });
    vi.stubGlobal("fetch", fetchMock);

    const el = makeEl();
    document.body.appendChild(el);
    await vi.waitFor(() => expect(el.step).toBe("verify-domain"));

    // pollIntervalMs=10, maxPollMs=35 -> ticks at 10/20/30 (3 polls), then stops before 40.
    await vi.advanceTimersByTimeAsync(100);
    expect(calls).toBe(3);
    await vi.advanceTimersByTimeAsync(1000);
    expect(calls).toBe(3);
  });

  // L-04 (security audit 2026-09-15): the default `openWindow` must pass
  // `noopener,noreferrer` — the page it opens is the org-registered IdP's own
  // authorization endpoint, and without it that page gets a live
  // `window.opener` handle on the admin portal tab (reverse tabnabbing).
  it("the default openWindow passes noopener,noreferrer", async () => {
    const el = document.createElement("ab-sso-wizard") as HTMLElement & {
      openWindow: (url: string) => unknown;
    };
    const spy = vi.spyOn(window, "open").mockReturnValue(null);
    el.openWindow("https://idp.test/authorize");
    expect(spy).toHaveBeenCalledWith("https://idp.test/authorize", "_blank", "noopener,noreferrer");
    spy.mockRestore();
  });

  it("test-login start opens the URL via openWindow and shows raw diagnostics on failure", async () => {
    const fetchMock = vi.fn<typeof fetch>(async (input) => {
      const url = String(input);
      if (url.includes("/enterprise/sso/test-login/start")) {
        return jsonResponse(400, { code: "SSO_PROVIDER_NOT_FOUND", message: "No provider" });
      }
      if (url.includes("/enterprise/sso/providers")) {
        return jsonResponse(200, { providers: [provider({ domainVerified: true })] });
      }
      throw new Error(`unmocked fetch: ${url}`);
    });
    vi.stubGlobal("fetch", fetchMock);

    const el = makeEl();
    document.body.appendChild(el);
    await vi.waitFor(() => expect(el.step).toBe("test-login"));

    const button = [...el.shadowRoot!.querySelectorAll("button")].find((b) =>
      b.textContent?.includes("Start test login"),
    )!;
    button.click();

    await vi.waitFor(() => expect(el.shadowRoot!.textContent).toContain("SSO_PROVIDER_NOT_FOUND"));
  });

  it("test-login opens the sign-in URL, then advances to enforce once testLoginPassedAt is set", async () => {
    let passed = false;
    const openWindow = vi.fn();
    const fetchMock = vi.fn<typeof fetch>(async (input) => {
      const url = String(input);
      if (url.includes("/enterprise/sso/test-login/start")) {
        passed = true;
        return jsonResponse(200, { url: "https://idp.test/authorize?x=1" });
      }
      if (url.includes("/enterprise/sso/providers")) {
        return jsonResponse(200, {
          providers: [
            provider({
              domainVerified: true,
              testLoginPassedAt: passed ? "2026-01-01T00:00:00Z" : null,
            }),
          ],
        });
      }
      throw new Error(`unmocked fetch: ${url}`);
    });
    vi.stubGlobal("fetch", fetchMock);

    const el = makeEl();
    el.openWindow = openWindow;
    document.body.appendChild(el);
    await vi.waitFor(() => expect(el.step).toBe("test-login"));

    const startButton = [...el.shadowRoot!.querySelectorAll("button")].find((b) =>
      b.textContent?.includes("Start test login"),
    )!;
    startButton.click();
    await vi.waitFor(() =>
      expect(openWindow).toHaveBeenCalledWith("https://idp.test/authorize?x=1"),
    );

    const doneButton = [...el.shadowRoot!.querySelectorAll("button")].find((b) =>
      b.textContent?.includes("I completed the test"),
    )!;
    doneButton.click();

    await vi.waitFor(() => expect(el.step).toBe("enforce"));
  });

  it("enforce toggle is disabled until testLoginPassedAt is set", async () => {
    vi.stubGlobal(
      "fetch",
      routeJson({
        "/enterprise/sso/providers": {
          providers: [provider({ domainVerified: true, testLoginPassedAt: null })],
        },
        "/get-session": { user: { id: "user_1" } },
      }),
    );
    const el = makeEl();
    document.body.appendChild(el);
    await vi.waitFor(() => expect(el.step).toBe("test-login"));
    el.step = "enforce";
    await el.updateComplete;

    const toggle = el.shadowRoot!.querySelector<HTMLButtonElement>(
      '[data-testid="enforce-toggle"]',
    )!;
    expect(toggle.disabled).toBe(true);
  });

  it("enabling enforcement posts ssoEnforced+breakGlassUserId and advances to done", async () => {
    const fetchMock = vi.fn<typeof fetch>(async (input, init) => {
      const url = String(input);
      if (url.includes("/enterprise/sso/providers")) {
        return jsonResponse(200, {
          providers: [
            provider({ domainVerified: true, testLoginPassedAt: "2026-01-01T00:00:00Z" }),
          ],
        });
      }
      if (url.includes("/get-session")) return jsonResponse(200, { user: { id: "user_1" } });
      if (url.includes("/enterprise/policy/set")) {
        const body = JSON.parse((init as RequestInit).body as string);
        expect(body).toEqual({ orgId: "org_1", ssoEnforced: true, breakGlassUserId: "user_1" });
        return jsonResponse(200, { orgId: "org_1" });
      }
      throw new Error(`unmocked fetch: ${url}`);
    });
    vi.stubGlobal("fetch", fetchMock);

    const el = makeEl();
    document.body.appendChild(el);
    await vi.waitFor(() => expect(el.step).toBe("enforce"));
    await vi.waitFor(() =>
      expect(
        el.shadowRoot!.querySelector<HTMLInputElement>('[name="breakGlassUserId"]')!.value,
      ).toBe("user_1"),
    );

    const toggle = el.shadowRoot!.querySelector<HTMLButtonElement>(
      '[data-testid="enforce-toggle"]',
    )!;
    expect(toggle.disabled).toBe(false);
    toggle.click();

    await vi.waitFor(() => expect(el.step).toBe("done"));
  });

  // Final review I-1: the server keeps *choosing* the break-glass user
  // owner-only, so an admin who walks this wizard reaches the last button and
  // gets `NOT_ORG_OWNER`. The raw server message ("Owner role required.")
  // says nothing about the way out.
  it("an admin hitting NOT_ORG_OWNER on the enforce step is told an owner must set the break-glass user", async () => {
    const fetchMock = vi.fn<typeof fetch>(async (input) => {
      const url = String(input);
      if (url.includes("/enterprise/sso/providers")) {
        return jsonResponse(200, {
          providers: [
            provider({ domainVerified: true, testLoginPassedAt: "2026-01-01T00:00:00Z" }),
          ],
        });
      }
      if (url.includes("/get-session")) return jsonResponse(200, { user: { id: "admin_1" } });
      if (url.includes("/enterprise/policy/set")) {
        return jsonResponse(403, { code: "NOT_ORG_OWNER", message: "Owner role required." });
      }
      throw new Error(`unmocked fetch: ${url}`);
    });
    vi.stubGlobal("fetch", fetchMock);

    const el = makeEl();
    document.body.appendChild(el);
    await vi.waitFor(() => expect(el.step).toBe("enforce"));
    await vi.waitFor(() =>
      expect(
        el.shadowRoot!.querySelector<HTMLInputElement>('[name="breakGlassUserId"]')!.value,
      ).toBe("admin_1"),
    );

    el.shadowRoot!.querySelector<HTMLButtonElement>('[data-testid="enforce-toggle"]')!.click();

    await vi.waitFor(() => {
      const error = el.shadowRoot!.querySelector(".ab-error");
      expect(error?.textContent).toBe("An organization owner must set the break-glass user first");
    });
    expect(el.step).toBe("enforce");
  });

  it("a storage event keyed ab_sso_test re-fetches providers and advances to enforce", async () => {
    let passed = false;
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>(async (input) => {
        const url = String(input);
        if (url.includes("/enterprise/sso/providers")) {
          return jsonResponse(200, {
            providers: [
              provider({
                domainVerified: true,
                testLoginPassedAt: passed ? "2026-01-01T00:00:00Z" : null,
              }),
            ],
          });
        }
        throw new Error(`unmocked fetch: ${url}`);
      }),
    );

    const el = makeEl();
    document.body.appendChild(el);
    await vi.waitFor(() => expect(el.step).toBe("test-login"));

    // The finish redirect's landing page (out of this component's scope)
    // is what actually writes `localStorage.ab_sso_test` — a `storage`
    // event only fires on *other* same-origin windows/tabs than the one
    // that wrote it, which is exactly the wizard's own window here, so a
    // plain dispatched `StorageEvent` is a faithful stand-in for that.
    passed = true;
    window.dispatchEvent(new StorageEvent("storage", { key: "ab_sso_test" }));

    await vi.waitFor(() => expect(el.step).toBe("enforce"));
  });

  it("enforce toggle stays disabled when breakGlassUserId is empty, even with a passed test login", async () => {
    vi.stubGlobal(
      "fetch",
      routeJson({
        "/enterprise/sso/providers": {
          providers: [
            provider({ domainVerified: true, testLoginPassedAt: "2026-01-01T00:00:00Z" }),
          ],
        },
        // No user id in the session response — `breakGlassUserId` stays empty.
        "/get-session": { user: null },
      }),
    );
    const el = makeEl();
    document.body.appendChild(el);
    await vi.waitFor(() => expect(el.step).toBe("enforce"));
    expect(el.breakGlassUserId).toBe("");

    const toggle = el.shadowRoot!.querySelector<HTMLButtonElement>(
      '[data-testid="enforce-toggle"]',
    )!;
    expect(toggle.disabled).toBe(true);

    const input = el.shadowRoot!.querySelector<HTMLInputElement>('[name="breakGlassUserId"]')!;
    expect(input.required).toBe(true);
  });

  it("handleEnforce refuses an empty breakGlassUserId even if the disabled button is bypassed", async () => {
    const fetchMock = vi.fn<typeof fetch>(async (input) => {
      const url = String(input);
      if (url.includes("/enterprise/sso/providers")) {
        return jsonResponse(200, {
          providers: [
            provider({ domainVerified: true, testLoginPassedAt: "2026-01-01T00:00:00Z" }),
          ],
        });
      }
      if (url.includes("/get-session")) return jsonResponse(200, { user: null });
      throw new Error(`unmocked fetch: ${url}`);
    });
    vi.stubGlobal("fetch", fetchMock);

    const el = makeEl();
    document.body.appendChild(el);
    await vi.waitFor(() => expect(el.step).toBe("enforce"));
    expect(el.breakGlassUserId).toBe("");

    // Bypasses the disabled button entirely — the handler itself must still
    // refuse, per the controller finding.
    await (el as unknown as { handleEnforce(): Promise<void> }).handleEnforce();
    await el.updateComplete;

    expect(el.step).toBe("enforce");
    expect(el.shadowRoot!.textContent).toContain("break-glass user id is required");
    expect(fetchMock.mock.calls.some(([u]) => String(u).includes("/enterprise/policy/set"))).toBe(
      false,
    );
  });
});

// Alpha Bros enterprise layer — `<ab-security-policy>` (Task 12).
//
// Pure DOM tests against a mocked, URL-aware `globalThis.fetch`, following
// `test/portal/members.test.ts`'s pattern. The central assertion this file
// exists to prove: `POST /enterprise/policy/set` only ever carries the
// fields an admin actually changed, never the full loaded record.

import { afterEach, describe, expect, it, vi } from "vitest";
import "../../src/portal/index";
import type { AbSecurityPolicy } from "../../src/portal/ab-security-policy";

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

function policyBody(overrides: Partial<Record<string, unknown>> = {}) {
  return {
    orgId: "org_1",
    require2fa: false,
    ssoEnforced: false,
    breakGlassUserId: null,
    sessionMaxAgeS: null,
    allowedMethods: [
      "sso",
      "magic_link",
      "password",
      "passkey",
      "google",
      "github",
      "linkedin",
      "microsoft",
    ],
    groupRoleMap: {},
    ...overrides,
  };
}

function makeEl(orgId = "org_1"): AbSecurityPolicy {
  const el = document.createElement("ab-security-policy") as AbSecurityPolicy;
  el.orgId = orgId;
  return el;
}

afterEach(() => {
  document.body.innerHTML = "";
  vi.unstubAllGlobals();
});

describe("<ab-security-policy>", () => {
  it("fetches /enterprise/policy and renders the loaded values", async () => {
    const fetchMock = vi.fn<typeof fetch>(async () =>
      jsonResponse(200, policyBody({ require2fa: true, sessionMaxAgeS: 3600 })),
    );
    vi.stubGlobal("fetch", fetchMock);

    const el = makeEl();
    document.body.appendChild(el);
    await vi.waitFor(() => expect(el.shadowRoot!.querySelector("form")).not.toBeNull());

    const [url] = fetchMock.mock.calls[0]!;
    expect(url).toBe("/api/auth/enterprise/policy?orgId=org_1");
    const checkbox = el.shadowRoot!.querySelector<HTMLInputElement>('input[name="require2fa"]')!;
    expect(checkbox.checked).toBe(true);
    const select = el.shadowRoot!.querySelector<HTMLSelectElement>(
      'select[name="sessionMaxAgeS"]',
    )!;
    expect(select.value).toBe("3600");
  });

  it("posts only require2fa when only require2fa changed", async () => {
    const fetchMock = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(jsonResponse(200, policyBody()))
      .mockResolvedValueOnce(jsonResponse(200, { orgId: "org_1" }))
      .mockResolvedValueOnce(jsonResponse(200, policyBody({ require2fa: true })));
    vi.stubGlobal("fetch", fetchMock);

    const el = makeEl();
    document.body.appendChild(el);
    await vi.waitFor(() => expect(el.shadowRoot!.querySelector("form")).not.toBeNull());

    const checkbox = el.shadowRoot!.querySelector<HTMLInputElement>('input[name="require2fa"]')!;
    checkbox.click();
    const form = el.shadowRoot!.querySelector("form")!;
    form.dispatchEvent(new SubmitEvent("submit", { bubbles: true, cancelable: true }));

    await vi.waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(3));
    const [url, init] = fetchMock.mock.calls[1]!;
    expect(url).toBe("/api/auth/enterprise/policy/set");
    expect(JSON.parse((init as RequestInit).body as string)).toEqual({
      orgId: "org_1",
      require2fa: true,
    });
  });

  it('submitting with no changes does not POST and shows "Nothing to save."', async () => {
    const fetchMock = vi.fn<typeof fetch>().mockResolvedValueOnce(jsonResponse(200, policyBody()));
    vi.stubGlobal("fetch", fetchMock);

    const el = makeEl();
    document.body.appendChild(el);
    await vi.waitFor(() => expect(el.shadowRoot!.querySelector("form")).not.toBeNull());

    const form = el.shadowRoot!.querySelector("form")!;
    form.dispatchEvent(new SubmitEvent("submit", { bubbles: true, cancelable: true }));
    await el.updateComplete;
    expect(el.shadowRoot!.textContent).toContain("Nothing to save.");
    await new Promise((resolve) => setTimeout(resolve, 10));
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("unchecking an allowed method posts the full remaining allowedMethods array", async () => {
    const fetchMock = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(jsonResponse(200, policyBody()))
      .mockResolvedValueOnce(jsonResponse(200, { orgId: "org_1" }))
      .mockResolvedValueOnce(jsonResponse(200, policyBody()));
    vi.stubGlobal("fetch", fetchMock);

    const el = makeEl();
    document.body.appendChild(el);
    await vi.waitFor(() => expect(el.shadowRoot!.querySelector("form")).not.toBeNull());

    const passwordCheckbox = el.shadowRoot!.querySelector<HTMLInputElement>(
      'input[name="allowedMethods"][value="password"]',
    )!;
    expect(passwordCheckbox.checked).toBe(true);
    passwordCheckbox.click();

    const form = el.shadowRoot!.querySelector("form")!;
    form.dispatchEvent(new SubmitEvent("submit", { bubbles: true, cancelable: true }));

    await vi.waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(3));
    const [, init] = fetchMock.mock.calls[1]!;
    const body = JSON.parse((init as RequestInit).body as string);
    expect(body.allowedMethods).not.toContain("password");
    expect(body.allowedMethods).toContain("sso");
  });

  it("adding a group->role row and saving posts the full groupRoleMap", async () => {
    const fetchMock = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(jsonResponse(200, policyBody()))
      .mockResolvedValueOnce(jsonResponse(200, { orgId: "org_1" }))
      .mockResolvedValueOnce(
        jsonResponse(200, policyBody({ groupRoleMap: { Engineering: "admin" } })),
      );
    vi.stubGlobal("fetch", fetchMock);

    const el = makeEl();
    document.body.appendChild(el);
    await vi.waitFor(() => expect(el.shadowRoot!.querySelector("form")).not.toBeNull());

    const nameInputs = el.shadowRoot!.querySelectorAll<HTMLInputElement>(
      'input[placeholder="Group display name"]',
    );
    const nameInput = nameInputs[0]!;
    nameInput.value = "Engineering";
    nameInput.dispatchEvent(new Event("input", { bubbles: true }));

    const addButton = [...el.shadowRoot!.querySelectorAll("button")].find(
      (b) => b.textContent?.trim() === "Add",
    )!;
    addButton.click();
    await el.updateComplete;
    expect(el.shadowRoot!.textContent).toContain("Engineering");

    const form = el.shadowRoot!.querySelector("form")!;
    form.dispatchEvent(new SubmitEvent("submit", { bubbles: true, cancelable: true }));

    await vi.waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(3));
    const [, init] = fetchMock.mock.calls[1]!;
    const body = JSON.parse((init as RequestInit).body as string);
    expect(body.groupRoleMap).toEqual({ Engineering: "member" });
  });

  it("removing a group row and saving posts the updated groupRoleMap", async () => {
    const fetchMock = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(jsonResponse(200, policyBody({ groupRoleMap: { Sales: "member" } })))
      .mockResolvedValueOnce(jsonResponse(200, { orgId: "org_1" }))
      .mockResolvedValueOnce(jsonResponse(200, policyBody({ groupRoleMap: {} })));
    vi.stubGlobal("fetch", fetchMock);

    const el = makeEl();
    document.body.appendChild(el);
    await vi.waitFor(() => expect(el.shadowRoot!.textContent).toContain("Sales"));

    const removeButton = [...el.shadowRoot!.querySelectorAll("button")].find(
      (b) => b.textContent?.trim() === "Remove",
    )!;
    removeButton.click();
    await el.updateComplete;

    const form = el.shadowRoot!.querySelector("form")!;
    form.dispatchEvent(new SubmitEvent("submit", { bubbles: true, cancelable: true }));

    await vi.waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(3));
    const [, init] = fetchMock.mock.calls[1]!;
    const body = JSON.parse((init as RequestInit).body as string);
    expect(body.groupRoleMap).toEqual({});
  });

  it("a failed save renders inline without discarding the loaded form", async () => {
    const fetchMock = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(jsonResponse(200, policyBody()))
      .mockResolvedValueOnce(jsonResponse(403, { code: "NOT_ORG_ADMIN", message: "Admin only" }));
    vi.stubGlobal("fetch", fetchMock);

    const el = makeEl();
    document.body.appendChild(el);
    await vi.waitFor(() => expect(el.shadowRoot!.querySelector("form")).not.toBeNull());

    const checkbox = el.shadowRoot!.querySelector<HTMLInputElement>('input[name="require2fa"]')!;
    checkbox.click();
    const form = el.shadowRoot!.querySelector("form")!;
    form.dispatchEvent(new SubmitEvent("submit", { bubbles: true, cancelable: true }));

    await vi.waitFor(() => expect(el.shadowRoot!.textContent).toContain("Admin only"));
    expect(el.shadowRoot!.querySelector("form")).not.toBeNull();
  });
});

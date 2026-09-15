// Alpha Bros enterprise layer — `<ab-security-settings>` (Task 10).
//
// Pure DOM tests against a mocked `globalThis.fetch`. Locked/unlocked tab
// state is driven entirely by the real `GET /enterprise/features` response;
// tab selection is driven by real clicks on the real `role="tablist"`
// buttons.

import { afterEach, describe, expect, it, vi } from "vitest";
import "../../src/portal/index";
import type { AbSecuritySettings } from "../../src/portal/ab-security-settings";

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

function makeEl(orgId = "org_1"): AbSecuritySettings {
  const el = document.createElement("ab-security-settings") as AbSecuritySettings;
  el.orgId = orgId;
  return el;
}

function tabButton(el: AbSecuritySettings, tab: string): HTMLButtonElement {
  return el.shadowRoot!.querySelector<HTMLButtonElement>(`button[data-tab="${tab}"]`)!;
}

afterEach(() => {
  document.body.innerHTML = "";
  vi.unstubAllGlobals();
});

describe("<ab-security-settings>", () => {
  it("upgrades with a shadow root and a role=tablist", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>(async () => jsonResponse(200, { features: [] })),
    );
    const el = makeEl();
    document.body.appendChild(el);
    await vi.waitFor(() => expect(el.shadowRoot!.querySelector('[role="tablist"]')).not.toBeNull());
  });

  it("fetches /enterprise/features and renders the default tab set", async () => {
    const fetchMock = vi.fn<typeof fetch>(async () => jsonResponse(200, { features: [] }));
    vi.stubGlobal("fetch", fetchMock);

    const el = makeEl();
    document.body.appendChild(el);
    await vi.waitFor(() => expect(el.shadowRoot!.querySelectorAll('[role="tab"]').length).toBe(6));

    const [url] = fetchMock.mock.calls[0]!;
    expect(url).toBe("/api/auth/enterprise/features?orgId=org_1");

    for (const tab of ["members", "sso", "scim", "policy", "api-keys", "audit"]) {
      expect(tabButton(el, tab)).not.toBeUndefined();
    }
  });

  it("hides/locks tabs whose feature is absent; members is never locked", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>(async () => jsonResponse(200, { features: ["sso"] })),
    );
    const el = makeEl();
    document.body.appendChild(el);
    await vi.waitFor(() => expect(el.shadowRoot!.querySelectorAll('[role="tab"]').length).toBe(6));

    expect(tabButton(el, "members").getAttribute("aria-disabled")).toBe("false");
    expect(tabButton(el, "sso").getAttribute("aria-disabled")).toBe("false");
    for (const tab of ["scim", "policy", "api-keys", "audit"]) {
      expect(tabButton(el, tab).getAttribute("aria-disabled")).toBe("true");
      expect(tabButton(el, tab).hasAttribute("disabled")).toBe(true);
    }
  });

  it("defaults to selecting the first unlocked tab (members)", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>(async () => jsonResponse(200, { features: ["sso"] })),
    );
    const el = makeEl();
    document.body.appendChild(el);
    await vi.waitFor(() =>
      expect(tabButton(el, "members").getAttribute("aria-selected")).toBe("true"),
    );
    expect(el.shadowRoot!.querySelector("ab-members")).not.toBeNull();
  });

  it("clicking an unlocked tab selects it and renders its (unknown) child element", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>(async () => jsonResponse(200, { features: ["sso"] })),
    );
    const el = makeEl();
    el.setAttribute("base-path", "/custom/auth");
    document.body.appendChild(el);
    await vi.waitFor(() => expect(el.shadowRoot!.querySelectorAll('[role="tab"]').length).toBe(6));

    tabButton(el, "sso").click();
    await el.updateComplete;

    expect(tabButton(el, "sso").getAttribute("aria-selected")).toBe("true");
    expect(tabButton(el, "members").getAttribute("aria-selected")).toBe("false");
    const child = el.shadowRoot!.querySelector("ab-sso-wizard");
    expect(child).not.toBeNull();
    expect(child!.getAttribute("org-id")).toBe("org_1");
    expect(child!.getAttribute("base-path")).toBe("/custom/auth");
  });

  it("clicking a locked tab does not select it or render its child element", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>(async () => jsonResponse(200, { features: ["sso"] })),
    );
    const el = makeEl();
    document.body.appendChild(el);
    await vi.waitFor(() => expect(el.shadowRoot!.querySelectorAll('[role="tab"]').length).toBe(6));

    tabButton(el, "audit").click();
    await el.updateComplete;

    expect(tabButton(el, "audit").getAttribute("aria-selected")).toBe("false");
    expect(el.shadowRoot!.querySelector("ab-audit-log")).toBeNull();
    expect(tabButton(el, "members").getAttribute("aria-selected")).toBe("true");
  });

  it("ArrowRight/ArrowLeft on the tablist move selection, skipping locked tabs and wrapping", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>(async () => jsonResponse(200, { features: ["sso"] })),
    );
    const el = makeEl();
    document.body.appendChild(el);
    await vi.waitFor(() => expect(el.shadowRoot!.querySelectorAll('[role="tab"]').length).toBe(6));
    // Unlocked: members, sso. Locked: scim, policy, api-keys, audit.
    expect(tabButton(el, "members").getAttribute("aria-selected")).toBe("true");

    const tablist = el.shadowRoot!.querySelector('[role="tablist"]')!;
    tablist.dispatchEvent(
      new KeyboardEvent("keydown", { key: "ArrowRight", bubbles: true, cancelable: true }),
    );
    await el.updateComplete;
    expect(tabButton(el, "sso").getAttribute("aria-selected")).toBe("true");

    // Next ArrowRight would land on the locked "scim" tab — must skip ahead
    // to the next unlocked one, wrapping back around to "members".
    tablist.dispatchEvent(
      new KeyboardEvent("keydown", { key: "ArrowRight", bubbles: true, cancelable: true }),
    );
    await el.updateComplete;
    expect(tabButton(el, "members").getAttribute("aria-selected")).toBe("true");

    tablist.dispatchEvent(
      new KeyboardEvent("keydown", { key: "ArrowLeft", bubbles: true, cancelable: true }),
    );
    await el.updateComplete;
    expect(tabButton(el, "sso").getAttribute("aria-selected")).toBe("true");
  });

  it("exposes aria-controls/role=tabpanel/aria-labelledby wiring between the selected tab and panel", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>(async () => jsonResponse(200, { features: [] })),
    );
    const el = makeEl();
    document.body.appendChild(el);
    await vi.waitFor(() => expect(el.shadowRoot!.querySelectorAll('[role="tab"]').length).toBe(6));

    const tab = tabButton(el, "members");
    const panel = el.shadowRoot!.querySelector('[role="tabpanel"]')!;
    expect(tab.getAttribute("aria-controls")).toBe(panel.id);
    expect(panel.getAttribute("aria-labelledby")).toBe(tab.id);
  });

  it("respects a custom tabs attribute", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>(async () => jsonResponse(200, { features: [] })),
    );
    const el = makeEl();
    el.setAttribute("tabs", "members,audit");
    document.body.appendChild(el);
    await vi.waitFor(() => expect(el.shadowRoot!.querySelectorAll('[role="tab"]').length).toBe(2));

    expect(tabButton(el, "members")).not.toBeUndefined();
    expect(tabButton(el, "audit")).not.toBeUndefined();
    expect(tabButton(el, "sso")).toBeNull();
  });

  it("renders the not-entitled error when GET /enterprise/features fails", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>(async () =>
        jsonResponse(403, { code: "FEATURE_NOT_ENTITLED", message: "nope" }),
      ),
    );
    const el = makeEl();
    document.body.appendChild(el);
    await vi.waitFor(() =>
      expect(el.shadowRoot!.textContent).toContain("This feature is not included in your plan"),
    );
  });
});

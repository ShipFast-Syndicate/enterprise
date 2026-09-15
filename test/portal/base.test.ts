// Alpha Bros enterprise layer — `src/portal/base.ts` + `src/portal/api.ts`
// (Task 10). `AbElement` is exercised through a tiny concrete subclass
// (Lit's `LitElement` is abstract enough — no `render()` — that it can't be
// instantiated/upgraded directly), with thin public wrappers around its
// `protected` members so this test file (checked by `pnpm typecheck`, which
// includes `test/**`) can drive them without violating TypeScript's access
// checks. `PortalApi` is exercised directly against a mocked `globalThis.fetch`.

import { afterEach, describe, expect, it, vi } from "vitest";
import { html, type PropertyValues, type TemplateResult } from "lit";
import { AbElement } from "../../src/portal/base";
import { PortalApi, PortalError } from "../../src/portal/api";

class AbTestElement extends AbElement {
  static properties = { ...AbElement.properties, testError: { state: true } };

  declare testError: unknown;

  willUpdateCalls = 0;

  constructor() {
    super();
    this.testError = undefined;
  }

  protected override willUpdate(changed: PropertyValues): void {
    super.willUpdate(changed);
    this.willUpdateCalls += 1;
  }

  triggerChange(detail?: unknown): void {
    this.emitChange(detail);
  }

  render(): TemplateResult {
    if (this.testError !== undefined) return this.renderError(this.testError);
    return html`<div class="probe">ok</div>`;
  }
}
if (!customElements.get("ab-test-element")) {
  customElements.define("ab-test-element", AbTestElement);
}

function makeEl(): AbTestElement {
  return document.createElement("ab-test-element") as AbTestElement;
}

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

afterEach(() => {
  document.body.innerHTML = "";
  vi.unstubAllGlobals();
});

describe("AbElement", () => {
  it("upgrades with a shadow root and default basePath", async () => {
    const el = makeEl();
    document.body.appendChild(el);
    await el.updateComplete;

    expect(el.shadowRoot).not.toBeNull();
    expect(el.shadowRoot!.querySelector(".probe")?.textContent).toBe("ok");
    expect(el.basePath).toBe("/api/auth");
    expect(el.orgId).toBe("");
  });

  it("reads org-id/base-path from attributes", async () => {
    const el = makeEl();
    el.setAttribute("org-id", "org_1");
    el.setAttribute("base-path", "/custom/auth");
    document.body.appendChild(el);
    await el.updateComplete;

    expect(el.orgId).toBe("org_1");
    expect(el.basePath).toBe("/custom/auth");
  });

  it("emitChange dispatches a bubbling, composed ab-change CustomEvent", async () => {
    const el = makeEl();
    document.body.appendChild(el);
    await el.updateComplete;

    const handler = vi.fn();
    document.body.addEventListener("ab-change", handler);
    el.triggerChange({ foo: "bar" });

    expect(handler).toHaveBeenCalledTimes(1);
    const event = handler.mock.calls[0]![0] as CustomEvent;
    expect(event.type).toBe("ab-change");
    expect(event.bubbles).toBe(true);
    expect(event.composed).toBe(true);
    expect(event.detail).toEqual({ foo: "bar" });
  });

  it("renderError maps FEATURE_NOT_ENTITLED to the not-entitled slot default text", async () => {
    const el = makeEl();
    document.body.appendChild(el);
    await el.updateComplete;

    el.testError = new PortalError({
      status: 403,
      code: "FEATURE_NOT_ENTITLED",
      message: "Organization is not entitled to this feature.",
    });
    await el.updateComplete;

    expect(el.shadowRoot!.querySelector('slot[name="not-entitled"]')).not.toBeNull();
    expect(el.shadowRoot!.textContent).toContain("This feature is not included in your plan");
  });

  it("renderError renders the error's own message for any other error", async () => {
    const el = makeEl();
    document.body.appendChild(el);
    await el.updateComplete;

    el.testError = new PortalError({ status: 500, message: "boom" });
    await el.updateComplete;

    expect(el.shadowRoot!.querySelector('slot[name="not-entitled"]')).toBeNull();
    expect(el.shadowRoot!.textContent).toContain("boom");
  });
});

describe("PortalApi", () => {
  it("get() uses credentials:include and encodes query params", async () => {
    const fetchMock = vi.fn<typeof fetch>(async () => jsonResponse(200, { ok: true }));
    vi.stubGlobal("fetch", fetchMock);

    const api = new PortalApi("/api/auth");
    const data = await api.get<{ ok: boolean }>("/enterprise/members", { orgId: "org 1" });

    expect(data).toEqual({ ok: true });
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0]!;
    expect(url).toBe("/api/auth/enterprise/members?orgId=org+1");
    expect((init as RequestInit).method).toBe("GET");
    expect((init as RequestInit).credentials).toBe("include");
  });

  it("post() sends a JSON content-type and body", async () => {
    const fetchMock = vi.fn<typeof fetch>(async () => jsonResponse(200, { id: "m1" }));
    vi.stubGlobal("fetch", fetchMock);

    const api = new PortalApi("/api/auth");
    const data = await api.post<{ id: string }>("/organization/invite-member", {
      email: "a@b.com",
      role: "member",
    });

    expect(data).toEqual({ id: "m1" });
    const [url, init] = fetchMock.mock.calls[0]!;
    expect(url).toBe("/api/auth/organization/invite-member");
    const request = init as RequestInit;
    expect(request.method).toBe("POST");
    expect(request.credentials).toBe("include");
    expect(new Headers(request.headers).get("content-type")).toBe("application/json");
    expect(JSON.parse(request.body as string)).toEqual({ email: "a@b.com", role: "member" });
  });

  it("throws PortalError with status/code/message on a non-2xx response", async () => {
    const fetchMock = vi.fn<typeof fetch>(async () =>
      jsonResponse(403, { code: "FEATURE_NOT_ENTITLED", message: "nope" }),
    );
    vi.stubGlobal("fetch", fetchMock);

    const api = new PortalApi("/api/auth");
    await expect(api.get("/enterprise/features", { orgId: "o1" })).rejects.toMatchObject({
      status: 403,
      code: "FEATURE_NOT_ENTITLED",
      message: "nope",
    });
  });

  it("falls back to a generic message when the error body isn't JSON", async () => {
    const fetchMock = vi.fn(
      async () => new Response("<html>502</html>", { status: 502, headers: {} }),
    );
    vi.stubGlobal("fetch", fetchMock);

    const api = new PortalApi("/api/auth");
    await expect(api.get("/enterprise/features", { orgId: "o1" })).rejects.toMatchObject({
      status: 502,
      code: undefined,
      message: "Request failed with status 502",
    });
  });
});

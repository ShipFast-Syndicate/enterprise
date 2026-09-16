// Alpha Bros enterprise layer — `<ab-scim-tokens>` (Task 11).
//
// Pure DOM tests against a mocked, URL-aware `globalThis.fetch`, following
// `test/portal/members.test.ts`'s pattern.

import { afterEach, describe, expect, it, vi } from "vitest";
import "../../src/portal/index";
import type { AbScimTokens } from "../../src/portal/ab-scim-tokens";

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

function makeEl(orgId = "org_1"): AbScimTokens {
  const el = document.createElement("ab-scim-tokens") as AbScimTokens;
  el.orgId = orgId;
  return el;
}

afterEach(() => {
  document.body.innerHTML = "";
  vi.unstubAllGlobals();
});

describe("<ab-scim-tokens>", () => {
  it("fetches /enterprise/scim/tokens and renders rows", async () => {
    const fetchMock = vi.fn<typeof fetch>(async () =>
      jsonResponse(200, {
        tokens: [{ providerId: "scim-org_1", createdAt: null, lastUsedAt: null }],
      }),
    );
    vi.stubGlobal("fetch", fetchMock);

    const el = makeEl();
    document.body.appendChild(el);
    await vi.waitFor(() => expect(el.shadowRoot!.querySelectorAll("tbody tr").length).toBe(1));

    const [url, init] = fetchMock.mock.calls[0]!;
    expect(url).toBe("/api/auth/enterprise/scim/tokens?orgId=org_1");
    expect((init as RequestInit).credentials).toBe("include");
    expect(el.shadowRoot!.textContent).toContain("scim-org_1");
  });

  it("the create form defaults the providerId input to scim-<orgId>", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>(async () => jsonResponse(200, { tokens: [] })),
    );
    const el = makeEl();
    document.body.appendChild(el);
    await vi.waitFor(() => expect(el.shadowRoot!.querySelector("form")).not.toBeNull());
    const input = el.shadowRoot!.querySelector<HTMLInputElement>('input[name="providerId"]')!;
    expect(input.value).toBe("scim-org_1");
  });

  it("create shows the token once, then Done clears it and re-fetches", async () => {
    const fetchMock = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(jsonResponse(200, { tokens: [] }))
      .mockResolvedValueOnce(
        jsonResponse(200, { scimToken: "scim_secret_abc", baseUrl: "https://app.test/scim/v2" }),
      )
      .mockResolvedValueOnce(
        jsonResponse(200, {
          tokens: [{ providerId: "scim-org_1", createdAt: null, lastUsedAt: null }],
        }),
      );
    vi.stubGlobal("fetch", fetchMock);

    const el = makeEl();
    document.body.appendChild(el);
    await vi.waitFor(() => expect(el.shadowRoot!.querySelector("form")).not.toBeNull());

    const form = el.shadowRoot!.querySelector("form")!;
    form.dispatchEvent(new SubmitEvent("submit", { bubbles: true, cancelable: true }));

    await vi.waitFor(() => expect(el.shadowRoot!.textContent).toContain("scim_secret_abc"));
    expect(el.shadowRoot!.textContent).toContain("https://app.test/scim/v2");

    const [createUrl, createInit] = fetchMock.mock.calls[1]!;
    expect(createUrl).toBe("/api/auth/enterprise/scim/tokens/create");
    expect(JSON.parse((createInit as RequestInit).body as string)).toEqual({
      orgId: "org_1",
      providerId: "scim-org_1",
    });

    const doneButton = [...el.shadowRoot!.querySelectorAll("button")].find((b) =>
      b.textContent?.includes("Done"),
    )!;
    doneButton.click();

    await vi.waitFor(() => expect(el.shadowRoot!.textContent).not.toContain("scim_secret_abc"));
    expect(fetchMock).toHaveBeenCalledTimes(3);
    expect(el.shadowRoot!.textContent).toContain("scim-org_1");
  });

  it("revoke posts to /enterprise/scim/tokens/revoke after confirm, then re-fetches", async () => {
    const fetchMock = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(
        jsonResponse(200, {
          tokens: [{ providerId: "scim-org_1", createdAt: null, lastUsedAt: null }],
        }),
      )
      .mockResolvedValueOnce(jsonResponse(200, { ok: true }))
      .mockResolvedValueOnce(jsonResponse(200, { tokens: [] }));
    vi.stubGlobal("fetch", fetchMock);

    const el = makeEl();
    el.confirm = () => true;
    document.body.appendChild(el);
    await vi.waitFor(() => expect(el.shadowRoot!.querySelectorAll("tbody tr").length).toBe(1));

    el.shadowRoot!.querySelector<HTMLButtonElement>("tbody button")!.click();

    await vi.waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(3));
    const [url, init] = fetchMock.mock.calls[1]!;
    expect(url).toBe("/api/auth/enterprise/scim/tokens/revoke");
    expect(JSON.parse((init as RequestInit).body as string)).toEqual({
      orgId: "org_1",
      providerId: "scim-org_1",
    });
    await vi.waitFor(() => expect(el.shadowRoot!.querySelectorAll("tbody tr").length).toBe(0));
  });

  it("revoke does nothing when confirm is declined", async () => {
    const fetchMock = vi.fn<typeof fetch>().mockResolvedValueOnce(
      jsonResponse(200, {
        tokens: [{ providerId: "scim-org_1", createdAt: null, lastUsedAt: null }],
      }),
    );
    vi.stubGlobal("fetch", fetchMock);

    const el = makeEl();
    el.confirm = () => false;
    document.body.appendChild(el);
    await vi.waitFor(() => expect(el.shadowRoot!.querySelectorAll("tbody tr").length).toBe(1));

    el.shadowRoot!.querySelector<HTMLButtonElement>("tbody button")!.click();
    await new Promise((resolve) => setTimeout(resolve, 10));
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("a failed revoke renders an inline error without wiping the loaded token list", async () => {
    const fetchMock = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(
        jsonResponse(200, {
          tokens: [{ providerId: "scim-org_1", createdAt: null, lastUsedAt: null }],
        }),
      )
      .mockResolvedValueOnce(jsonResponse(500, { message: "Upstream failure" }));
    vi.stubGlobal("fetch", fetchMock);

    const el = makeEl();
    el.confirm = () => true;
    document.body.appendChild(el);
    await vi.waitFor(() => expect(el.shadowRoot!.querySelectorAll("tbody tr").length).toBe(1));

    el.shadowRoot!.querySelector<HTMLButtonElement>("tbody button")!.click();

    await vi.waitFor(() => expect(el.shadowRoot!.textContent).toContain("Upstream failure"));
    // The load-error path would have replaced the whole view — asserting
    // the row and form are both still present proves this is the inline
    // `submitError` path instead.
    expect(el.shadowRoot!.querySelectorAll("tbody tr").length).toBe(1);
    expect(el.shadowRoot!.querySelector("form")).not.toBeNull();
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });
});

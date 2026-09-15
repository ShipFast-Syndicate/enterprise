// Alpha Bros enterprise layer — `<ab-api-keys>` (Task 12).
//
// Pure DOM tests against a mocked, URL-aware `globalThis.fetch`, following
// `test/portal/members.test.ts`'s pattern.

import { afterEach, describe, expect, it, vi } from "vitest";
import "../../src/portal/index";
import type { AbApiKeys } from "../../src/portal/ab-api-keys";

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

function makeEl(orgId = "org_1"): AbApiKeys {
  const el = document.createElement("ab-api-keys") as AbApiKeys;
  el.orgId = orgId;
  return el;
}

afterEach(() => {
  document.body.innerHTML = "";
  vi.unstubAllGlobals();
});

describe("<ab-api-keys>", () => {
  it("fetches /api-key/list and renders rows (no orgId — per-user keys)", async () => {
    const fetchMock = vi.fn<typeof fetch>(async () =>
      jsonResponse(200, {
        apiKeys: [
          {
            id: "key_1",
            name: "CI",
            start: "ab_12",
            prefix: "ab_",
            enabled: true,
            createdAt: "2026-01-01T00:00:00.000Z",
            expiresAt: null,
          },
        ],
        total: 1,
      }),
    );
    vi.stubGlobal("fetch", fetchMock);

    const el = makeEl();
    document.body.appendChild(el);
    await vi.waitFor(() => expect(el.shadowRoot!.querySelectorAll("tbody tr").length).toBe(1));

    const [url, init] = fetchMock.mock.calls[0]!;
    expect(url).toBe("/api/auth/api-key/list");
    expect((init as RequestInit).credentials).toBe("include");
    expect(el.shadowRoot!.textContent).toContain("CI");
    expect(el.shadowRoot!.textContent).toContain("Never");
  });

  it("create shows the key once, then Done clears it and re-fetches", async () => {
    const fetchMock = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(jsonResponse(200, { apiKeys: [], total: 0 }))
      .mockResolvedValueOnce(
        jsonResponse(200, { id: "key_1", name: "CI", key: "ab_rawsecretvalue" }),
      )
      .mockResolvedValueOnce(
        jsonResponse(200, {
          apiKeys: [
            {
              id: "key_1",
              name: "CI",
              start: "ab_",
              prefix: "ab_",
              enabled: true,
              createdAt: "2026-01-01T00:00:00.000Z",
              expiresAt: null,
            },
          ],
          total: 1,
        }),
      );
    vi.stubGlobal("fetch", fetchMock);

    const el = makeEl();
    document.body.appendChild(el);
    await vi.waitFor(() => expect(el.shadowRoot!.querySelector("form")).not.toBeNull());

    const form = el.shadowRoot!.querySelector("form")!;
    form.querySelector<HTMLInputElement>('[name="name"]')!.value = "CI";
    const select = form.querySelector<HTMLSelectElement>('[name="expiresIn"]')!;
    select.value = String(30 * 24 * 60 * 60);
    form.dispatchEvent(new SubmitEvent("submit", { bubbles: true, cancelable: true }));

    await vi.waitFor(() => expect(el.shadowRoot!.textContent).toContain("ab_rawsecretvalue"));

    const [createUrl, createInit] = fetchMock.mock.calls[1]!;
    expect(createUrl).toBe("/api/auth/api-key/create");
    expect(JSON.parse((createInit as RequestInit).body as string)).toEqual({
      name: "CI",
      expiresIn: 30 * 24 * 60 * 60,
    });

    const doneButton = [...el.shadowRoot!.querySelectorAll("button")].find((b) =>
      b.textContent?.includes("Done"),
    )!;
    doneButton.click();

    await vi.waitFor(() => expect(el.shadowRoot!.textContent).not.toContain("ab_rawsecretvalue"));
    expect(fetchMock).toHaveBeenCalledTimes(3);
    expect(el.shadowRoot!.textContent).toContain("CI");
  });

  it("create with no name/expiry omits both fields from the body", async () => {
    const fetchMock = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(jsonResponse(200, { apiKeys: [], total: 0 }))
      .mockResolvedValueOnce(jsonResponse(200, { id: "key_1", name: null, key: "ab_x" }));
    vi.stubGlobal("fetch", fetchMock);

    const el = makeEl();
    document.body.appendChild(el);
    await vi.waitFor(() => expect(el.shadowRoot!.querySelector("form")).not.toBeNull());

    const form = el.shadowRoot!.querySelector("form")!;
    form.dispatchEvent(new SubmitEvent("submit", { bubbles: true, cancelable: true }));

    await vi.waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(2));
    const [, init] = fetchMock.mock.calls[1]!;
    expect(JSON.parse((init as RequestInit).body as string)).toEqual({});
  });

  it("delete posts to /api-key/delete after confirm, then re-fetches", async () => {
    const fetchMock = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(
        jsonResponse(200, {
          apiKeys: [
            {
              id: "key_1",
              name: "CI",
              start: "ab_",
              prefix: "ab_",
              enabled: true,
              createdAt: "2026-01-01T00:00:00.000Z",
              expiresAt: null,
            },
          ],
          total: 1,
        }),
      )
      .mockResolvedValueOnce(jsonResponse(200, { success: true }))
      .mockResolvedValueOnce(jsonResponse(200, { apiKeys: [], total: 0 }));
    vi.stubGlobal("fetch", fetchMock);

    const el = makeEl();
    el.confirm = () => true;
    document.body.appendChild(el);
    await vi.waitFor(() => expect(el.shadowRoot!.querySelectorAll("tbody tr").length).toBe(1));

    el.shadowRoot!.querySelector<HTMLButtonElement>("tbody button")!.click();

    await vi.waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(3));
    const [url, init] = fetchMock.mock.calls[1]!;
    expect(url).toBe("/api/auth/api-key/delete");
    expect(JSON.parse((init as RequestInit).body as string)).toEqual({ keyId: "key_1" });
    await vi.waitFor(() => expect(el.shadowRoot!.querySelectorAll("tbody tr").length).toBe(0));
  });

  it("delete does nothing when confirm is declined", async () => {
    const fetchMock = vi.fn<typeof fetch>().mockResolvedValueOnce(
      jsonResponse(200, {
        apiKeys: [
          {
            id: "key_1",
            name: "CI",
            start: "ab_",
            prefix: "ab_",
            enabled: true,
            createdAt: "2026-01-01T00:00:00.000Z",
            expiresAt: null,
          },
        ],
        total: 1,
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
});

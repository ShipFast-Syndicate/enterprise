// Alpha Bros enterprise layer — `<ab-audit-log>` (Task 12).
//
// Pure DOM tests against a mocked, URL-aware `globalThis.fetch`, following
// `test/portal/members.test.ts`'s pattern.

import { afterEach, describe, expect, it, vi } from "vitest";
import "../../src/portal/index";
import type { AbAuditLog } from "../../src/portal/ab-audit-log";

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

function event(overrides: Partial<Record<string, unknown>> = {}) {
  return {
    id: "evt_1",
    seq: 1,
    createdAt: "2026-01-01T00:00:00.000Z",
    actorType: "user",
    actorId: "user_1",
    action: "member.invited",
    targetType: "member",
    targetId: "member_1",
    ...overrides,
  };
}

function makeEl(orgId = "org_1"): AbAuditLog {
  const el = document.createElement("ab-audit-log") as AbAuditLog;
  el.orgId = orgId;
  return el;
}

afterEach(() => {
  document.body.innerHTML = "";
  vi.unstubAllGlobals();
});

describe("<ab-audit-log>", () => {
  it("fetches /enterprise/audit/list and renders rows", async () => {
    const fetchMock = vi.fn<typeof fetch>(async () =>
      jsonResponse(200, { items: [event()], nextCursor: null }),
    );
    vi.stubGlobal("fetch", fetchMock);

    const el = makeEl();
    document.body.appendChild(el);
    await vi.waitFor(() => expect(el.shadowRoot!.querySelectorAll("tbody tr").length).toBe(1));

    const [url, init] = fetchMock.mock.calls[0]!;
    expect(url).toBe("/api/auth/enterprise/audit/list?orgId=org_1");
    expect((init as RequestInit).credentials).toBe("include");
    expect(el.shadowRoot!.textContent).toContain("member.invited");
  });

  it('"Load more" appends items via nextCursor and stops offering once nextCursor is null', async () => {
    const fetchMock = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(
        jsonResponse(200, { items: [event({ id: "evt_1", seq: 2 })], nextCursor: "2" }),
      )
      .mockResolvedValueOnce(
        jsonResponse(200, { items: [event({ id: "evt_2", seq: 1 })], nextCursor: null }),
      );
    vi.stubGlobal("fetch", fetchMock);

    const el = makeEl();
    document.body.appendChild(el);
    await vi.waitFor(() => expect(el.shadowRoot!.querySelectorAll("tbody tr").length).toBe(1));

    const loadMore = [...el.shadowRoot!.querySelectorAll("button")].find((b) =>
      b.textContent?.includes("Load more"),
    )!;
    loadMore.click();

    await vi.waitFor(() => expect(el.shadowRoot!.querySelectorAll("tbody tr").length).toBe(2));
    const [url] = fetchMock.mock.calls[1]!;
    expect(url).toBe("/api/auth/enterprise/audit/list?orgId=org_1&cursor=2");

    expect(
      [...el.shadowRoot!.querySelectorAll("button")].some((b) =>
        b.textContent?.includes("Load more"),
      ),
    ).toBe(false);
  });

  it("filter submit re-fetches with action/actor/from/to and resets pagination", async () => {
    const fetchMock = vi.fn<typeof fetch>(async () =>
      jsonResponse(200, { items: [event()], nextCursor: null }),
    );
    vi.stubGlobal("fetch", fetchMock);

    const el = makeEl();
    document.body.appendChild(el);
    await vi.waitFor(() => expect(el.shadowRoot!.querySelector("form")).not.toBeNull());

    const form = el.shadowRoot!.querySelector("form")!;
    form.querySelector<HTMLInputElement>('[name="actorId"]')!.value = "user_9";
    form.querySelector<HTMLInputElement>('[name="from"]')!.value = "2026-01-01";
    form.querySelector<HTMLInputElement>('[name="to"]')!.value = "2026-01-31";
    form.dispatchEvent(new SubmitEvent("submit", { bubbles: true, cancelable: true }));

    await vi.waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(2));
    const [url] = fetchMock.mock.calls[1]!;
    const parsed = new URL(String(url), "http://localhost");
    expect(parsed.searchParams.get("actorId")).toBe("user_9");
    expect(parsed.searchParams.get("from")).toBe(String(Date.parse("2026-01-01")));
    expect(parsed.searchParams.get("to")).toBe(String(Date.parse("2026-01-31")));
    expect(parsed.searchParams.has("cursor")).toBe(false);
  });

  it("the export link's href carries the current filters", async () => {
    const fetchMock = vi.fn<typeof fetch>(async () =>
      jsonResponse(200, { items: [event()], nextCursor: null }),
    );
    vi.stubGlobal("fetch", fetchMock);
    const el = makeEl();
    document.body.appendChild(el);
    await vi.waitFor(() => expect(el.shadowRoot!.querySelector("form")).not.toBeNull());

    const form = el.shadowRoot!.querySelector("form")!;
    form.querySelector<HTMLInputElement>('[name="actorId"]')!.value = "user_9";
    form.dispatchEvent(new SubmitEvent("submit", { bubbles: true, cancelable: true }));
    await vi.waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(2));
    await vi.waitFor(() => expect(el.shadowRoot!.querySelector("a[download]")).not.toBeNull());

    const link = el.shadowRoot!.querySelector<HTMLAnchorElement>("a[download]")!;
    const parsed = new URL(link.getAttribute("href")!, "http://localhost");
    expect(parsed.pathname).toBe("/api/auth/enterprise/audit/export");
    expect(parsed.searchParams.get("orgId")).toBe("org_1");
    expect(parsed.searchParams.get("actorId")).toBe("user_9");
  });

  it('"Verify chain" shows an ok badge, then a broken badge on a different org', async () => {
    const fetchMock = vi.fn<typeof fetch>(async (input) => {
      const url = String(input);
      if (url.includes("/enterprise/audit/verify")) {
        return jsonResponse(200, { ok: true });
      }
      return jsonResponse(200, { items: [event()], nextCursor: null });
    });
    vi.stubGlobal("fetch", fetchMock);

    const el = makeEl();
    document.body.appendChild(el);
    await vi.waitFor(() => expect(el.shadowRoot!.querySelectorAll("tbody tr").length).toBe(1));

    const verifyButton = [...el.shadowRoot!.querySelectorAll("button")].find((b) =>
      b.textContent?.includes("Verify chain"),
    )!;
    verifyButton.click();
    await vi.waitFor(() => expect(el.shadowRoot!.textContent).toContain("Chain intact"));

    fetchMock.mockImplementation(async (input) => {
      const url = String(input);
      if (url.includes("/enterprise/audit/verify")) {
        return jsonResponse(200, { ok: false, brokenAtSeq: 7 });
      }
      return jsonResponse(200, { items: [event()], nextCursor: null });
    });
    verifyButton.click();
    await vi.waitFor(() => expect(el.shadowRoot!.textContent).toContain("Broken at seq 7"));
  });

  it("a failed verify renders an inline error without wiping the loaded rows", async () => {
    const fetchMock = vi.fn<typeof fetch>(async (input) => {
      const url = String(input);
      if (url.includes("/enterprise/audit/verify")) {
        return jsonResponse(500, { message: "Verify unavailable" });
      }
      return jsonResponse(200, { items: [event()], nextCursor: null });
    });
    vi.stubGlobal("fetch", fetchMock);

    const el = makeEl();
    document.body.appendChild(el);
    await vi.waitFor(() => expect(el.shadowRoot!.querySelectorAll("tbody tr").length).toBe(1));

    const verifyButton = [...el.shadowRoot!.querySelectorAll("button")].find((b) =>
      b.textContent?.includes("Verify chain"),
    )!;
    verifyButton.click();

    await vi.waitFor(() => expect(el.shadowRoot!.textContent).toContain("Verify unavailable"));
    // The load-error path would have replaced the whole view — asserting
    // the row and filter form are both still present proves this is the
    // inline `submitError` path instead.
    expect(el.shadowRoot!.querySelectorAll("tbody tr").length).toBe(1);
    expect(el.shadowRoot!.querySelector("form")).not.toBeNull();
  });
});

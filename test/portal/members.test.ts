// Alpha Bros enterprise layer — `<ab-members>` (Task 10).
//
// Pure DOM tests against a mocked `globalThis.fetch`: each test drives the
// real custom element (`document.createElement("ab-members")`, real shadow
// DOM, real events) and asserts on the actual requests `fetch` received and
// the actual rendered DOM, not on internal component state. `vi.waitFor` is
// used after every state-changing action because `AbMembers` kicks off its
// data fetch fire-and-forget from `connectedCallback`/event handlers rather
// than exposing a promise a test could await directly — matching how a real
// consumer of this element would observe it (poll the DOM), not a
// test-only backdoor.

import { afterEach, describe, expect, it, vi } from "vitest";
import "../../src/portal/index";
import type { AbMembers } from "../../src/portal/ab-members";

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

interface MemberFixture {
  id: string;
  userId: string;
  email: string;
  name: string;
  role: string;
  teams: string[];
}

function membersBody(members: MemberFixture[], invitations: unknown[] = []) {
  return { members, invitations };
}

function makeEl(orgId = "org_1"): AbMembers {
  const el = document.createElement("ab-members") as AbMembers;
  el.orgId = orgId;
  return el;
}

afterEach(() => {
  document.body.innerHTML = "";
  vi.unstubAllGlobals();
});

describe("<ab-members>", () => {
  it("upgrades with a shadow root", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>(async () => jsonResponse(200, membersBody([]))),
    );
    const el = makeEl();
    document.body.appendChild(el);
    await el.updateComplete;
    expect(el.shadowRoot).not.toBeNull();
  });

  it("fetches /enterprise/members and renders N member rows plus invitations", async () => {
    const fetchMock = vi.fn<typeof fetch>(async () =>
      jsonResponse(
        200,
        membersBody(
          [
            {
              id: "m1",
              userId: "u1",
              email: "owner@acme.test",
              name: "Owner",
              role: "owner",
              teams: ["acme"],
            },
            {
              id: "m2",
              userId: "u2",
              email: "dev@acme.test",
              name: "Dev",
              role: "member",
              teams: ["Platform"],
            },
          ],
          [
            {
              id: "i1",
              email: "pending@acme.test",
              role: "member",
              status: "pending",
              expiresAt: "2026-01-01T00:00:00.000Z",
            },
          ],
        ),
      ),
    );
    vi.stubGlobal("fetch", fetchMock);

    const el = makeEl();
    document.body.appendChild(el);

    await vi.waitFor(() => {
      expect(el.shadowRoot!.querySelectorAll("tbody tr").length).toBe(2);
    });

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0]!;
    expect(url).toBe("/api/auth/enterprise/members?orgId=org_1");
    expect((init as RequestInit).credentials).toBe("include");

    const rowText = el.shadowRoot!.querySelector("tbody tr")!.textContent ?? "";
    expect(rowText).toContain("owner@acme.test");
    expect(rowText).toContain("Owner");
    expect(rowText).toContain("acme");

    expect(el.shadowRoot!.textContent).toContain("pending@acme.test");
  });

  it("invite submit posts email+role+organizationId then re-fetches", async () => {
    const fetchMock = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(jsonResponse(200, membersBody([])))
      .mockResolvedValueOnce(jsonResponse(200, { id: "invite-1" }))
      .mockResolvedValueOnce(
        jsonResponse(
          200,
          membersBody([
            { id: "m3", userId: "u3", email: "new@acme.test", name: "", role: "member", teams: [] },
          ]),
        ),
      );
    vi.stubGlobal("fetch", fetchMock);

    const el = makeEl();
    document.body.appendChild(el);
    // Not `tbody tr` count === 0 — that's also true of the *loading* state
    // (no `<table>` rendered at all yet), so it can resolve before the
    // form exists. The form only renders once the load has settled.
    await vi.waitFor(() => expect(el.shadowRoot!.querySelector("form")).not.toBeNull());

    const changeHandler = vi.fn();
    el.addEventListener("ab-change", changeHandler);

    const form = el.shadowRoot!.querySelector("form")!;
    const emailInput = form.querySelector<HTMLInputElement>('input[name="email"]')!;
    const roleSelect = form.querySelector<HTMLSelectElement>('select[name="role"]')!;
    emailInput.value = "new@acme.test";
    roleSelect.value = "admin";
    form.dispatchEvent(new SubmitEvent("submit", { bubbles: true, cancelable: true }));

    await vi.waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(3));

    const [inviteUrl, inviteInit] = fetchMock.mock.calls[1]!;
    expect(inviteUrl).toBe("/api/auth/organization/invite-member");
    expect(JSON.parse((inviteInit as RequestInit).body as string)).toEqual({
      email: "new@acme.test",
      role: "admin",
      organizationId: "org_1",
    });

    const [refetchUrl] = fetchMock.mock.calls[2]!;
    expect(refetchUrl).toBe("/api/auth/enterprise/members?orgId=org_1");

    await vi.waitFor(() => expect(el.shadowRoot!.querySelectorAll("tbody tr").length).toBe(1));
    expect(changeHandler).toHaveBeenCalledTimes(1);
  });

  it("role select change posts to /organization/update-member-role then re-fetches", async () => {
    const fetchMock = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(
        jsonResponse(
          200,
          membersBody([
            {
              id: "m2",
              userId: "u2",
              email: "dev@acme.test",
              name: "Dev",
              role: "member",
              teams: [],
            },
          ]),
        ),
      )
      .mockResolvedValueOnce(jsonResponse(200, { member: { id: "m2" } }))
      .mockResolvedValueOnce(
        jsonResponse(
          200,
          membersBody([
            {
              id: "m2",
              userId: "u2",
              email: "dev@acme.test",
              name: "Dev",
              role: "admin",
              teams: [],
            },
          ]),
        ),
      );
    vi.stubGlobal("fetch", fetchMock);

    const el = makeEl();
    document.body.appendChild(el);
    await vi.waitFor(() => expect(el.shadowRoot!.querySelectorAll("tbody tr").length).toBe(1));

    const select = el.shadowRoot!.querySelector<HTMLSelectElement>("tbody select")!;
    select.value = "admin";
    select.dispatchEvent(new Event("change", { bubbles: true }));

    await vi.waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(3));
    const [url, init] = fetchMock.mock.calls[1]!;
    expect(url).toBe("/api/auth/organization/update-member-role");
    expect(JSON.parse((init as RequestInit).body as string)).toEqual({
      memberId: "m2",
      role: "admin",
      organizationId: "org_1",
    });
  });

  it("remove posts to /organization/remove-member after confirm, and re-fetches", async () => {
    const fetchMock = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(
        jsonResponse(
          200,
          membersBody([
            {
              id: "m2",
              userId: "u2",
              email: "dev@acme.test",
              name: "Dev",
              role: "member",
              teams: [],
            },
          ]),
        ),
      )
      .mockResolvedValueOnce(jsonResponse(200, { member: { id: "m2" } }))
      .mockResolvedValueOnce(jsonResponse(200, membersBody([])));
    vi.stubGlobal("fetch", fetchMock);

    const el = makeEl();
    el.confirm = () => true;
    document.body.appendChild(el);
    await vi.waitFor(() => expect(el.shadowRoot!.querySelectorAll("tbody tr").length).toBe(1));

    const removeButton = el.shadowRoot!.querySelector<HTMLButtonElement>("tbody button")!;
    removeButton.click();

    await vi.waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(3));
    const [url, init] = fetchMock.mock.calls[1]!;
    expect(url).toBe("/api/auth/organization/remove-member");
    expect(JSON.parse((init as RequestInit).body as string)).toEqual({
      memberIdOrEmail: "m2",
      organizationId: "org_1",
    });
    await vi.waitFor(() => expect(el.shadowRoot!.querySelectorAll("tbody tr").length).toBe(0));
  });

  it("remove does nothing when confirm is declined", async () => {
    const fetchMock = vi.fn<typeof fetch>().mockResolvedValueOnce(
      jsonResponse(
        200,
        membersBody([
          {
            id: "m2",
            userId: "u2",
            email: "dev@acme.test",
            name: "Dev",
            role: "member",
            teams: [],
          },
        ]),
      ),
    );
    vi.stubGlobal("fetch", fetchMock);

    const el = makeEl();
    el.confirm = () => false;
    document.body.appendChild(el);
    await vi.waitFor(() => expect(el.shadowRoot!.querySelectorAll("tbody tr").length).toBe(1));

    const removeButton = el.shadowRoot!.querySelector<HTMLButtonElement>("tbody button")!;
    removeButton.click();

    // Give any (wrongly fired) async work a chance to run before asserting
    // the negative — a bare synchronous assertion right after .click() could
    // pass even with a real bug if the extra fetch is dispatched a tick late.
    await new Promise((resolve) => setTimeout(resolve, 10));
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(el.shadowRoot!.querySelectorAll("tbody tr").length).toBe(1);
  });

  it("a failed invite renders an inline error without wiping the loaded roster", async () => {
    const fetchMock = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(
        jsonResponse(
          200,
          membersBody([
            {
              id: "m1",
              userId: "u1",
              email: "owner@acme.test",
              name: "Owner",
              role: "owner",
              teams: [],
            },
          ]),
        ),
      )
      .mockResolvedValueOnce(
        jsonResponse(409, { code: "ALREADY_INVITED", message: "Already invited" }),
      );
    vi.stubGlobal("fetch", fetchMock);

    const el = makeEl();
    document.body.appendChild(el);
    await vi.waitFor(() => expect(el.shadowRoot!.querySelectorAll("tbody tr").length).toBe(1));

    const form = el.shadowRoot!.querySelector("form")!;
    form.querySelector<HTMLInputElement>('input[name="email"]')!.value = "dup@acme.test";
    form.dispatchEvent(new SubmitEvent("submit", { bubbles: true, cancelable: true }));

    await vi.waitFor(() => expect(el.shadowRoot!.textContent).toContain("Already invited"));
    // The load-error path (`renderError` replacing the whole view) would
    // have dropped the table entirely — asserting both proves this is the
    // inline `submitError` path instead.
    expect(el.shadowRoot!.querySelectorAll("tbody tr").length).toBe(1);
    expect(el.shadowRoot!.querySelector("form")).not.toBeNull();
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });
});

// Alpha Bros enterprise layer — portal locale support.
//
// Two layers: the catalogue itself (every locale complete, placeholders
// intact) and the elements (`locale` attribute, fallback to the closest
// `lang`, then `en`; `locale="fr"` leaves no English on any tab).

import { afterEach, describe, expect, it, vi } from "vitest";
import "../../src/portal/index";
import type { AbSecuritySettings } from "../../src/portal/ab-security-settings";
import type { AbMembers } from "../../src/portal/ab-members";
import type { AbSsoWizard } from "../../src/portal/ab-sso-wizard";
import {
  MESSAGES,
  SUPPORTED_LOCALES,
  isMessageKey,
  matchLocale,
  translate,
  type Locale,
  type MessageKey,
} from "../../src/portal/i18n";

const KEYS = Object.keys(MESSAGES.en) as MessageKey[];
const TRANSLATED = SUPPORTED_LOCALES.filter((l): l is Exclude<Locale, "en"> => l !== "en");
const placeholders = (s: string): string[] =>
  [...s.matchAll(/\{(\w+)\}/g)].map((m) => m[1]!).sort();

/** Words that read the same in every language (product names, acronyms, the international "e-mail"-style terms). */
const SAME_EVERYWHERE = new Set<MessageKey>([
  "settings.tab.sso",
  "settings.tab.scim",
  "policy.method.sso",
  "policy.method.google",
  "policy.method.github",
  "policy.method.linkedin",
  "policy.method.microsoft",
  "policy.method.passkey",
  "scim.tokenLabel",
  "audit.col.actor",
  "audit.col.action",
  "audit.col.target",
  "members.col.name",
  "members.col.teams",
  "apiKeys.col.name",
  "policy.method.password",
  "policy.col.role",
  "members.col.email",
  "invitation.status.pending",
  "policy.session.1h",
  "apiKeys.nameLabel",
  "sso.recordName",
  "common.fieldLabel",
]);

function jsonResponse(body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { "content-type": "application/json" },
  });
}

const ROUTES: Array<[string, unknown]> = [
  ["/enterprise/features", { features: ["sso", "scim", "enforce_2fa", "api_keys", "audit_log"] }],
  [
    "/enterprise/members",
    {
      members: [
        { id: "m1", userId: "u1", email: "a@acme.com", name: "A", role: "admin", teams: [] },
      ],
      invitations: [
        { id: "i1", email: "b@acme.com", role: "member", status: "pending", expiresAt: "x" },
      ],
    },
  ],
  ["/enterprise/sso/providers", { providers: [] }],
  [
    "/enterprise/scim/tokens",
    { tokens: [{ providerId: "okta", createdAt: null, lastUsedAt: null }] },
  ],
  [
    "/enterprise/policy",
    {
      orgId: "org_1",
      require2fa: false,
      ssoEnforced: false,
      breakGlassUserId: null,
      sessionMaxAgeS: null,
      allowedMethods: ["sso"],
      groupRoleMap: { Admins: "admin" },
    },
  ],
  [
    "/api-key/list",
    { apiKeys: [{ id: "k1", name: "ci", start: "ab_", createdAt: "x", expiresAt: null }] },
  ],
  ["/enterprise/audit/list", { items: [], nextCursor: "next" }],
];

function stubFetch(): void {
  vi.stubGlobal(
    "fetch",
    vi.fn<typeof fetch>(async (input) => {
      const url = String(input);
      const route = ROUTES.find(([path]) => url.includes(path));
      return jsonResponse(route ? route[1] : {});
    }),
  );
}

/** Every string a user can see or hear in `root`, descending through nested shadow roots. */
function visibleText(root: ParentNode & { textContent: string | null }): string {
  const parts = [root.textContent ?? ""];
  for (const node of root.querySelectorAll("*")) {
    for (const attr of ["placeholder", "aria-label", "title"]) {
      const value = node.getAttribute(attr);
      if (value) parts.push(value);
    }
    if (node.shadowRoot) parts.push(visibleText(node.shadowRoot));
  }
  return parts.join("\n");
}

function makeSettings(
  attrs: Record<string, string> = {},
  parent?: HTMLElement,
): AbSecuritySettings {
  const el = document.createElement("ab-security-settings") as AbSecuritySettings;
  el.orgId = "org_1";
  for (const [k, v] of Object.entries(attrs)) el.setAttribute(k, v);
  (parent ?? document.body).appendChild(el);
  return el;
}

async function ready(el: AbSecuritySettings): Promise<void> {
  await vi.waitFor(() => expect(el.shadowRoot!.querySelectorAll('[role="tab"]').length).toBe(6));
}

function tabLabels(el: AbSecuritySettings): string[] {
  return [...el.shadowRoot!.querySelectorAll('[role="tab"]')].map((b) => b.textContent!.trim());
}

const savedLang = document.documentElement.getAttribute("lang");

afterEach(() => {
  document.body.innerHTML = "";
  if (savedLang === null) document.documentElement.removeAttribute("lang");
  else document.documentElement.setAttribute("lang", savedLang);
  vi.unstubAllGlobals();
});

describe("portal string catalogue", () => {
  it.each(TRANSLATED)("%s defines every key en does, and no other", (locale) => {
    expect(Object.keys(MESSAGES[locale]).sort()).toEqual([...KEYS].sort());
  });

  it.each(TRANSLATED)("%s keeps each {placeholder} of the en string", (locale) => {
    for (const key of KEYS) {
      expect(placeholders(MESSAGES[locale][key]), `${locale} ${key}`).toEqual(
        placeholders(MESSAGES.en[key]),
      );
    }
  });

  it.each(TRANSLATED)("%s has no entry left as the English source text", (locale) => {
    const untranslated = KEYS.filter(
      (key) => MESSAGES[locale][key] === MESSAGES.en[key] && !SAME_EVERYWHERE.has(key),
    );
    expect(untranslated).toEqual([]);
  });

  it("matches a tag by its primary subtag, case and separator insensitive", () => {
    expect(matchLocale("fr")).toBe("fr");
    expect(matchLocale("fr-CA")).toBe("fr");
    expect(matchLocale("DE_at")).toBe("de");
    expect(matchLocale("pt-BR")).toBeUndefined();
    expect(matchLocale("")).toBeUndefined();
    expect(matchLocale(null)).toBeUndefined();
  });

  it("fills placeholders and leaves an unknown one in place", () => {
    expect(translate("fr", "members.confirmRemove", { who: "a@acme.com" })).toBe(
      "Retirer a@acme.com de cette organisation ?",
    );
    expect(translate("en", "members.confirmRemove")).toBe("Remove {who} from this organization?");
  });

  it("only treats real catalogue keys as keys", () => {
    expect(isMessageKey("role.admin")).toBe(true);
    expect(isMessageKey("role.superuser")).toBe(false);
    expect(isMessageKey("toString")).toBe(false);
  });
});

describe("locale resolution", () => {
  it("renders English when neither locale nor lang is set", async () => {
    stubFetch();
    const el = makeSettings();
    await ready(el);
    expect(tabLabels(el)).toContain("Members");
    expect(el.resolvedLocale).toBe("en");
  });

  it("uses the locale attribute", async () => {
    stubFetch();
    const el = makeSettings({ locale: "fr" });
    await ready(el);
    expect(tabLabels(el)).toContain("Membres");
    expect(el.resolvedLocale).toBe("fr");
  });

  it("accepts a region-qualified locale", async () => {
    stubFetch();
    const el = makeSettings({ locale: "es-MX" });
    await ready(el);
    expect(tabLabels(el)).toContain("Miembros");
  });

  it("falls back to the closest lang attribute", async () => {
    stubFetch();
    document.documentElement.setAttribute("lang", "fr");
    const wrapper = document.createElement("div");
    wrapper.setAttribute("lang", "de");
    document.body.appendChild(wrapper);
    const el = makeSettings({}, wrapper);
    await ready(el);
    expect(tabLabels(el)).toContain("Mitglieder");
  });

  it("falls back to the document lang when no closer one is set", async () => {
    stubFetch();
    document.documentElement.setAttribute("lang", "it-IT");
    const el = makeSettings();
    await ready(el);
    expect(tabLabels(el)).toContain("Membri");
  });

  it("lets locale win over lang", async () => {
    stubFetch();
    document.documentElement.setAttribute("lang", "de");
    const el = makeSettings({ locale: "es" });
    await ready(el);
    expect(tabLabels(el)).toContain("Miembros");
  });

  it("falls through an unsupported locale to lang", async () => {
    stubFetch();
    document.documentElement.setAttribute("lang", "fr");
    const el = makeSettings({ locale: "ja" });
    await ready(el);
    expect(tabLabels(el)).toContain("Membres");
  });

  it("falls back to en when the closest lang is unsupported, even under a supported one", async () => {
    stubFetch();
    document.documentElement.setAttribute("lang", "fr");
    const wrapper = document.createElement("div");
    wrapper.setAttribute("lang", "ja");
    document.body.appendChild(wrapper);
    const el = makeSettings({}, wrapper);
    await ready(el);
    expect(tabLabels(el)).toContain("Members");
  });

  it("falls back to en for an unsupported locale with no lang", async () => {
    stubFetch();
    const el = makeSettings({ locale: "ja" });
    await ready(el);
    expect(tabLabels(el)).toContain("Members");
  });

  it("reads lang across a shadow root", async () => {
    stubFetch();
    const host = document.createElement("div");
    host.setAttribute("lang", "de");
    document.body.appendChild(host);
    const shadow = host.attachShadow({ mode: "open" });
    const members = document.createElement("ab-members") as AbMembers;
    members.orgId = "org_1";
    shadow.appendChild(members);
    expect(members.resolvedLocale).toBe("de");
  });

  it("re-renders when locale changes", async () => {
    stubFetch();
    const el = makeSettings({ locale: "fr" });
    await ready(el);
    el.setAttribute("locale", "de");
    await vi.waitFor(() => expect(tabLabels(el)).toContain("Mitglieder"));
  });

  it("hands the resolved locale to the tab it stamps", async () => {
    stubFetch();
    document.documentElement.setAttribute("lang", "it");
    const el = makeSettings();
    await ready(el);
    await vi.waitFor(() =>
      expect(el.shadowRoot!.querySelector("ab-members")!.getAttribute("locale")).toBe("it"),
    );
  });
});

describe('<ab-security-settings locale="fr">', () => {
  it("renders no English string on any tab", async () => {
    stubFetch();
    const el = makeSettings({ locale: "fr" });
    await ready(el);

    const english = KEYS.filter(
      (k) => MESSAGES.en[k] !== MESSAGES.fr[k] && !MESSAGES.en[k].includes("{"),
    ).map((k) => MESSAGES.en[k]);
    expect(english.length).toBeGreaterThan(50);

    const seen: Record<string, string> = {};
    const tags: Record<string, string> = {
      members: "ab-members",
      sso: "ab-sso-wizard",
      scim: "ab-scim-tokens",
      policy: "ab-security-policy",
      "api-keys": "ab-api-keys",
      audit: "ab-audit-log",
    };
    for (const tab of Object.keys(tags)) {
      el.shadowRoot!.querySelector<HTMLButtonElement>(`button[data-tab="${tab}"]`)!.click();
      await vi.waitFor(() => {
        const child = el.shadowRoot!.querySelector<HTMLElement>(tags[tab]!);
        expect(child?.shadowRoot?.querySelector(".ab-loading")).toBeNull();
        expect(child?.shadowRoot?.children.length ?? 0).toBeGreaterThan(0);
      });
      // The SAML form has its own labels: render it too.
      if (tab === "sso") {
        const wizard = el.shadowRoot!.querySelector<AbSsoWizard>("ab-sso-wizard")!;
        wizard.ssoType = "saml";
        await wizard.updateComplete;
      }
      seen[tab] = visibleText(el.shadowRoot!);
    }

    for (const [tab, text] of Object.entries(seen)) {
      // Whole-string match on a line/attribute: `Name` must not match inside `Provider name`.
      const lines = new Set(text.split("\n").map((l) => l.replace(/\s+/g, " ").trim()));
      for (const line of english) expect(lines.has(line), `${tab}: "${line}"`).toBe(false);
    }
    expect(seen["members"]).toContain("Invitations en attente");
    expect(seen["sso"]).toContain("Certificat de signature SAML");
    expect(seen["scim"]).toContain("Renouveler le jeton");
    expect(seen["policy"]).toContain("Exiger l’authentification à deux facteurs");
    expect(seen["api-keys"]).toContain("Créer une clé");
    expect(seen["audit"]).toContain("Exporter en CSV");
  });

  it("localises the locked-tab notice and the not-entitled fallback", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>(async () => jsonResponse({ features: [] })),
    );
    const el = makeSettings({ locale: "fr", tabs: "sso" });
    await ready2(el);
    expect(visibleText(el.shadowRoot!)).toContain("Cette fonctionnalité n’est pas incluse");
  });

  it("localises confirmation prompts", async () => {
    stubFetch();
    const el = makeSettings({ locale: "fr" });
    await ready(el);
    await vi.waitFor(() => expect(el.shadowRoot!.querySelector("ab-members")).not.toBeNull());
    const members = el.shadowRoot!.querySelector<AbMembers>("ab-members")!;
    const confirm = vi.fn(() => false);
    members.confirm = confirm;
    await vi.waitFor(() =>
      expect(members.shadowRoot!.querySelector("tbody button")).not.toBeNull(),
    );
    members.shadowRoot!.querySelector<HTMLButtonElement>("tbody button")!.click();
    expect(confirm).toHaveBeenCalledWith("Retirer a@acme.com de cette organisation ?");
  });
});

/** `ready` expects the default six tabs; a `tabs` override renders fewer. */
async function ready2(el: AbSecuritySettings): Promise<void> {
  await vi.waitFor(() => expect(el.shadowRoot!.querySelectorAll('[role="tab"]').length).toBe(1));
}

// The audit route table is complete by construction (audit 3 F-13, fix plan
// PR-6): every endpoint a preset instance mounts — with the one product
// plugin the fleet adds, `magicLink()` — is audited by the plugin, audits
// itself, or is listed as deliberately unaudited with a reason. A new
// upstream endpoint (a better-auth bump, a new preset plugin) fails this
// test until someone decides which it is.

import { describe, expect, it } from "vitest";
import { magicLink } from "better-auth/plugins";
import { makeAuth } from "../helpers/auth";
import {
  AUDITED_PATHS,
  auditEntryFor,
  SELF_AUDITED_PATHS,
  UNAUDITED_PATHS,
  UNAUDITED_SERVER_ONLY_ENDPOINTS,
} from "../../src/server/audit/plugin";

interface MountedEndpoint {
  name: string;
  path: string | undefined;
  methods: string[];
}

async function mountedEndpoints(): Promise<MountedEndpoint[]> {
  const t = await makeAuth({ plugins: [magicLink({ sendMagicLink: async () => {} })] });
  const api = t.auth.api as unknown as Record<
    string,
    { path?: string; options?: { method?: string | string[] } }
  >;
  return Object.entries(api).map(([name, endpoint]) => {
    const method = endpoint?.options?.method;
    return {
      name,
      path: endpoint?.path,
      methods: Array.isArray(method) ? method : method ? [method] : [],
    };
  });
}

function unauditedFor(path: string, method: string): string | null {
  const entry = UNAUDITED_PATHS[path];
  if (!entry) return null;
  if (entry.methods && !entry.methods.includes(method)) return null;
  return entry.reason;
}

describe("audit route table — every mounted endpoint is decided", () => {
  it("each HTTP endpoint and method is audited, self-audited, or unaudited with a reason — never none, never two", async () => {
    const undecided: string[] = [];
    const doubled: string[] = [];
    for (const endpoint of await mountedEndpoints()) {
      if (!endpoint.path) continue;
      for (const method of endpoint.methods) {
        const decisions = [
          auditEntryFor(endpoint.path, method) ? "audited" : null,
          endpoint.path in SELF_AUDITED_PATHS ? "self-audited" : null,
          unauditedFor(endpoint.path, method) ? "unaudited" : null,
        ].filter(Boolean);
        if (decisions.length === 0) undecided.push(`${method} ${endpoint.path}`);
        if (decisions.length > 1)
          doubled.push(`${method} ${endpoint.path}: ${decisions.join("+")}`);
      }
    }
    expect(undecided).toEqual([]);
    expect(doubled).toEqual([]);
  });

  it("each path-less server-only endpoint is listed by name with a reason", async () => {
    const pathless = (await mountedEndpoints()).filter((e) => !e.path).map((e) => e.name);
    expect(pathless.length).toBeGreaterThan(0);
    for (const name of pathless) {
      expect(UNAUDITED_SERVER_ONLY_ENDPOINTS[name], name).toMatch(/\S/);
    }
  });

  it("every reason is stated, and no path is both audited and self-audited", () => {
    for (const [path, { reason }] of Object.entries(UNAUDITED_PATHS)) {
      expect(reason.length, path).toBeGreaterThan(10);
    }
    for (const path of Object.keys(SELF_AUDITED_PATHS)) {
      expect(AUDITED_PATHS[path], path).toBeUndefined();
    }
  });

  it("pins the paths earlier reviews found missing: IdP update/delete, /api-key/update, the shared SSO callback, /admin/*, org lifecycle, 2FA, sessions", () => {
    const pinned: Record<string, string> = {
      "/sso/update-provider": "sso.provider_updated",
      "/sso/delete-provider": "sso.provider_deleted",
      "/sso/callback": "auth.sso_sign_in",
      "/callback/:id": "auth.sign_in",
      "/api-key/update": "api_key.updated",
      "/admin/impersonate-user": "admin.impersonation_started",
      "/admin/stop-impersonating": "admin.impersonation_stopped",
      "/admin/set-role": "admin.user_role_changed",
      "/admin/ban-user": "admin.user_banned",
      "/admin/remove-user": "admin.user_removed",
      "/organization/delete": "org.deleted",
      "/organization/leave": "member.left",
      "/change-password": "user.password_changed",
      "/two-factor/disable": "two_factor.disabled",
      "/two-factor/verify-totp": "auth.sign_in",
      "/revoke-sessions": "session.revoked_all",
    };
    for (const [path, action] of Object.entries(pinned)) {
      expect(AUDITED_PATHS[path]?.action, path).toBe(action);
    }
  });
});

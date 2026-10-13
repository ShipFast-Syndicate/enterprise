// GHSA-8p84-pc7q-69jr — audit gap 2, route table and decision helpers.
//
// Every endpoint upstream ships that can create or continue a session —
// found by scanning the pinned `better-auth` and `@better-auth/*` builds for
// `createSession(` / `handleOAuthUserInfo(` and listing the routes those
// files declare — is pinned below with its outcome under `require2fa`. A
// route is allowed to stand only when its method carries a second factor
// (`satisfiedBy`), when upstream's `twoFactor()` challenge follows it, when
// it is `/sign-up/email` (a brand-new user, confined to enrolment), or when
// it is a continuation; everything else is refused. A new upstream route —
// or one that moves — changes the discovered set and fails the pin, so it
// is reviewed here before it can stand.
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import type { BetterAuthPlugin } from "better-auth";
import { twoFactor } from "better-auth/plugins";
import {
  classifySessionCreate,
  DEFAULT_TWO_FACTOR_SATISFIED_BY,
  TWO_FACTOR_ENROLLMENT_ALLOWED_PATHS,
  twoFactorChallengeFollows,
  twoFactorEnrollmentAllowedPaths,
  twoFactorRefusal,
  twoFactorSatisfiedBy,
} from "../../src/server/policy/enforcement";
import type { EnterpriseOptions } from "../../src/server/types";

// --- upstream census ---------------------------------------------------------

function walk(dir: string, out: string[] = []): string[] {
  for (const entry of readdirSync(dir)) {
    const path = join(dir, entry);
    if (statSync(path).isDirectory()) walk(path, out);
    else if (path.endsWith(".mjs")) out.push(path);
  }
  return out;
}

/** `{ "<package>/dist/…": [routes] }` for every upstream build file that creates a session (directly or through the OAuth user-info helper). */
function sessionCreatingRoutes(): Record<string, string[]> {
  const modules = join(process.cwd(), "node_modules");
  const roots = [
    join(modules, "better-auth", "dist"),
    ...readdirSync(join(modules, "@better-auth")).map((name) =>
      join(modules, "@better-auth", name, "dist"),
    ),
  ];
  const table: Record<string, string[]> = {};
  for (const root of roots) {
    let files: string[];
    try {
      files = walk(root);
    } catch {
      continue;
    }
    for (const file of files) {
      const source = readFileSync(file, "utf8");
      if (!/createSession\(|handleOAuthUserInfo\(/.test(source)) continue;
      const routes = [...source.matchAll(/createAuthEndpoint\(\s*"([^"]+)"/g)].map((m) => m[1]!);
      table[file.slice(modules.length + 1)] = routes;
    }
  }
  return table;
}

/**
 * The census at the pinned upstream versions (better-auth 1.7.5 and its
 * companions). Every route declared in a session-creating file, whether or
 * not that particular route creates a session itself (a file's non-session
 * routes are listed too — they can only be refused, never stand).
 */
const PINNED_ROUTES: Record<string, string[]> = {
  "better-auth/dist/api/routes/callback.mjs": ["/callback/:id"],
  "better-auth/dist/api/routes/email-verification.mjs": [
    "/send-verification-email",
    "/verify-email",
  ],
  "better-auth/dist/api/routes/sign-in.mjs": ["/sign-in/social", "/sign-in/email"],
  "better-auth/dist/api/routes/sign-up.mjs": ["/sign-up/email"],
  "better-auth/dist/api/routes/update-user.mjs": [
    "/update-user",
    "/change-password",
    "/delete-user",
    "/delete-user/callback",
    "/change-email",
  ],
  "better-auth/dist/oauth2/link-account.mjs": [],
  "better-auth/dist/plugins/admin/routes.mjs": [
    "/admin/set-role",
    "/admin/get-user",
    "/admin/create-user",
    "/admin/update-user",
    "/admin/list-users",
    "/admin/list-user-sessions",
    "/admin/unban-user",
    "/admin/ban-user",
    "/admin/impersonate-user",
    "/admin/stop-impersonating",
    "/admin/revoke-user-session",
    "/admin/revoke-user-sessions",
    "/admin/remove-user",
    "/admin/set-user-password",
    "/admin/has-permission",
  ],
  "better-auth/dist/plugins/anonymous/index.mjs": ["/sign-in/anonymous", "/delete-anonymous-user"],
  "better-auth/dist/plugins/device-authorization/routes.mjs": [
    "/device/code",
    "/device/token",
    "/device",
    "/device/approve",
    "/device/deny",
  ],
  "better-auth/dist/plugins/email-otp/routes.mjs": [
    "/email-otp/send-verification-otp",
    "/email-otp/check-verification-otp",
    "/email-otp/verify-email",
    "/sign-in/email-otp",
    "/email-otp/request-password-reset",
    "/forget-password/email-otp",
    "/email-otp/reset-password",
    "/email-otp/request-email-change",
    "/email-otp/change-email",
  ],
  "better-auth/dist/plugins/magic-link/index.mjs": ["/sign-in/magic-link", "/magic-link/verify"],
  "better-auth/dist/plugins/oauth-proxy/index.mjs": [
    "/callback/:id/oauth-proxy",
    "/oauth-proxy-callback",
  ],
  "better-auth/dist/plugins/one-tap/index.mjs": ["/one-tap/callback"],
  "better-auth/dist/plugins/phone-number/routes.mjs": [
    "/sign-in/phone-number",
    "/phone-number/send-otp",
    "/phone-number/verify",
    "/phone-number/request-password-reset",
    "/phone-number/reset-password",
  ],
  "better-auth/dist/plugins/siwe/index.mjs": ["/siwe/verify"],
  "better-auth/dist/plugins/test-utils/auth-helpers.mjs": [],
  "better-auth/dist/plugins/two-factor/index.mjs": ["/two-factor/enable", "/two-factor/disable"],
  "better-auth/dist/plugins/two-factor/otp/index.mjs": [
    "/two-factor/send-otp",
    "/two-factor/verify-otp",
  ],
  "better-auth/dist/plugins/two-factor/totp/index.mjs": [
    "/two-factor/get-totp-uri",
    "/two-factor/verify-totp",
  ],
  "better-auth/dist/plugins/two-factor/verify-two-factor.mjs": [],
  "better-auth/dist/plugins/username/index.mjs": ["/sign-in/username", "/is-username-available"],
  "@better-auth/passkey/dist/index.mjs": [
    "/passkey/generate-register-options",
    "/passkey/generate-authenticate-options",
    "/passkey/verify-registration",
    "/passkey/verify-authentication",
    "/passkey/list-user-passkeys",
    "/passkey/delete-passkey",
    "/passkey/update-passkey",
  ],
  "@better-auth/sso/dist/index.mjs": [
    "/sso/providers",
    "/sso/get-provider",
    "/sso/update-provider",
    "/sso/delete-provider",
    "/sso/request-domain-verification",
    "/sso/verify-domain",
    "/sso/saml2/sp/metadata",
    "/sso/register",
    "/sign-in/sso",
    "/sso/callback/:providerId",
    "/sso/callback",
    "/sso/saml2/sp/acs/:providerId",
    "/sso/saml2/sp/slo/:providerId",
    "/sso/saml2/logout/:providerId",
  ],
};

/**
 * The routes whose session may stand under `require2fa` with the default
 * options, and why. Everything else in the census is refused.
 */
const STANDS: Record<string, "satisfiedBy" | "challenge" | "sign-up" | "continuation"> = {
  "/sso/callback/:providerId": "satisfiedBy",
  "/sso/callback": "satisfiedBy",
  "/sso/saml2/sp/acs/:providerId": "satisfiedBy",
  "/sign-in/email": "challenge",
  "/sign-up/email": "sign-up",
  "/two-factor/enable": "continuation",
  "/two-factor/disable": "continuation",
  "/two-factor/verify-totp": "continuation",
  "/two-factor/verify-otp": "continuation",
  "/two-factor/verify-backup-code": "continuation",
  "/change-password": "continuation",
  "/admin/impersonate-user": "continuation",
};

/**
 * `@better-auth/sso` routes that live in the census file but never mint a
 * session (provider management, metadata, logout). `classifySessionCreate`
 * names every `/sso/*` path `sso`, so they are listed here rather than
 * judged: a new `/sso/*` route upstream adds is *not* on this list and is
 * therefore judged — and, being named `sso`, would stand — which fails the
 * census assertion below until it is reviewed.
 */
const SSO_NON_SESSION_ROUTES = new Set([
  "/sso/providers",
  "/sso/get-provider",
  "/sso/update-provider",
  "/sso/delete-provider",
  "/sso/request-domain-verification",
  "/sso/verify-domain",
  "/sso/saml2/sp/metadata",
  "/sso/register",
  "/sso/saml2/sp/slo/:providerId",
  "/sso/saml2/logout/:providerId",
]);

const withTwoFactor = { options: { plugins: [twoFactor()] as BetterAuthPlugin[] } };

/** Partial `EnterpriseOptions` carrying only a `policy` block — all the decision helpers read. */
function withPolicy(policy: NonNullable<EnterpriseOptions["policy"]>): EnterpriseOptions {
  return { policy } as unknown as EnterpriseOptions;
}

/** The refusal (its code) or `null` for a session created from `path` under `require2fa`. */
function outcome(
  path: string,
  extra: { params?: Record<string, string>; body?: unknown; session?: unknown } = {},
  opts?: EnterpriseOptions,
): string | null {
  const ctx = {
    path,
    params: extra.params,
    body: extra.body,
    context: { ...withTwoFactor, session: extra.session ?? null },
  };
  const refusal = twoFactorRefusal(ctx, classifySessionCreate(ctx, opts, { userId: "u1" }), opts);
  return refusal ? String(refusal.body?.code) : null;
}

describe("gap 2 — every upstream session-creating route is pinned with its outcome under require2fa", () => {
  it("the census of session-creating upstream files and their routes is exactly the pinned table", () => {
    const discovered = sessionCreatingRoutes();
    expect(Object.keys(discovered).sort()).toEqual(Object.keys(PINNED_ROUTES).sort());
    for (const [file, routes] of Object.entries(PINNED_ROUTES)) {
      expect(discovered[file], file).toEqual(routes);
    }
    // `/two-factor/verify-backup-code` creates its session through the shared
    // `verifyTwoFactor` helper (a path-less file in the census); pinned by
    // name so its continuation status is asserted like the others.
    expect(discovered["better-auth/dist/plugins/two-factor/verify-two-factor.mjs"]).toEqual([]);
  });

  it("only satisfiedBy methods, challenged paths, sign-up and continuations stand; every other route in the census is refused", () => {
    const census = [
      ...new Set([...Object.values(PINNED_ROUTES).flat(), "/two-factor/verify-backup-code"]),
    ];
    expect(Object.keys(STANDS).every((p) => census.includes(p))).toBe(true);
    expect([...SSO_NON_SESSION_ROUTES].every((p) => census.includes(p))).toBe(true);
    for (const path of census) {
      if (SSO_NON_SESSION_ROUTES.has(path)) continue;
      const params = path.includes(":id") ? { id: "github" } : undefined;
      const body = path === "/sign-in/social" ? { provider: "google" } : undefined;
      const result = outcome(path, { params, body });
      if (path in STANDS) {
        expect(result, path).toBeNull();
      } else {
        // A named method that carries no second factor is refused as such;
        // an unclassifiable path is refused as an unknown method.
        const classified = classifySessionCreate({ path, params, body }, undefined, {
          userId: "u1",
        });
        expect(result, path).toBe(
          classified.kind === "method" ? "TWO_FACTOR_REQUIRED" : "METHOD_NOT_ALLOWED",
        );
      }
    }
  });

  it("the routes that stand each stand for exactly the pinned reason", () => {
    for (const [path, reason] of Object.entries(STANDS)) {
      const classified = classifySessionCreate({ path }, undefined, { userId: "u1" });
      switch (reason) {
        case "satisfiedBy":
          expect(classified, path).toEqual({ kind: "method", method: "sso" });
          expect(DEFAULT_TWO_FACTOR_SATISFIED_BY).toContain("sso");
          // Taken out of `satisfiedBy`, the same route is refused.
          expect(outcome(path, {}, withPolicy({ twoFactor: { satisfiedBy: [] } }))).toBe(
            "TWO_FACTOR_REQUIRED",
          );
          break;
        case "challenge":
          expect(classified, path).toEqual({ kind: "method", method: "password" });
          expect(twoFactorChallengeFollows({ path, context: withTwoFactor })).toBe(true);
          break;
        case "sign-up":
          expect(classified, path).toEqual({ kind: "method", method: "password" });
          expect(twoFactorChallengeFollows({ path, context: withTwoFactor })).toBe(true);
          break;
        case "continuation":
          expect(classified, path).toEqual({ kind: "continuation", path });
          break;
      }
    }
  });

  it("/verify-email stands only as a continuation of the same user's session; /sign-in/social without a provider is an unknown method", () => {
    expect(outcome("/verify-email")).toBe("TWO_FACTOR_REQUIRED");
    expect(outcome("/verify-email", { session: { user: { id: "u1" } } })).toBeNull();
    expect(outcome("/verify-email", { session: { user: { id: "someone-else" } } })).toBe(
      "TWO_FACTOR_REQUIRED",
    );
    expect(outcome("/sign-in/social")).toBe("METHOD_NOT_ALLOWED");
    expect(outcome("/sign-in/social", { body: { provider: "github" } })).toBe(
      "TWO_FACTOR_REQUIRED",
    );
    expect(outcome("/callback/:id")).toBe("METHOD_NOT_ALLOWED");
    expect(outcome("/callback/:id", { params: { id: "google" } })).toBe("TWO_FACTOR_REQUIRED");
    expect(outcome("/callback/google")).toBe("TWO_FACTOR_REQUIRED");
  });

  it("a challenged path declared through policy.signInMethods stands because the challenge follows, not because of its name", () => {
    const opts = withPolicy({
      signInMethods: { "/sign-in/username": "username", "/sign-in/email-otp": "email_otp" },
    });
    // Upstream's `twoFactor()` challenges `/sign-in/username`, so the
    // session it creates is withdrawn for an enrolled user like a password one.
    expect(outcome("/sign-in/username", {}, opts)).toBeNull();
    // `/sign-in/email-otp` is not challenged: a name alone buys nothing.
    expect(outcome("/sign-in/email-otp", {}, opts)).toBe("TWO_FACTOR_REQUIRED");
    // Unless the product vouches for it.
    expect(
      outcome(
        "/sign-in/email-otp",
        {},
        withPolicy({ ...opts.policy, twoFactor: { satisfiedBy: ["email_otp"] } }),
      ),
    ).toBeNull();
  });
});

describe("gap 2 — the challenge decision is read from the mounted twoFactor() plugin", () => {
  it("upstream's after-hook challenges exactly /sign-in/email, /sign-in/username and /sign-in/phone-number among the census", () => {
    const census = Object.values(PINNED_ROUTES).flat();
    const challenged = census.filter((path) =>
      twoFactorChallengeFollows({ path, context: withTwoFactor }),
    );
    expect(challenged.sort()).toEqual([
      "/sign-in/email",
      "/sign-in/phone-number",
      "/sign-in/username",
      "/sign-up/email", // this layer's one addition: nothing to challenge yet, enrolment-only session
    ]);
  });

  it("without the plugin no challenge follows (fail closed): /sign-in/email is refused, only /sign-up/email stands", () => {
    const none = { options: { plugins: [] as BetterAuthPlugin[] } };
    expect(twoFactorChallengeFollows({ path: "/sign-in/email", context: none })).toBe(false);
    expect(twoFactorChallengeFollows({ path: "/sign-in/email", context: null })).toBe(false);
    expect(twoFactorChallengeFollows({ path: "/sign-in/email" })).toBe(false);
    expect(twoFactorChallengeFollows({ path: "/sign-up/email", context: none })).toBe(true);
    expect(twoFactorChallengeFollows({ context: withTwoFactor })).toBe(false);
    const ctx = { path: "/sign-in/email", context: { ...none, session: null } };
    expect(String(twoFactorRefusal(ctx, classifySessionCreate(ctx))?.body?.code)).toBe(
      "TWO_FACTOR_REQUIRED",
    );
  });

  it("a matcher that cannot be consulted with the path alone counts as no challenge", () => {
    const throwing: BetterAuthPlugin = {
      id: "two-factor",
      hooks: {
        after: [
          {
            matcher: () => {
              throw new Error("needs a full context");
            },
            handler: (async () => {}) as never,
          },
        ],
      },
    };
    expect(
      twoFactorChallengeFollows({
        path: "/sign-in/email",
        context: { options: { plugins: [throwing] } },
      }),
    ).toBe(false);
  });

  it("satisfiedBy defaults to [sso] and is taken verbatim from the options", () => {
    expect(twoFactorSatisfiedBy()).toEqual(["sso"]);
    expect(twoFactorSatisfiedBy({} as EnterpriseOptions)).toEqual(["sso"]);
    expect(
      twoFactorSatisfiedBy({
        policy: { twoFactor: { satisfiedBy: ["passkey"] } },
      } as EnterpriseOptions),
    ).toEqual(["passkey"]);
    expect(
      twoFactorSatisfiedBy({
        policy: { twoFactor: { satisfiedBy: [] as string[] } },
      } as EnterpriseOptions),
    ).toEqual([]);
  });
});

describe("gap 2 — the enrolment allow-list", () => {
  it("is pinned: the session read, sign-out, the public home-realm probe and upstream's enrolment endpoints", () => {
    expect([...TWO_FACTOR_ENROLLMENT_ALLOWED_PATHS]).toEqual([
      "/get-session",
      "/sign-out",
      "/enterprise/home-realm",
      "/two-factor/enable",
      "/two-factor/get-totp-uri",
      "/two-factor/verify-totp",
      "/two-factor/send-otp",
      "/two-factor/verify-otp",
    ]);
    // Every `/two-factor/*` entry is a route upstream really declares.
    const twoFactorRoutes = Object.entries(PINNED_ROUTES)
      .filter(([file]) => file.includes("/two-factor/"))
      .flatMap(([, routes]) => routes);
    for (const path of TWO_FACTOR_ENROLLMENT_ALLOWED_PATHS) {
      if (path.startsWith("/two-factor/")) expect(twoFactorRoutes, path).toContain(path);
    }
    // No session-creating sign-in route is on it: a stale enrolment-only
    // session cannot start another sign-in, only finish enrolling or leave.
    for (const [path, reason] of Object.entries(STANDS)) {
      if (reason === "continuation") continue; // `/two-factor/*` enrolment steps are the point
      expect(TWO_FACTOR_ENROLLMENT_ALLOWED_PATHS.has(path), path).toBe(false);
    }
  });

  it("policy.twoFactor.enrollmentPaths is appended, never replaces", () => {
    expect(twoFactorEnrollmentAllowedPaths()).toBe(TWO_FACTOR_ENROLLMENT_ALLOWED_PATHS);
    expect(twoFactorEnrollmentAllowedPaths({} as EnterpriseOptions)).toBe(
      TWO_FACTOR_ENROLLMENT_ALLOWED_PATHS,
    );
    const merged = twoFactorEnrollmentAllowedPaths({
      policy: { twoFactor: { enrollmentPaths: ["/zz-product/enrol"] } },
    } as EnterpriseOptions);
    expect([...merged]).toEqual([...TWO_FACTOR_ENROLLMENT_ALLOWED_PATHS, "/zz-product/enrol"]);
  });
});

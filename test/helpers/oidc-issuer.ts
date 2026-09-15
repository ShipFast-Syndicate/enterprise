// Test helper: an in-process OIDC issuer (`node:http`) for the SSO
// end-to-end tests (`test/e2e/oidc.test.ts`, `test/e2e/jit.test.ts`). Serves
// the 5 endpoints `@better-auth/sso@1.6.33`'s OIDC code-flow path needs when
// registered with `oidcConfig.skipDiscovery: true` (ruling (a)):
// `/.well-known/openid-configuration`, `/jwks`, `/authorize`, `/token`,
// `/userinfo`.
//
// This flow goes through the id_token/jwks path, not the userinfo path
// (`processOIDCCallback` in `@better-auth/sso` only calls `userInfoEndpoint`
// when the registered provider config sets one — the tests here register
// without it, per `test/server/enterprise-api.test.ts`'s existing OIDC
// registration pattern), so `/userinfo` exists for completeness/parity with
// the brief rather than being exercised by these tests.
//
// Every OIDC endpoint but `/authorize` is re-validated as a "publicly
// routable host" on *every* `/sign-in/sso` call and callback (`@better-auth/
// sso`'s `assertOIDCEndpointsResolvePublic`/`validateSkipDiscoveryEndpoint`,
// an SSRF guard against internal IdPs) — a loopback origin like this issuer's
// fails that check unless the auth instance's `trustedOrigins` explicitly
// allow-lists it. `test/helpers/auth.ts`'s `makeAuth` accepts a
// `trustedOrigins` override for exactly this; every OIDC/JIT test must pass
// `[issuer.issuerUrl]` there.

import { createServer, get as httpGet, type IncomingMessage, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { randomUUID } from "node:crypto";
import { SignJWT, exportJWK, generateKeyPair } from "jose";

export interface OidcIssuerUser {
  sub: string;
  email: string;
}

export interface OidcIssuer {
  /** Origin the issuer listens on, e.g. `http://127.0.0.1:54321` — pass this to `makeAuth({ trustedOrigins: [issuer.issuerUrl] })`. */
  issuerUrl: string;
  authorizationEndpoint: string;
  tokenEndpoint: string;
  jwksEndpoint: string;
  userInfoEndpoint: string;
  discoveryEndpoint: string;
  clientId: string;
  clientSecret: string;
  /** Sets the identity `/token`'s id_token (and `/userinfo`) assert for every subsequent `/authorize` round trip. */
  setUser(user: OidcIssuerUser): void;
  close(): Promise<void>;
}

async function readBody(req: IncomingMessage): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of req) chunks.push(chunk as Buffer);
  return Buffer.concat(chunks).toString("utf8");
}

function parseBasicAuth(
  header: string | undefined,
): { clientId: string; clientSecret: string } | null {
  if (!header?.startsWith("Basic ")) return null;
  const decoded = Buffer.from(header.slice("Basic ".length), "base64").toString("utf8");
  const sep = decoded.indexOf(":");
  if (sep === -1) return null;
  return { clientId: decoded.slice(0, sep), clientSecret: decoded.slice(sep + 1) };
}

export async function startOidcIssuer(
  opts: { clientId?: string; clientSecret?: string; user?: OidcIssuerUser } = {},
): Promise<OidcIssuer> {
  const clientId = opts.clientId ?? "test-client";
  const clientSecret = opts.clientSecret ?? "test-client-secret";
  const kid = "test-issuer-key-1";
  const { publicKey, privateKey } = await generateKeyPair("RS256", { extractable: true });
  const publicJwk = { ...(await exportJWK(publicKey)), kid, alg: "RS256", use: "sig" };

  let currentUser: OidcIssuerUser = opts.user ?? { sub: "test-user-1", email: "user@example.test" };
  // code -> the `nonce` (if any) the /authorize request carried, so /token can echo it.
  const issuedCodes = new Map<string, { nonce?: string }>();

  let issuerUrl = "";

  const server: Server = createServer((req, res) => {
    void (async () => {
      const url = new URL(req.url ?? "/", "http://placeholder.invalid");

      if (url.pathname === "/.well-known/openid-configuration") {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(
          JSON.stringify({
            issuer: issuerUrl,
            authorization_endpoint: `${issuerUrl}/authorize`,
            token_endpoint: `${issuerUrl}/token`,
            jwks_uri: `${issuerUrl}/jwks`,
            userinfo_endpoint: `${issuerUrl}/userinfo`,
          }),
        );
        return;
      }

      if (url.pathname === "/jwks") {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ keys: [publicJwk] }));
        return;
      }

      if (url.pathname === "/authorize") {
        const redirectUri = url.searchParams.get("redirect_uri");
        if (!redirectUri) {
          res.writeHead(400, { "content-type": "text/plain" });
          res.end("missing redirect_uri");
          return;
        }
        const code = randomUUID();
        issuedCodes.set(code, { nonce: url.searchParams.get("nonce") ?? undefined });
        const location = new URL(redirectUri);
        location.searchParams.set("code", code);
        const state = url.searchParams.get("state");
        if (state) location.searchParams.set("state", state);
        res.writeHead(302, { location: location.toString() });
        res.end();
        return;
      }

      if (url.pathname === "/token" && req.method === "POST") {
        const rawBody = await readBody(req);
        const params = new URLSearchParams(rawBody);
        const basic = parseBasicAuth(req.headers.authorization);
        const suppliedClientId = basic?.clientId ?? params.get("client_id");
        const suppliedClientSecret = basic?.clientSecret ?? params.get("client_secret");
        if (suppliedClientId !== clientId || suppliedClientSecret !== clientSecret) {
          res.writeHead(401, { "content-type": "application/json" });
          res.end(JSON.stringify({ error: "invalid_client" }));
          return;
        }
        const code = params.get("code") ?? "";
        const pending = issuedCodes.get(code);
        issuedCodes.delete(code);
        if (!pending) {
          res.writeHead(400, { "content-type": "application/json" });
          res.end(JSON.stringify({ error: "invalid_grant" }));
          return;
        }

        const now = Math.floor(Date.now() / 1000);
        const idToken = await new SignJWT({
          email: currentUser.email,
          email_verified: true,
          ...(pending.nonce ? { nonce: pending.nonce } : {}),
        })
          .setProtectedHeader({ alg: "RS256", kid })
          .setSubject(currentUser.sub)
          .setIssuer(issuerUrl)
          .setAudience(clientId)
          .setIssuedAt(now)
          .setExpirationTime(now + 300)
          .sign(privateKey);

        res.writeHead(200, { "content-type": "application/json" });
        res.end(
          JSON.stringify({
            access_token: `test-access-token-${code}`,
            token_type: "Bearer",
            expires_in: 300,
            id_token: idToken,
          }),
        );
        return;
      }

      if (url.pathname === "/userinfo") {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(
          JSON.stringify({ sub: currentUser.sub, email: currentUser.email, email_verified: true }),
        );
        return;
      }

      res.writeHead(404, { "content-type": "text/plain" });
      res.end("not found");
    })().catch((err) => {
      res.writeHead(500, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: "internal_error", detail: String(err) }));
    });
  });

  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address() as AddressInfo;
  issuerUrl = `http://127.0.0.1:${address.port}`;

  return {
    issuerUrl,
    authorizationEndpoint: `${issuerUrl}/authorize`,
    tokenEndpoint: `${issuerUrl}/token`,
    jwksEndpoint: `${issuerUrl}/jwks`,
    userInfoEndpoint: `${issuerUrl}/userinfo`,
    discoveryEndpoint: `${issuerUrl}/.well-known/openid-configuration`,
    clientId,
    clientSecret,
    setUser(user) {
      currentUser = user;
    },
    close: () =>
      new Promise<void>((resolve, reject) => {
        server.close((err) => (err ? reject(err) : resolve()));
      }),
  };
}

/** GETs `url` without following the redirect — for reading `/authorize`'s `Location` header directly. Uses `node:http` rather than `fetch(..., {redirect:"manual"})`: an opaque-redirect fetch response hides response headers per the WHATWG spec, which would make `Location` unreadable. */
export function getNoRedirect(url: string): Promise<{ status: number; location: string | null }> {
  return new Promise((resolve, reject) => {
    httpGet(url, (res) => {
      res.resume(); // drain, we don't need the body
      resolve({ status: res.statusCode ?? 0, location: res.headers.location ?? null });
    }).on("error", reject);
  });
}

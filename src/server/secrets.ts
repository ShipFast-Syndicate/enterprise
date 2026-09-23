import { getCurrentAdapter } from "@better-auth/core/context";
// Alpha Bros enterprise layer — encryption at rest for IdP secrets (C-04).
//
// `EnterpriseOptions.secretsKey` used to be a *declared but entirely unused*
// option: `grep -rn secretsKey src/` found only its own declaration, while
// the design spec (§7.4) promises "IdP OIDC client secrets: encrypted in the
// DB with `secretsKey` from 1Password". A DB dump showed
// `ssoProvider.oidcConfig` holding `{"clientId":"cid","clientSecret":
// "SUPERSECRET",...}` verbatim — so anyone with database read (a backup, a
// replica, a logged query, a SQL injection elsewhere in the embedding
// product) got every tenant's IdP credentials. A required option that does
// nothing is worse than no option at all, because embedders assume §7.4 is
// implemented.
//
// Design:
//
// - **Where.** A transparent wrapper around `context.adapter`, installed
//   from `enterpriseGate`'s `init()` (`./gate.ts`). better-auth's
//   `runPluginInit` merges a plugin's returned `context` into the live
//   `AuthContext` and only *afterwards* builds `internalAdapter` from
//   `context.adapter` (`node_modules/better-auth/dist/context/helpers.mjs`),
//   so both access paths inherit the wrapper. Every `@better-auth/sso` read
//   and write of `ssoProvider` goes through `ctx.context.adapter`
//   (verified by grep over `@better-auth/sso@1.6.33`'s `dist/index.mjs` —
//   `adapter.create` at :2723, `adapter.findOne` at :1379/:2890/:2898/:3050,
//   `adapter.update` at :1525, `adapter.findMany` at :1359/:2905), so the
//   OIDC callback still receives a plaintext `clientSecret` while the row on
//   disk holds ciphertext.
// - **What.** `oidcConfig.clientSecret`, plus the SAML private-key material
//   in `samlConfig` (`privateKey`, `privateKeyPass`, `decryptionPvk`,
//   `encPrivateKey`, `encPrivateKeyPass`, and the same keys nested under
//   `spMetadata`). Public material (certs, endpoints, client ids) is left
//   readable so operators can still inspect a row.
// - **How.** AES-256-GCM via Web Crypto (no `node:crypto` — this package
//   must keep running on workerd), key = SHA-256 of `secretsKey`, a fresh
//   random 12-byte IV per value, output `enc:v1:<base64url(iv || ct||tag)>`.
// - **Migration.** A value that doesn't carry the `enc:v1:` prefix is
//   returned untouched on read, so existing plaintext rows keep working and
//   are re-encrypted the next time they're written.

import type { AuthContext } from "better-auth";

type Adapter = AuthContext["adapter"];

const PREFIX = "enc:v1:";
const IV_BYTES = 12;

/** Minimum `secretsKey` length the README/`types.ts` have always documented (L-08). */
export const MIN_SECRETS_KEY_LENGTH = 32;

/**
 * Throws if `secretsKey` is missing or shorter than 32 characters (L-08).
 * Until C-04 the rule was documented but never enforced anywhere — a product
 * could ship `secretsKey: "x"` and nothing complained, because nothing read
 * the value at all. Now that it is load-bearing, it is validated at
 * construction time (`enterprisePreset`) rather than on first use.
 */
export function assertSecretsKey(secretsKey: string): void {
  if (typeof secretsKey !== "string" || secretsKey.length < MIN_SECRETS_KEY_LENGTH) {
    throw new Error(
      `enterprisePreset: "secretsKey" must be a string of at least ${MIN_SECRETS_KEY_LENGTH} characters — it encrypts IdP client secrets and SAML private keys at rest.`,
    );
  }
}

function toBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function fromBase64Url(value: string): Uint8Array {
  const padded = value.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(padded.padEnd(Math.ceil(padded.length / 4) * 4, "="));
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

const keyCache = new Map<string, Promise<CryptoKey>>();

function importKey(secretsKey: string): Promise<CryptoKey> {
  let key = keyCache.get(secretsKey);
  if (!key) {
    key = (async () => {
      const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(secretsKey));
      return crypto.subtle.importKey("raw", digest, { name: "AES-GCM" }, false, [
        "encrypt",
        "decrypt",
      ]);
    })();
    keyCache.set(secretsKey, key);
  }
  return key;
}

/**
 * `enc:v1:<base64url(iv || ciphertext||tag)>` — AES-256-GCM, fresh IV per
 * call, **bound to `aad`** (the owning provider's `providerId`) as GCM
 * additional authenticated data.
 *
 * The binding is what makes a ciphertext non-transplantable: copying a
 * sealed `clientSecret` from one `ssoProvider` row onto another — the move
 * available to anyone who can write the database but not read the key —
 * produces a decryption failure rather than silently re-pointing a working
 * IdP credential at a provider the attacker controls.
 */
export async function encryptSecret(
  plaintext: string,
  secretsKey: string,
  aad: string,
): Promise<string> {
  const key = await importKey(secretsKey);
  const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES));
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: "AES-GCM", iv, additionalData: new TextEncoder().encode(aad) },
      key,
      new TextEncoder().encode(plaintext),
    ),
  );
  const packed = new Uint8Array(iv.length + ciphertext.length);
  packed.set(iv, 0);
  packed.set(ciphertext, iv.length);
  return `${PREFIX}${toBase64Url(packed)}`;
}

export function isEncrypted(value: unknown): value is string {
  return typeof value === "string" && value.startsWith(PREFIX);
}

/**
 * Inverse of `encryptSecret`, including the `aad` binding. A value without
 * the `enc:v1:` prefix is returned unchanged (migration-friendly: rows
 * written before this shipped are plaintext and must keep working). A
 * prefixed value that fails to decrypt throws — a wrong or rotated
 * `secretsKey`, or a ciphertext lifted from another provider's row, must be
 * loud, not silently produce a garbage client secret that then fails at the
 * IdP with an unexplainable error.
 */
export async function decryptSecret(
  value: string,
  secretsKey: string,
  aad: string,
): Promise<string> {
  if (!isEncrypted(value)) return value;
  const key = await importKey(secretsKey);
  const packed = fromBase64Url(value.slice(PREFIX.length));
  const iv = packed.slice(0, IV_BYTES);
  const ciphertext = packed.slice(IV_BYTES);
  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv, additionalData: new TextEncoder().encode(aad) },
    key,
    ciphertext,
  );
  return new TextDecoder().decode(plaintext);
}

// --- which fields of which model carry secret material ---------------------

const SECRET_MODEL = "ssoProvider";

/** JSON-string columns of `ssoProvider`, and the keys inside each that are secret. */
const SECRET_JSON_FIELDS: Record<string, { keys: string[]; nested?: string[] }> = {
  oidcConfig: { keys: ["clientSecret"] },
  samlConfig: {
    keys: ["privateKey", "privateKeyPass", "decryptionPvk", "encPrivateKey", "encPrivateKeyPass"],
    nested: ["spMetadata"],
  },
};

type Json = Record<string, unknown>;

async function mapSecretKeys(
  config: Json,
  spec: { keys: string[]; nested?: string[] },
  transform: (value: string) => Promise<string>,
): Promise<Json> {
  const out: Json = { ...config };
  for (const key of spec.keys) {
    const value = out[key];
    if (typeof value === "string" && value.length > 0) out[key] = await transform(value);
  }
  for (const key of spec.nested ?? []) {
    const nested = out[key];
    if (nested && typeof nested === "object" && !Array.isArray(nested)) {
      out[key] = await mapSecretKeys(nested as Json, { keys: spec.keys }, transform);
    }
  }
  return out;
}

/**
 * Applies `transform` to every secret key of every secret-bearing JSON field
 * of a `ssoProvider` row/payload, preserving whether that field was stored
 * as a JSON *string* (what `@better-auth/sso` writes) or already-parsed
 * object (what a `type: "json"` adapter may hand back). Anything that isn't
 * parseable JSON is left exactly as-is rather than destroyed.
 */
async function mapProviderSecrets(
  data: Json,
  transform: (value: string) => Promise<string>,
): Promise<Json> {
  let out = data;
  for (const [field, spec] of Object.entries(SECRET_JSON_FIELDS)) {
    const raw = out[field];
    if (raw === null || raw === undefined) continue;

    let parsed: Json | null = null;
    let wasString = false;
    if (typeof raw === "string") {
      wasString = true;
      try {
        const candidate: unknown = JSON.parse(raw);
        if (candidate && typeof candidate === "object" && !Array.isArray(candidate)) {
          parsed = candidate as Json;
        }
      } catch {
        parsed = null; // not JSON (or legacy/garbage) — leave the value alone
      }
    } else if (typeof raw === "object" && !Array.isArray(raw)) {
      parsed = raw as Json;
    }
    if (!parsed) continue;

    const mapped = await mapSecretKeys(parsed, spec, transform);
    if (out === data) out = { ...data };
    out[field] = wasString ? JSON.stringify(mapped) : mapped;
  }
  return out;
}

const encryptPayload = (data: unknown, secretsKey: string, aad: string): Promise<unknown> =>
  data && typeof data === "object" && !Array.isArray(data)
    ? mapProviderSecrets(data as Json, (value) =>
        isEncrypted(value) ? Promise.resolve(value) : encryptSecret(value, secretsKey, aad),
      )
    : Promise.resolve(data);

/**
 * Decrypts a row read back from the adapter. The AAD is the row's own
 * `providerId`; a row that doesn't carry one (no upstream or in-package read
 * path narrows the column set — `@better-auth/sso@1.6.33` uses no `select`
 * anywhere, verified by grep — so this is defensive) is returned untouched
 * rather than throwing, since an undecryptable-but-present ciphertext is
 * more useful to an operator than a failed request.
 */
const decryptRow = async (row: unknown, secretsKey: string): Promise<unknown> => {
  if (!row || typeof row !== "object" || Array.isArray(row)) return row;
  const aad = (row as { providerId?: unknown }).providerId;
  if (typeof aad !== "string") return row;
  return mapProviderSecrets(row as Json, (value) => decryptSecret(value, secretsKey, aad));
};

// --- the adapter wrapper ---------------------------------------------------

interface ModelParams {
  model?: unknown;
  data?: unknown;
  update?: unknown;
  where?: unknown;
}

function isSecretModel(params: unknown): boolean {
  return (params as ModelParams | undefined)?.model === SECRET_MODEL;
}

function whereValue(params: ModelParams, field: string): string | null {
  const where = params.where;
  if (!Array.isArray(where)) return null;
  for (const clause of where as Array<{ field?: unknown; value?: unknown; operator?: unknown }>) {
    if (clause?.field === field && typeof clause.value === "string") {
      if (clause.operator === undefined || clause.operator === "eq") return clause.value;
    }
  }
  return null;
}

/**
 * The AAD for a write: the `providerId` of the row being written.
 *
 * Resolved from the payload first (`create` always carries it —
 * `@better-auth/sso@1.6.33`'s register call, `dist/index.mjs:2723`), then
 * from an `eq` clause on `providerId` in the `where` (which is how upstream
 * updates address the row, `:1525`), and finally by reading the row back by
 * `id` through the *unwrapped* adapter (no recursion, and no decryption
 * needed — only the `providerId` column is used).
 *
 * `null` means "cannot bind this write", and the caller refuses rather than
 * writing an unbound — or worse, plaintext — secret.
 */
async function resolveWriteAad(
  target: Pick<Adapter, "findOne">,
  params: ModelParams,
  payload: unknown,
): Promise<string | null> {
  const fromPayload = (payload as { providerId?: unknown } | undefined)?.providerId;
  if (typeof fromPayload === "string" && fromPayload) return fromPayload;

  const fromWhere = whereValue(params, "providerId");
  if (fromWhere) return fromWhere;

  const id = whereValue(params, "id");
  if (!id) return null;
  const row = await target.findOne<{ providerId?: string }>({
    model: SECRET_MODEL,
    where: [{ field: "id", value: id }],
  });
  return typeof row?.providerId === "string" ? row.providerId : null;
}

/** Only thrown for a write this wrapper cannot bind — never for ordinary traffic. */
function unbindableWrite(operation: string): Error {
  return new Error(
    `@alphabros/enterprise: refusing to write ${SECRET_MODEL} secret material via "${operation}" without a resolvable providerId — the ciphertext is bound to it, so an unbound write could not be read back. Include providerId in the payload or address the row by providerId/id.`,
  );
}

/** Whether a payload actually carries any secret-bearing field worth binding. */
function touchesSecrets(payload: unknown): boolean {
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) return false;
  return Object.keys(SECRET_JSON_FIELDS).some(
    (field) => (payload as Json)[field] !== undefined && (payload as Json)[field] !== null,
  );
}

/**
 * Returns `adapter` with transparent encrypt-on-write / decrypt-on-read for
 * `ssoProvider` secret material. Every other model, and every other adapter
 * method, is passed straight through untouched.
 *
 * A `Proxy` (rather than an object spread) so that adapter implementations
 * which add methods this package doesn't know about — or which rely on
 * `this` — keep working unchanged.
 */
export function withSecretEncryption(adapter: Adapter, secretsKey: string): Adapter {
  return wrapAdapter(adapter, secretsKey, true);
}

function wrapAdapter(adapter: Adapter, secretsKey: string, followTransaction: boolean): Adapter {
  const proxy = new Proxy(adapter, {
    get(target, prop, receiver) {
      const value = Reflect.get(target, prop, receiver) as unknown;
      if (typeof value !== "function") return value;
      const call = async (params: unknown): Promise<unknown> => {
        const active = followTransaction ? await getCurrentAdapter(target) : target;
        if (active !== target && active !== proxy) {
          const method = Reflect.get(active, prop) as (input: unknown) => Promise<unknown>;
          return method.call(active, params);
        }
        return value.call(target, params);
      };

      switch (prop) {
        case "transaction":
          return (callback: (transaction: Adapter) => Promise<unknown>) =>
            target.transaction((transaction) =>
              callback(wrapAdapter(transaction as Adapter, secretsKey, false)),
            );
        case "create":
          return async (params: ModelParams) => {
            if (!isSecretModel(params)) return call(params);
            if (!touchesSecrets(params.data)) return decryptRow(await call(params), secretsKey);
            const aad = await resolveWriteAad(
              followTransaction ? await getCurrentAdapter(target) : target,
              params,
              params.data,
            );
            if (!aad) throw unbindableWrite("create");
            const data = await encryptPayload(params.data, secretsKey, aad);
            return decryptRow(await call({ ...params, data }), secretsKey);
          };
        case "update":
        case "updateMany":
          return async (params: ModelParams) => {
            if (!isSecretModel(params)) return call(params);
            if (!touchesSecrets(params.update)) return decryptRow(await call(params), secretsKey);
            const aad = await resolveWriteAad(
              followTransaction ? await getCurrentAdapter(target) : target,
              params,
              params.update,
            );
            if (!aad) throw unbindableWrite(String(prop));
            const update = await encryptPayload(params.update, secretsKey, aad);
            return decryptRow(await call({ ...params, update }), secretsKey);
          };
        case "findOne":
          return async (params: unknown) => {
            const row = await call(params);
            return isSecretModel(params) ? decryptRow(row, secretsKey) : row;
          };
        case "findMany":
          return async (params: unknown) => {
            const rows = await call(params);
            if (!isSecretModel(params) || !Array.isArray(rows)) return rows;
            return Promise.all(rows.map((row) => decryptRow(row, secretsKey)));
          };
        default:
          return call;
      }
    },
  }) as Adapter;
  return proxy;
}

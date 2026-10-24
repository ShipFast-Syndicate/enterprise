## [1.1.2](https://github.com/ShipFast-Syndicate/enterprise/compare/v1.1.1...v1.1.2) (2026-10-24)

### Bug Fixes

* **deps:** bump zod to 4.6.7 (GHSA-mrhx-c7xc-m3w5) ([#56](https://github.com/ShipFast-Syndicate/enterprise/issues/56)) ([84d5f62](https://github.com/ShipFast-Syndicate/enterprise/commit/84d5f625d342ecb306ed256392c0412e17dd83b6))
* **deps:** override undici to 7.30.1 (GHSA-xjj6-f33q-929c) ([#58](https://github.com/ShipFast-Syndicate/enterprise/issues/58)) ([a294e5a](https://github.com/ShipFast-Syndicate/enterprise/commit/a294e5aa6d9d83249f0816ac9d66b1f264078684))
* **deps:** widen better-auth/better-call peer ranges and upgrade dependencies to latest ([#59](https://github.com/ShipFast-Syndicate/enterprise/issues/59)) ([a98eef4](https://github.com/ShipFast-Syndicate/enterprise/commit/a98eef404f037eadc1d631f0a5ccb190ae654c37))

## [1.1.1](https://github.com/ShipFast-Syndicate/enterprise/compare/v1.1.0...v1.1.1) (2026-10-14)

### Bug Fixes

* **deps:** require better-auth 1.7.7 and read its magic-link rows ([#31](https://github.com/ShipFast-Syndicate/enterprise/issues/31)) ([41690a2](https://github.com/ShipFast-Syndicate/enterprise/commit/41690a2e12b7ade9893f485f6c9291473be745fc)), closes [#27](https://github.com/ShipFast-Syndicate/enterprise/issues/27)

## [1.1.0](https://github.com/ShipFast-Syndicate/enterprise/compare/v1.0.1...v1.1.0) (2026-10-13)

### Features

* **policy,audit:** foundations for the 1.1.0 security release ([3d620d2](https://github.com/ShipFast-Syndicate/enterprise/commit/3d620d2d0957589ee4dd2b12c8eb2e3d19a81335))

### Bug Fixes

* **api-keys:** bind API keys to the live user, expire them by default, revoke them on every deprovisioning path and keep them off the management surface ([b45a44c](https://github.com/ShipFast-Syndicate/enterprise/commit/b45a44c4b27907bb51ca02fc1a0c457a944f12f6))
* **api-keys:** confine a key to an allow-list — /get-session and upstream's own verify call — instead of a deny-list, and expose the per-key rate limit ([f259e5e](https://github.com/ShipFast-Syndicate/enterprise/commit/f259e5e5adcc53883af063d25dfd947ed98623fa))
* **api-keys:** keep the expiry bound on update and refuse a key on every key, organization, account and credential write ([c192d1f](https://github.com/ShipFast-Syndicate/enterprise/commit/c192d1f49ff9a01b431cb20ecdc71cba7191f0d5))
* **api-keys:** refuse a key on every SSO provider, account-linking and OAuth-token path, and enforce the refusal in the validator whatever carries the key ([272e63f](https://github.com/ShipFast-Syndicate/enterprise/commit/272e63f75fad50d3e161b716008df5eab1d774f6))
* **audit:** bind org rows to the acted-on resource, bound every request value, gate provider changes ([f01958b](https://github.com/ShipFast-Syndicate/enterprise/commit/f01958be99b86e424c1d4b9ebfba57d044e0a7af))
* **audit:** classify refusals from the package's own code, bound request values, keep caller-chosen rows off the response path ([f6b3599](https://github.com/ShipFast-Syndicate/enterprise/commit/f6b3599b2e2e1da89d4006efa843b23a63447182))
* **audit:** gate the org each endpoint acts on, keep walker cases reaching gated paths, answer 500 when an audit row is missing ([fdc1f94](https://github.com/ShipFast-Syndicate/enterprise/commit/fdc1f94d319f98a2ef2a52615456aeabb15e1665))
* **audit:** record sign-ins, staff and IdP changes in the right org chains, attributed to the caller ([5de066d](https://github.com/ShipFast-Syndicate/enterprise/commit/5de066d6104a7402a09a750703ffb70a6f95239a))
* **audit:** refuse org ids that are not ids before any query, bound every audit writer, log failed queries without SQL ([aa613ac](https://github.com/ShipFast-Syndicate/enterprise/commit/aa613ac80c3d6fa1731839e0c7917eab01d91bad))
* **ci:** make public package release self-contained ([aacbdb7](https://github.com/ShipFast-Syndicate/enterprise/commit/aacbdb7f67d59f7b33d270f58540e36775a1ba35))
* **ci:** restore Dependabot progress and update coverage ([#17](https://github.com/ShipFast-Syndicate/enterprise/issues/17)) ([d4ff9a5](https://github.com/ShipFast-Syndicate/enterprise/commit/d4ff9a524d5126e19b671ea982285ed2955256b5))
* **cli:** ask for --from when a folder holds an earlier 0001 without 0002 ([0050dff](https://github.com/ShipFast-Syndicate/enterprise/commit/0050dffa0dd39e90ebefdf7ef98a0122f70e4194))
* **cli:** match emitted migration names without a dynamic RegExp ([8382345](https://github.com/ShipFast-Syndicate/enterprise/commit/83823455dc07aa6871f019bb4d683c8dc235e22d))
* **deps:** force handlebars >= 4.7.10 (critical GHSA-p8wg-vrv2-v86f) ([9b31890](https://github.com/ShipFast-Syndicate/enterprise/commit/9b31890aa235c016a691886466d00a310b6b7fad))
* **deps:** override source-map-js >= 1.2.2 and record the unpatched braces advisory ([3e04ebf](https://github.com/ShipFast-Syndicate/enterprise/commit/3e04ebf0f786684be04d517180b85faa4295ed52)), closes [rendra#493](https://github.com/ShipFast-Syndicate/rendra/issues/493)
* **deps:** retry when CodeQL finishes just after CI ([#18](https://github.com/ShipFast-Syndicate/enterprise/issues/18)) ([8fc8581](https://github.com/ShipFast-Syndicate/enterprise/commit/8fc8581bdc83eabc822b9c03224f6fd1902f839d))
* **policy:** enforce require2fa at session creation and on every request, and require an enrolled enabler ([1780b2f](https://github.com/ShipFast-Syndicate/enterprise/commit/1780b2f852ca0ab0b26972a85561dcc50cc1d937))
* **policy:** enforce the union of org policies, clamp session refresh, close the pre-auth oracle ([10e0e47](https://github.com/ShipFast-Syndicate/enterprise/commit/10e0e47cf05dddcd875da8a4e2441438e65ad8d2))
* **policy:** judge allowedMethods narrowing against the full method vocabulary ([45c974f](https://github.com/ShipFast-Syndicate/enterprise/commit/45c974fc0be2c8466a0ae32a35781795152b23e7))
* **policy:** judge an API key's owner under require2fa, and let migrate emit from a given migration ([3627619](https://github.com/ShipFast-Syndicate/enterprise/commit/3627619a189277c7618c54728c57497079abe203))
* **policy:** judge require2fa standing from existing timestamps, answer null on /get-session, and keep the enabling admin able to sign in ([77d9a06](https://github.com/ShipFast-Syndicate/enterprise/commit/77d9a06a26e583f74c73461d9a1ef900e1dd704f))
* **policy:** paginate the membership scan, enforce /verify-email auto-sign-in, match the shared SSO callback ([cd0eb5b](https://github.com/ShipFast-Syndicate/enterprise/commit/cd0eb5b517b473e056a40c48c69d0045db3e97bf))
* **policy:** re-judge require2fa on a standing session and follow the bearer carrier ([22680aa](https://github.com/ShipFast-Syndicate/enterprise/commit/22680aa20dd144d703aaf7067d9c2fd85c3688aa))
* **secrets,scim:** never trust enc:v1 prefix on write; SCIM decommission owner-only ([bcc9506](https://github.com/ShipFast-Syndicate/enterprise/commit/bcc9506db0291ebbd748ad5998db26af0c06023a))
* **sso:** bind domain verification to provider organization ([#20](https://github.com/ShipFast-Syndicate/enterprise/issues/20)) ([d6db777](https://github.com/ShipFast-Syndicate/enterprise/commit/d6db7771377780f765aa579d481e0764671cc451))
* **sso:** bind SSO sign-ins to the provider's verified domain, one org per verified domain, issuer allow-list ([ee83d35](https://github.com/ShipFast-Syndicate/enterprise/commit/ee83d355b8adc2acd09770def34e737f8387fd17))
* **sso:** bind the issuer allow-list to the IdP endpoints; stop SSO_DOMAIN_TAKEN echoing another org's domains ([b3ae767](https://github.com/ShipFast-Syndicate/enterprise/commit/b3ae76711acb09359ccbfebba50b5006a8bf7d32))
* **sso:** derive the SAML signing trust root through samlify — pin the union of what samlify verifies against and every literal signing certificate, fail closed ([da18f73](https://github.com/ShipFast-Syndicate/enterprise/commit/da18f73ee087dda7ecef1bbb63141631d4799d1a))
* **sso:** pin the SAML trust root — sso.allowedIssuers now binds the signing certificate, fail closed, and re-checks stored providers at sign-in ([019cd40](https://github.com/ShipFast-Syndicate/enterprise/commit/019cd400a2e13658b2c9fb3cc1ba3140c7c978dd))

## [1.0.1](https://github.com/ShipFast-Syndicate/enterprise/compare/v1.0.0...v1.0.1) (2026-09-23)

### Bug Fixes

* **sso:** release provider-bound domain verification ([#21](https://github.com/ShipFast-Syndicate/enterprise/issues/21)) ([611f225](https://github.com/ShipFast-Syndicate/enterprise/commit/611f22504ecb8d5fa86eef05912777a980881f1d)), closes [#19](https://github.com/ShipFast-Syndicate/enterprise/issues/19)

## [1.0.0](https://github.com/ShipFast-Syndicate/enterprise/compare/v0.1.0...v1.0.0) (2026-09-23)

### ⚠ BREAKING CHANGES

* migrate enterprise provisioning to patched Better Auth 1.7

### Bug Fixes

* **ci:** isolate public pull request jobs and minimize secrets ([360af9d](https://github.com/ShipFast-Syndicate/enterprise/commit/360af9df873dae68eb7996a6f25539fee8f42b0d))
* **ci:** make public package release self-contained ([f9c42c3](https://github.com/ShipFast-Syndicate/enterprise/commit/f9c42c37fa8446fac7d0e55d1f88c666c5ed5a9c))
* migrate enterprise provisioning to patched Better Auth 1.7 ([743a462](https://github.com/ShipFast-Syndicate/enterprise/commit/743a46291d0f69a7fb1bbc3b821e10aa328c2d0e))

## [0.1.0](https://github.com/ShipFast-Syndicate/enterprise/compare/v0.0.0...v0.1.0) (2026-09-16)

### Features

* **client:** enterprise client plugin and home-realm helper ([44dd0e7](https://github.com/ShipFast-Syndicate/enterprise/commit/44dd0e767fc124aec5797a1d6fbde690cada5283))
* **portal:** base element, settings shell and members ([c758fe1](https://github.com/ShipFast-Syndicate/enterprise/commit/c758fe10b65bc7276bcb67bc7bfd9e32171f2153))
* **portal:** policy, api keys and audit log ([cd4acca](https://github.com/ShipFast-Syndicate/enterprise/commit/cd4acca8d10eac7becd1a442d717e116b767db94))
* **portal:** SSO wizard and SCIM tokens ([51d9658](https://github.com/ShipFast-Syndicate/enterprise/commit/51d9658c97133c2d9a1562ed7779f439036e3e94))
* **schema:** enterprise tables, verify and CLI ([a247bc0](https://github.com/ShipFast-Syndicate/enterprise/commit/a247bc0f58eed619effb66f010354a8247d5b2fe))
* **server:** audit log plugin with per-org hash chain ([237468c](https://github.com/ShipFast-Syndicate/enterprise/commit/237468ca71ca8a1aac1bb6df35613154e172a6ce))
* **server:** enterprise portal API endpoints ([ac5068d](https://github.com/ShipFast-Syndicate/enterprise/commit/ac5068d76119cd6f9b20f5ccd29c6808e9ddad8a))
* **server:** enterprisePreset and SAML/OIDC end-to-end coverage ([c8ec57e](https://github.com/ShipFast-Syndicate/enterprise/commit/c8ec57eb400f35291b04203bd79d3b44c72c3ec7))
* **server:** entitlements and gate plugin ([b4bcdc8](https://github.com/ShipFast-Syndicate/enterprise/commit/b4bcdc835efc6687cc6680b3d1d735a8d86634c7))
* **server:** org policy plugin, home-realm discovery, deprovision cascade ([527170e](https://github.com/ShipFast-Syndicate/enterprise/commit/527170eb2ebeaa6536a20893c25d4da3bce1fdac))
* **server:** SCIM 2.0 Groups plugin mapped to organization teams ([56c32de](https://github.com/ShipFast-Syndicate/enterprise/commit/56c32deb41c1fb79eeaf45e390f49278d4b9e9d3))

### Bug Fixes

* **audit:** chain the first post-compaction write from the anchor's lastHash ([dcee102](https://github.com/ShipFast-Syndicate/enterprise/commit/dcee1022a7c3764cc0cdf9561718cf98fa5c7753))
* **audit:** paged verify; crash-safe compaction ([aa26ba7](https://github.com/ShipFast-Syndicate/enterprise/commit/aa26ba79185aa4bd91f80bd42e45b22a01765433))
* **build:** deterministic tsup output, Low findings, security docs ([4ecb7b9](https://github.com/ShipFast-Syndicate/enterprise/commit/4ecb7b9b6e7bcc5b381ebcb26212a111cdca8840))
* **cli:** drizzle journal entry on migrate ([e788775](https://github.com/ShipFast-Syndicate/enterprise/commit/e788775e127560fa943f1a9ff962b769575a5f8e))
* **policy:** admins may enable SSO enforcement with an existing break-glass user ([e8c0a48](https://github.com/ShipFast-Syndicate/enterprise/commit/e8c0a4890ad3b02af9ef685949dbb7a95c4b183b))
* **portal:** clear stale inline error on audit-log reload ([b1a4098](https://github.com/ShipFast-Syndicate/enterprise/commit/b1a40984588b40bdf3ecbc1e843cf325a5af7264))
* **portal:** inline mutation errors, required break-glass user, shared table/shown-once helpers ([1ea7144](https://github.com/ShipFast-Syndicate/enterprise/commit/1ea7144fbe0fdba16c7901670f9c383e94f50ecc))
* **release:** harden release.yml against template injection and floating pins ([8fca32f](https://github.com/ShipFast-Syndicate/enterprise/commit/8fca32f9c3e6be9d233d70627f5acd08c45c47a3))
* **release:** manual first publish without provenance; idempotent publish job ([daa0a84](https://github.com/ShipFast-Syndicate/enterprise/commit/daa0a843785f1135f3a002897960a3100346847f))
* **schema:** don't re-export migrationFilePath from the public barrel ([ee386a3](https://github.com/ShipFast-Syndicate/enterprise/commit/ee386a331ffa5c341600845e1a4fb81f08013e88))
* **schema:** SQL-aware statement splitter; shared test options ([5db5090](https://github.com/ShipFast-Syndicate/enterprise/commit/5db5090e54ce3ff65d5e4c9958394cab1ab78223))
* **security:** C-01, C-02 — audit-log tenancy and retention compaction ([284d9c1](https://github.com/ShipFast-Syndicate/enterprise/commit/284d9c1d985a4f3103888cc7b4814acdc0dfbfc9))
* **security:** C-03, M-03, M-04 — SCIM role model, entitlement gate, ReDoS ([224f05c](https://github.com/ShipFast-Syndicate/enterprise/commit/224f05c74d126fff7d5ffc6406e71370988d8249))
* **security:** C-04, M-01, M-06, M-07, M-08 — secrets at rest and authorization ([c4068c4](https://github.com/ShipFast-Syndicate/enterprise/commit/c4068c4b3e4ee24eca4cf388a37ddb30afbc6092))
* **security:** no owner via group map; AAD-bound secrets; retention validation; docs ([0844fa7](https://github.com/ShipFast-Syndicate/enterprise/commit/0844fa76bd50c0a746d7c97679f2dd740e3e94ac))
* **server:** audit failed SSO sign-ins separately; document samlSpKeys; shared SSO test helpers ([5eff1dc](https://github.com/ShipFast-Syndicate/enterprise/commit/5eff1dc142a52170b8ab35e73c8a10aa52923a34))
* **server:** consume SSO test-login pending row; cached forward router; honour custom ACS url ([eee39ed](https://github.com/ShipFast-Syndicate/enterprise/commit/eee39ed41484090a31d9631f314c64b73a58f8cf))
* **server:** keep plugin endpoint types literal so the client is typed ([899cc1c](https://github.com/ShipFast-Syndicate/enterprise/commit/899cc1c016149bad687640c479e8e361d7ddc0cf))
* **server:** membership-based policy resolution, method enforcement backstop, validated allowedMethods ([627290b](https://github.com/ShipFast-Syndicate/enterprise/commit/627290b325bf9e98b0e36d8066465a056ccd3486))
* **server:** method-aware SCIM audit hooks; chain, CSV and failure-path tests ([152e155](https://github.com/ShipFast-Syndicate/enterprise/commit/152e155bf4bbd27e870da3e147bbe04cf60c13b9))
* **server:** org-only SCIM provider creation and provider ownership ([2022e1c](https://github.com/ShipFast-Syndicate/enterprise/commit/2022e1c0eafa40676d8fa0a00e7ccf2e9ec97485))
* **server:** scim groups — two-group role recompute test, externalId uniqueness, stable ordering ([7edde6b](https://github.com/ShipFast-Syndicate/enterprise/commit/7edde6b18f34275fb8f06f81afa695790a755b78))
* **sso:** test-login finish derives the org from the provider ([a8a75e8](https://github.com/ShipFast-Syndicate/enterprise/commit/a8a75e83f8b85d9728f565b26d05c8326a5fe1f3))

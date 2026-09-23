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

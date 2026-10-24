# Public CI

The public repository calls its own `public-ci.yml` workflow. The preceding
remote CI invocation failed before any jobs started, but earlier CI and release
runs successfully called the private hub after this repository became public.
The exact cause of that startup failure is not established. Self-contained CI
makes hosted runner placement and the complete gate contract explicit without
depending on private hub access or nested workflow references.
All CI jobs use GitHub-hosted runners and read-only repository access. Forks need
no repository secrets, reviewer App key, private artifacts service, or PR comment
permission. Checkouts do not retain the token in Git configuration.

Branch protection continues to use `ci / summary`. This job requires:

- CI policy and workflow contract tests;
- lint, typecheck, formatting, unit tests and coverage;
- Semgrep's configured code/security rule sets;
- Trivy CRITICAL/HIGH vulnerabilities, secrets and configuration findings;
- Gitleaks full-history scanning with `.gitleaks.toml`;
- `pnpm audit --audit-level=high` with the existing documented exception;
- the npm package build;
- the packed tarball (`package` job): `pnpm pack`, file list checked against the
  allow-list in `.github/scripts/pack-files.mjs`, then
  `.github/scripts/consumer-install.sh` installs it into a scratch project with
  the declared peers, imports `/server`, `/schema`, `/client` and `/portal`
  through the package name and runs `ab-enterprise --help`;
- `actionlint` (pinned release, SHA-256 checked, shellcheck included) on every
  workflow;
- the existing PR base/head policy;
- for PRs into main, both deploy-QA statuses on the exact PR head, or the live
  `release_grant` override.

Branch rulesets (`develop`, `main` and the repository-level
`enterprise-develop`/`enterprise-main`) require `ci / summary`; confirmed through
`GET /repos/ShipFast-Syndicate/enterprise/rules/branches/{develop,main}` on
2026-10-23. Renaming the caller job `ci` or the `summary` job breaks merges.

Every job declares `timeout-minutes` (asserted by the contract tests) and the
least permissions it needs; `ci.yml` cancels superseded runs per ref and
`release.yml` serialises releases without cancelling one in flight. CI also runs
nightly (03:17 UTC) on the default branch, `develop`, to catch new advisories
and registry or runner drift between merges.

Failures, cancellations, missing reports and unexpected skipped jobs block the
summary. Dependabot PRs run the full set, including the Node quality job (lint,
typecheck, formatting, tests and coverage); none of these jobs use secrets. The
Dependabot merge gate only merges patch/minor updates on a green exact head, and
never merges the `better-auth` group or tooling the release job executes
(semantic-release and its plugins, tsup, esbuild, typescript, the release job's
actions): those PRs are opened and tested, then wait for a maintainer. E2E and migration
dry-run jobs were disabled for this package and remain disabled. There is no
numeric coverage threshold configured; the coverage command must succeed.

Run the policy/closure tests with `node --test .github/scripts/*.test.mjs` after
`pnpm install --frozen-lockfile`. The Gitleaks job also exercises a harmless
history-only marker at a formerly allowlisted path, proving that a different
commit is still scanned. Scanner binaries have pinned versions and archive
SHA-256 digests from their official GitHub releases. Actions have full commit pins.
Review those pins and the test allowlist together when updating tools.

Coverage is retained as a GitHub artifact. Secret scan reports stay on the
ephemeral runner; raw matches are not published as artifacts or PR comments.
Semgrep reports a failing exit code without printing matched source. Reproduce
locally with the command in the workflow to inspect findings privately.

`release.yml` runs semantic-release locally on pushes to `main`, then the
`publish` job (OIDC trusted publishing, `npm` environment) and a
`post-release-smoke` job that installs the just-published version from the
registry with `consumer-install.sh`. Dispatching the workflow manually runs only
`publish-dry-run`: build, version check against the registry and
`npm publish --dry-run`, with a read-only token, no OIDC and no `npm`
environment, so a rehearsal can never publish. The main-PR release-readiness
gate remains enforced.

Hosted placement in this source does not restrict what an altered workflow can
request. The workflow contract tests detect drift; a PR can edit those tests too.
Organization runner-group admission and fork approval remain separate
administrative controls.

## Release checklist (maintainers)

Releases are cut by semantic-release on `main`; the version comes from the commit history
(`feat` → minor, `fix` → patch, a `BREAKING CHANGE` footer → major). Before merging a release
into `main`:

1. On the exact commit to be merged, run the same gates CI runs:
   `pnpm install --frozen-lockfile`, `pnpm lint`, `pnpm typecheck`,
   `pnpm exec prettier --check .`, `pnpm test`, `pnpm build`,
   `python3 .github/scripts/dependabot-gate.test.py` and
   `node --test .github/scripts/*.test.mjs` (the glob, not the directory).
2. Dispatch **Release** (dry run) on the release head; CI's `package` job already enforces
   the tarball allow-list, so a file-list change there is a deliberate edit to
   `.github/scripts/pack-files.mjs`.
3. `pnpm audit --prod`.
4. `pnpm exec semantic-release --dry-run` with a read-only token, and confirm the computed
   version. A squash or merge commit's type decides the bump: keep the commit types of the
   changes, and never add a `BREAKING CHANGE` footer to a release that is not meant to be a
   major.
5. Confirm the release job's GitHub token carries only the permissions semantic-release needs
   (`contents`, `issues`, `pull-requests`), and that the `npm` environment still requires
   approval.
6. After the publish: deprecate superseded versions when the release notes say so
   (`npm deprecate "@alphabros/enterprise@<range>" "<message>"`), and check the provenance
   statement on npm names the tagged release commit.

## Public contribution intake (maintainers)

The repository takes external requests as issues only (see `CONTRIBUTING.md`). Issues are
picked up by the studio's issue triage, which reads `enterprise` from the shared feeder project
list and files a ClawVault task for each confirmed issue; code fixes are routed to code-bro.
Security reports arrive through GitHub private vulnerability reporting (`SECURITY.md`), which
must stay enabled.

Two repository settings back this policy and must stay as they are:

- **Actions → Fork pull request workflows → Require approval for first-time contributors**
  stays on, so a fork pull request never runs a workflow without a maintainer's approval.
- code-bro's automatic review and merge only act on pull requests from branches of this
  organization's repository. A pull request from a fork is never reviewed or merged by the
  bots; close it with a pointer to `CONTRIBUTING.md` and ask for an issue.

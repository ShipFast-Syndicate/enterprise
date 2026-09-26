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
- the existing PR base/head policy;
- for PRs into main, both deploy-QA statuses on the exact PR head, or the live
  `release_grant` override.

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

The separate `release.yml` still calls a private reusable release workflow. That
call has executed successfully and now explicitly requests a GitHub-hosted
runner. Verify hosted execution on the next authorized release before applying
any runner-group restriction that would remove its previous access. The runner
choice does not authorize package publication; the main-PR release-readiness
gate remains enforced.

Hosted placement in this source does not restrict what an altered workflow can
request. The workflow contract tests detect drift; a PR can edit those tests too.
Organization runner-group admission and fork approval remain separate
administrative controls.

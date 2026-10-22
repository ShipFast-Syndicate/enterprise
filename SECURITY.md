# Security policy

## Reporting a vulnerability

**Do not open a public issue, discussion or pull request for a security problem.**

Report it privately through GitHub's private vulnerability reporting:

1. Go to the repository's [**Security** tab](https://github.com/ShipFast-Syndicate/enterprise/security).
2. Select **Report a vulnerability**
   ([direct link](https://github.com/ShipFast-Syndicate/enterprise/security/advisories/new)).
3. Describe the problem, the affected version and entry point, and the steps to reproduce it.

Only the maintainers can see your report. Private vulnerability reporting is enabled on this
repository.

Please include:

- the affected package version and your `better-auth` peer versions;
- what an attacker can do (for example sign in as another user, read another organization's
  data, forge an audit entry);
- a proof of concept, if you have one, with any real secrets and personal data removed.

If the problem is in `better-auth` or one of its `@better-auth/*` packages rather than in this
package, report it to that project as well. We will tell you if we find that the cause is
upstream.

## What we do with a report

- We acknowledge the report within **5 business days**.
- We confirm or rule out the problem, and keep you informed in the private advisory.
- When a fix is ready, we publish a patched release and a GitHub security advisory. We credit
  you in the advisory unless you ask us not to.

Please give us a reasonable time to ship the fix before you disclose the problem publicly. We
will agree a disclosure date with you in the advisory.

## Supported versions

| Version | Supported         |
| ------- | ----------------- |
| 1.x     | ✅ Security fixes |
| 0.1.x   | ❌ Upgrade to 1.x |

Security fixes ship in the latest 1.x release only. 0.1.x depends on `better-auth` releases
with known vulnerabilities; follow [`docs/upgrading-to-1.1.md`](./docs/upgrading-to-1.1.md) to
upgrade.

## Scope

In scope: the code in this repository and the published `@alphabros/enterprise` package —
the server plugins, client helpers, schema and CLI, and the admin portal elements.

Out of scope: vulnerabilities in your own application code, in your identity provider, or in
deployments that do not follow [`docs/security.md`](./docs/security.md) (for example a reused
`secretsKey`, or an audit chain without a `chainKey`).

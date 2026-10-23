# Contributing to @alphabros/enterprise

Thanks for your interest. This repository is public so that you can read the code, install
the package and tell us what breaks. For now, we take contributions as **issues only**.

## How to send a request

1. Search the [open issues](https://github.com/ShipFast-Syndicate/enterprise/issues) first. If
   your problem is already there, add a comment with your details instead of a new issue.
2. Open a new issue with the matching form:
   - **Bug report** — something does not work as the docs say.
   - **Feature request** — something you need that the package does not do yet.
3. **Security problems never go in a public issue.** Report them privately: see
   [`SECURITY.md`](./SECURITY.md).

Questions about how to use the package are welcome as issues too. Read the
[README](./README.md) and the guides in [`docs/`](./docs) first; the answer may already be there.

## What a good bug report contains

- The package version (`npm ls @alphabros/enterprise`) and the versions of `better-auth` and
  each `@better-auth/*` package you have installed. The package expects the exact peer set
  listed in the README; a mismatched set is the most common cause of a bug.
- Your runtime: Node version, or the platform (for example Cloudflare Workers, Vercel), and
  your database adapter.
- The entry point involved (`/server`, `/client`, `/schema`, `/portal` or the CLI).
- The smallest set of steps that shows the problem, with the configuration you pass to the
  preset or plugin. Remove secrets, keys, certificates and customer data first.
- What you expected, and what happened instead: the full error message or the HTTP status and
  response body.
- For SSO problems: whether it is SAML or OIDC, and the identity provider (Okta, Entra ID,
  Keycloak, …). Never paste a full SAML response or token; describe it.

## What a good feature request contains

- The problem you are trying to solve, in your own product's terms. Tell us the need, not only
  the solution you have in mind.
- Who needs it (for example an organization admin, an end user, your own backend).
- What you do today instead, if anything.
- Any standard it should follow (SAML, OIDC, SCIM 2.0 RFC sections), with a link.

## What happens next

Every new issue is triaged by the Alpha Bros team. A confirmed issue becomes an internal task,
is fixed on a branch of this repository and reviewed through a pull request that links back to
your issue. The issue closes automatically when that pull request merges, and the fix ships in
the next release (see [`CHANGELOG.md`](./CHANGELOG.md)). We may ask you questions in the issue
along the way.

We cannot promise a date for any fix or feature.

## Pull requests from forks

**We do not accept external pull requests yet.** A pull request from a fork is closed with a
pointer to this file, even when the change is good. Open an issue instead and describe the
change; if you already have a patch, describe what it changes in the issue. We will revisit
this policy once the package and its review process are ready for outside code.

## Roadmap

The package is the shared enterprise layer for the Alpha Bros products. In plain words:

- **Package (done).** SSO with SAML and OIDC, SCIM provisioning, organizations, an audit
  log, security policies and an admin portal, published on npm as `@alphabros/enterprise`.
- **Pilots (next).** Two Alpha Bros products turn the enterprise features on for their top
  plan and prove the single sign-on journey end to end.
- **Rollout.** The other Alpha Bros products adopt the package one at a time.
- **Shared accounts (later).** One Alpha Bros account that signs you in across products.
  This needs its own design first.

Requests that fit the current phase are the easiest for us to take on.

## License

By opening an issue you agree that we may use your report and any code snippet in it to improve
the package under its [MIT license](./LICENSE).

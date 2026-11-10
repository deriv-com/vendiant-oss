# Security policy

## Supported versions

Security fixes are applied on the default branch. Self-hosters should track `master`
or the latest release tag.

## Reporting a vulnerability

**Do not** open public GitHub issues for security-sensitive reports.

Use one of these channels:

1. **GitHub private security advisory** (preferred): [Report a vulnerability](https://github.com/deriv-com/vendiant-oss/security/advisories/new) on `deriv-com/vendiant-oss`.
2. **Email**: [security@deriv.com](mailto:security@deriv.com) — include the repository name and affected component.

Include:

- Description and impact
- Steps to reproduce
- Affected component (frontend auth, Dashboard backend, API layer, webhooks, scanners, breach monitor, …)
- Suggested fix if you have one

We aim to acknowledge reports within a few business days.

## Deployment expectations for self-hosters

- **Authentication** — production requires an SSO gateway that issues JWTs verified via
  `SSO_JWKS_URL` / `SSO_ISSUER` / `SSO_AUDIENCE` (see [docs/AUTHENTICATION.md](docs/AUTHENTICATION.md)).
- **`ENABLE_MOCK_AUTH`** — development only; every request becomes an admin. It is ignored when
  `NODE_ENV=production` or `SSO_JWKS_URL` is set, but never expose `docker-compose.dev.yml` on a
  reachable host.
- **Network exposure** — expose only nginx (`:8081`). The backend (`:5005`), API layer (`:5006`)
  and PostgreSQL must not be directly reachable from untrusted networks.
- **API layer** — issue API keys with the narrowest scopes needed, rotate them, and review the
  audit log. Webhook endpoints should only be reachable by your breach-management platform.
- **Secrets** — never commit `.env`. Set a strong `DB_PASSWORD`; store breach-platform tokens,
  Slack webhooks and third-party API keys in a secrets manager and rotate them regularly.
- **Data** — scan results and breach records are sensitive. Restrict database access and
  backups accordingly, and do not commit scanner output (it is gitignored).
- **Scanning** — only scan domains you own or are authorised to assess. Network scanning
  providers send real traffic to targets.

## Secure defaults

The default `docker compose` stack runs the frontend in production mode and requires a valid SSO
token on every request. The dev override (`docker-compose.dev.yml`) enables mock auth for local
use only. Production deployments must configure real SSO and follow the [README](README.md) and
[docs/](docs/).

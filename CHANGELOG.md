# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased] — open-source release

This branch is the vendor-neutral, Docker-native edition of Vendiant.

### Changed

- **Network scanning is pluggable.** `Network/providers` defines a `NetworkScanProvider`
  interface with a dependency-free TCP connect scanner (default), an nmap wrapper and a
  template for hosted scanning APIs. `NETWORK_SCAN_PROVIDER` selects the implementation.
  See `docs/NETWORK_SCANNING.md`.
- **Breach monitoring is vendor-neutral.** The breach platform client, webhook ingestion,
  quota tracking, Slack alerts and dashboard pages now use the generic `breach-monitor`
  naming (`/api/breach-monitor/*`, `/vendiant/webhooks/breach-monitor`,
  `breach_monitor_records`). Endpoint URLs, credentials and employee domains come from
  `BREACH_MONITOR_*` / `EMPLOYEE_EMAIL_DOMAINS`. See `docs/BREACH_MONITORING.md`.
- **Single sign-on is gateway-agnostic.** The frontend verifies a JWT forwarded by any SSO
  gateway / identity-aware proxy (`SSO_JWKS_URL`, `SSO_ISSUER`, `SSO_AUDIENCE`,
  `SSO_JWT_HEADER`, `SSO_GROUPS_CLAIM`); group names are configurable. See
  `docs/AUTHENTICATION.md`.
- **Access Management user picker** reads from a configurable user directory
  (`USER_DIRECTORY_URL`, `USER_DIRECTORY_FILE`) with a database fallback.
- **Docker Compose only.** Kubernetes, Cloud Build / Deploy, Skaffold and cloud-database
  specific configuration were removed; the stack runs on plain PostgreSQL.
- PDF report branding, CORS origins, LLM endpoint and dashboard URL are all environment
  variables.

### Removed

- Database dumps containing real data (replaced by a data-free
  `Postgress/init-scripts/schema.sql`), company logos and hard-coded vendor logo mappings,
  the company-specific user directory client and the IdP-specific configuration guide.

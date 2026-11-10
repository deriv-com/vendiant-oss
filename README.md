# Vendiant

Vendiant is an open-source third-party (vendor) security posture platform
that runs on plain Docker Compose with a standard PostgreSQL database.
Give it a vendor's domain and it discovers subdomains, scans them across
several categories, turns the findings into scores and grades, tracks them
over time, alerts on regressions and produces PDF reports. A breach-monitor
page surfaces credential exposures for your own domains from whichever
breach-management platform you use.

Nothing in this repository is tied to a particular company or cloud: the
scanning tool, breach platform, SSO gateway, user directory, branding and
alert destinations are all configured through environment variables, and
the network-scanning integration is a pluggable interface you can
implement for your own tooling.

## What it scans

| Category | Module | How |
|----------|--------|-----|
| Subdomain discovery | `Subdomains/`, `Sublist3r_New/` | DNS enumeration, certificate transparency, brute force |
| Network exposure | `Network/` | Open ports via a **pluggable scanning provider** (built-in TCP scan, nmap, or your tool) – [docs/NETWORK_SCANNING.md](docs/NETWORK_SCANNING.md) |
| Encryption | `Encryption/` | TLS configuration and certificate checks via testssl.sh / pyOpenSSL |
| DNS | `DNS/` | SPF, DMARC, DNSSEC, zone hygiene, WHOIS |
| Email | `email/` | Mail security posture |
| Website headers | `Header_Vulnerabilities/` | Security headers and cookie flags |
| Domain reputation | `Domain Reputation/` | AbuseIPDB and related signals |
| Recent incidents | `Recent Incidents/` | News and incident feeds per vendor (LLM assisted) |
| Certifications | `certificates/` | LLM-assisted lookup of SOC 2 / ISO attestations |
| Breach monitor | `Dashboard/breach_monitor_*.py` | Credential exposures for your own domains from your **breach management platform** – [docs/BREACH_MONITORING.md](docs/BREACH_MONITORING.md) |
| Public breach feed | `pawned/` | Have I Been Pwned RSS cross-checked against your vendor list |

Scores per category are combined by `Dashboard/unified_scoring_config.py`
into an overall vendor score and letter grade.

## Architecture

```
browser ──▶ SSO gateway ──▶ nginx (:8081) ──▶ Next.js dashboard (:3005) ──▶ FastAPI backend (:5005) ──▶ PostgreSQL
                                   └──────▶ FastAPI API layer (:5006, API-key access for integrations & webhooks)
```

- `Dashboard/` – FastAPI backend (`app_new.py`), schedulers, Slack alerts, PDF reports, access management, breach monitor
- `frontend/` – Next.js dashboard (SSO JWT verification, role-based access)
- `api_layer/` – separate FastAPI service exposing vendor data to other systems with API keys, scopes and audit logging, and receiving breach-platform webhooks (`api_layer/README.md`, `API_Docs.md`, `Webhook_Docs.md`)
- `Postgress/init-scripts/schema.sql` – core schema (data-free), loaded by compose on first start; the backend creates and migrates the remaining tables on startup
- `nginx/` – reverse proxy, rate limits, security headers

## Quick start

```bash
git clone <this repo> vendiant && cd vendiant
cp .env.example .env              # at minimum: DB_PASSWORD, EMPLOYEE_EMAIL_DOMAINS
docker compose up --build         # or: podman compose up --build
```

Open <http://localhost:8081>. The compose stack runs the frontend in
production mode, so every request must carry a valid SSO token (see
[docs/AUTHENTICATION.md](docs/AUTHENTICATION.md)); without one you land on
`/unauthorized`. To try the UI without an SSO gateway, add the dev override,
which runs the frontend in development mode with mock auth (every request is
signed in as an admin; never expose it):

```bash
docker compose -f docker-compose.yml -f docker-compose.dev.yml up --build
```

The default configuration needs **no third-party API keys** to scan: network
scanning uses the built-in TCP scanner.

The stack works with both Docker and Podman (tested with Podman 6 and
podman-compose 1.5 on macOS).

To see the breach monitor populated without a platform, copy the example
data:

```bash
cp data/breach_records.example.json data/breach_records.json
```

### Local development

```bash
# backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cd Dashboard && python app_new.py            # http://localhost:5005

# frontend
cd frontend && npm install && ENABLE_MOCK_AUTH=true npm run dev   # http://localhost:3005

# api layer
cd api_layer && pip install -r requirements.txt && python main.py   # http://localhost:5006

# database
createdb vendiant && psql -d vendiant -f Postgress/init-scripts/schema.sql
```

System tools used by the scanners: `dig`, `nslookup`, `whois`, `curl`,
`wget`, `openssl` (`apt-get install dnsutils whois curl wget openssl` or
`brew install bind`). For TLS scanning, fetch testssl.sh (GPLv2, not
vendored in this repo) at the same pinned commit the Docker image uses
(`TESTSSL_COMMIT` in `Dashboard/Dockerfile`, upstream tag `v3.2.5`):

```bash
cd Encryption/LOCAL
git clone https://github.com/testssl/testssl.sh.git
git -C testssl.sh checkout --detach 4f17be931a9d60f3f987975aea8221f1a8eaf7aa
```

`Encryption/LOCAL/testssl.sh/` and scanner output files are gitignored; don't
commit either.

Optional: `nmap` if you choose the nmap network provider.

## Configuration

Everything lives in `.env` (see `.env.example` for the full list).

| Area | Variables | Docs |
|------|-----------|------|
| Database | `DB_HOST`, `DB_PORT`, `DB_NAME`, `DB_USER`, `DB_PASSWORD`, optional `DB_NAME_BREACHES` | |
| URLs / CORS | `NEXT_PUBLIC_BASE_URL`, `CORS_ORIGINS` | |
| LLM | `OPENAI_API_KEY`, `OPENAI_BASE_URL` (any OpenAI-compatible endpoint), `OPENAI_MODEL_NAME` | |
| Network scanning | `NETWORK_SCAN_PROVIDER` = `socket` / `nmap` / `module:Class` + provider options | [docs/NETWORK_SCANNING.md](docs/NETWORK_SCANNING.md) |
| Breach monitoring | `EMPLOYEE_EMAIL_DOMAINS`, `BREACH_MONITOR_*` | [docs/BREACH_MONITORING.md](docs/BREACH_MONITORING.md) |
| Single sign-on | `SSO_JWKS_URL`, `SSO_ISSUER`, `SSO_AUDIENCE`, `SSO_JWT_HEADER`, `SSO_GROUPS_CLAIM`, `NEXT_PUBLIC_SSO_GROUP_*`, `NEXT_PUBLIC_SSO_LOGOUT_URL` | [docs/AUTHENTICATION.md](docs/AUTHENTICATION.md) |
| User directory | `USER_DIRECTORY_URL`, `USER_DIRECTORY_FILE` | [docs/AUTHENTICATION.md](docs/AUTHENTICATION.md) |
| Reputation | `ABUSE_API_KEY`, `NVD_API_KEY`, `SONAR_API_KEY` | |
| Slack | `SLACK_WEBHOOK_URL`, `SLACK_HEALTH_CHECK_WEBHOOK_URL` | |
| PDF branding | `REPORT_BRAND_NAME`, `REPORT_BRAND_COLOR`, `REPORT_LOGO_PATH` | |

### Bringing your own tools

- **Network scanner**: implement `NetworkScanProvider.scan_host()` and set
  `NETWORK_SCAN_PROVIDER=your.module:YourClass`. A complete template for
  wrapping a hosted scanning API is in
  `Network/providers/custom_provider_example.py`.
- **Breach platform**: point `BREACH_MONITOR_BREACH_SEARCH_URL` and the
  credential variables at your platform's search API and register
  `/vendiant/webhooks/breach-monitor` as its outbound webhook. The record
  format and the request/response protocol are documented in
  `docs/BREACH_MONITORING.md`.
- **SSO**: any identity-aware proxy that forwards a JWT. Set the JWKS URL,
  issuer, audience and header name; map your groups to roles with the
  `NEXT_PUBLIC_SSO_GROUP_*` variables.

## Operations

- `scripts/backup-script` dumps the Postgres container to
  `Postgress/backups/database/` (paths and credentials come from the
  environment); `scripts/rebuild-script.sh` backs up, rebuilds and restarts
  the stack.
- Logs are written per module under `custom_integrations/logs/`.
- Scan schedules, Slack digests and alerting are configured in
  `Dashboard/scheduler_config.py`, `Dashboard/scheduler_manager.py` and
  `Dashboard/routes/background_scan_scheduler.py`.
- `CHANGELOG.md` tracks notable changes.

## Data hygiene

The repository ships **no scan data and no breach data**. `data/*.json`
(except `*.example.json`), `Postgress/backups/` and `.env` are git-ignored.
Keep it that way: breach exports contain personal data.

## Troubleshooting

- "Network scan provider is not usable": the chosen provider failed
  `validate_config()` (nmap missing, API key unset). The Slack alert or
  backend log says why.
- Breach Monitor page empty: `GET /api/breach-monitor/health` reports which
  endpoints and credentials are configured and how many records are stored.
- Redirected to `/unauthorized`: the SSO JWT failed verification or the
  user is in none of the configured groups; check `SSO_*` and
  `NEXT_PUBLIC_SSO_GROUP_*`.
- `psycopg2` build errors: `psycopg2-binary` is already pinned.

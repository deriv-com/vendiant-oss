# Vendiant Security API Layer

A secure, high-performance REST API for vendor security risk management built with FastAPI, featuring scope-based authentication, rate limiting, and comprehensive audit logging.

## Features

- **Domain-Focused Security Intelligence**: Complete vendor lifecycle management with security scoring
- **FastAPI Framework**: High-performance async API with automatic OpenAPI documentation
- **Enhanced Security**: Argon2 password hashing and cryptographically secure API keys
- **Fine-Grained Scope Control**: Six individual scopes assignable per API key
- **Rate Limiting**: 50 requests/minute per API key with response headers
- **Comprehensive Audit Logging**: Full request tracking with client IP and user agent capture
- **Podman Ready**: Full containerization with Containerfile and podman-compose support

## Table of Contents

- [Quick Start (Local)](#quick-start-local)
- [Podman Container Setup](#podman-container-setup)
- [API Endpoints](#api-endpoints)
- [Authentication & Authorization](#authentication--authorization)
- [API Usage Examples](#api-usage-examples)
- [API Key Management](#api-key-management)
- [Environment Variables](#environment-variables)
- [Monitoring & Security](#monitoring--security)
- [Troubleshooting](#troubleshooting)

---

## Quick Start (Local)

### Prerequisites
- Python 3.11+
- PostgreSQL running locally
- Vendiant backend running on port 5005
- `.venv` virtual environment at the project root

### 1. Environment Setup

Ensure `.env` in the project root contains **both** sets of DB variables (the backend reads `DB_*`; other tooling uses `POSTGRES_*`):

```bash
DATABASE_URL=postgresql://<user>:<password>@localhost:5432/vendiant

POSTGRES_HOST=localhost
POSTGRES_PORT=5432
POSTGRES_DB=vendiant
POSTGRES_USER=<user>
POSTGRES_PASSWORD=<password>

# DB_* aliases required by Dashboard/db_config.py
DB_HOST=localhost
DB_PORT=5432
DB_NAME=vendiant
DB_USER=<user>
DB_PASSWORD=<password>

BACKEND_API_URL=http://localhost:5005
CORS_ORIGINS=http://localhost:8081
```

### 2. Start the Backend

```bash
PYTHONPATH=/path/to/vendiant \
  .venv/bin/python3 Dashboard/app_new.py
```

### 3. Start the API Layer

```bash
cd api_layer
PYTHONPATH=$(pwd) \
  ../.venv/bin/uvicorn main:app --host 127.0.0.1 --port 5006
```

### 4. Create an API Key

```bash
# Interactive CLI
cd api_layer
python3 utils/api_key_creation.py

# Or programmatically
PYTHONPATH=$(pwd) python3 -c "
from auth.api_key_manager import APIKeyManager
mgr = APIKeyManager()
key, key_id = mgr.generate_api_key('my-key', group_name='admin')
print('API Key:', key)
"
```

### 5. Verify

```bash
curl http://localhost:5006/vendiant/health
```

---

## Podman Container Setup

The project includes `Containerfile`s for Podman builds and a `podman-compose.yml` at the project root.

### Services

| Service | Port | Build context |
|---------|------|---------------|
| postgres | 5432 | `postgres:15-alpine` (image) |
| backend | 5005 | `Dashboard/Containerfile` |
| vendiant_api | 5006 | `api_layer/Containerfile` |
| frontend | 3005 | `frontend/Dockerfile` |
| nginx | 8081 | `nginx/Dockerfile` |

### Build Individual Images

```bash
# Uses --format docker so HEALTHCHECK is embedded correctly
BUILDAH_FORMAT=docker podman build \
  --format docker -t vendiant-api:latest \
  -f api_layer/Containerfile ./api_layer

BUILDAH_FORMAT=docker podman build \
  --format docker -t vendiant-backend:latest \
  -f Dashboard/Containerfile .
```

### Full Stack with podman-compose

```bash
# Build and start all services
BUILDAH_FORMAT=docker podman-compose -f podman-compose.yml up --build

# Or use the helper script
./podman-build.sh up
```

### Helper Script Commands

```bash
./podman-build.sh build   # Build all images
./podman-build.sh up      # Build + start full stack
./podman-build.sh down    # Stop and remove containers
./podman-build.sh logs    # Follow logs
./podman-build.sh ps      # Show running containers
```

### Create API Key in Container

```bash
podman exec -it vendiant_api python3 -c "
from auth.api_key_manager import APIKeyManager
mgr = APIKeyManager()
key, key_id = mgr.generate_api_key('container-admin', group_name='admin')
print('API Key:', key)
print('Credential ID:', key_id)
"
```

### Access Points (containerized)

- **API docs (Swagger)**: http://localhost:8081/vendiant/docs
- **API docs (ReDoc)**: http://localhost:8081/vendiant/redoc
- **API base**: http://localhost:8081/vendiant/
- **Direct API** (no nginx): http://localhost:5006/vendiant/

---

## API Endpoints

### Endpoint Summary

| Method | Endpoint | Description | Required Scope |
|--------|----------|-------------|----------------|
| `GET` | `/vendiant/health` | Health check | None |
| `GET` | `/vendiant/vendors` | List all vendors | `vendors:list` |
| `GET` | `/vendiant/domain/{domain}/score` | Get domain risk score | `vendors:read` |
| `GET` | `/vendiant/domain/{domain}/report` | Get full domain report | `reports:read` |
| `POST` | `/vendiant/vendor` | Add a new vendor | `vendors:add` |
| `DELETE` | `/vendiant/domain/{domain}` | Delete vendor by domain | `vendors:delete` |
| `POST` | `/vendiant/domain/{domain}/fullscan` | Trigger full security scan | `scans:run` |

### Interactive Docs

When running locally: http://localhost:5006/vendiant/docs  
When running via nginx: http://localhost:8081/vendiant/docs

---

## Authentication & Authorization

### API Key Format

```
vnd_<32-character URL-safe base64 string>
```

Example: `vnd_KYfg_h44Gn1n6W7HcFjVkLcdyh9c5nCW`

Pass the key in every request via the `X-API-Key` header:

```bash
curl -H "X-API-Key: vnd_your_key_here" http://localhost:5006/vendiant/vendors
```

### Available Scopes

| Scope | Description | Endpoints |
|-------|-------------|-----------|
| `vendors:list` | List all vendors | `GET /vendiant/vendors` |
| `vendors:read` | Read vendor domain scores | `GET /vendiant/domain/{domain}/score` |
| `reports:read` | Read domain reports | `GET /vendiant/domain/{domain}/report` |
| `vendors:add` | Add new vendors | `POST /vendiant/vendor` |
| `vendors:delete` | Delete vendors | `DELETE /vendiant/domain/{domain}` |
| `scans:run` | Trigger full domain scans | `POST /vendiant/domain/{domain}/fullscan` |

### Permission Groups

#### `admin`
Has all scopes (`*`). Can access every endpoint.

#### `read_only`
Has `vendors:list`, `vendors:read`, `reports:read`. Read-only access — cannot create, delete, or scan.

#### `finegrained`
Has a custom subset of scopes defined at key creation time. Use this to grant exactly the permissions needed and no more.

```bash
# Example: create a key that can only trigger scans
PYTHONPATH=. python3 -c "
from auth.api_key_manager import APIKeyManager
mgr = APIKeyManager()
key, _ = mgr.generate_api_key(
    'scanner-key',
    group_name='finegrained',
    finegrained_scopes=['scans:run', 'vendors:read']
)
print(key)
"
```

### Authentication Error Responses

**Missing key (401)**:
```json
{ "detail": "API key required. Include X-API-Key header." }
```

**Invalid key (401)**:
```json
{ "detail": "Invalid API key" }
```

**Insufficient scope (403)**:
```json
{ "detail": "Access denied: required scope 'vendors:add' not granted" }
```

**Rate limit exceeded (429)**:
```json
{ "detail": "Rate limit exceeded. 50 requests/minute allowed." }
```

---

## API Usage Examples

### GET /vendiant/health

No authentication required.

```bash
curl http://localhost:5006/vendiant/health
```

```json
{
  "status": "healthy",
  "service": "vendiant-api",
  "timestamp": "2026-05-18T09:41:51.612716"
}
```

### GET /vendiant/vendors

Requires `vendors:list` scope.

```bash
curl -H "X-API-Key: vnd_your_key" http://localhost:5006/vendiant/vendors
```

```json
[
  { "id": 1, "domain": "example.com", "name": "Example Corp" },
  { "id": 2, "domain": "example.org", "name": "Example Org" }
]
```

### GET /vendiant/domain/{domain}/score

Requires `vendors:read` scope.

```bash
curl -H "X-API-Key: vnd_your_key" \
  http://localhost:5006/vendiant/domain/example.com/score
```

```json
{
  "domain": "example.com",
  "overall_risk_score": 895.0,
  "risk_level": "Low",
  "vendor_name": "Example Corp",
  "last_updated": "2026-01-07 22:19:07",
  "scan_status": {
    "scan_active": false,
    "scan_stage_message": "Scan completed",
    "job_id": null,
    "last_scan_completed": "2026-01-07 22:19:07"
  }
}
```

Risk score range: **0–950** (higher = better security posture).

| Risk Level | Score Range |
|------------|-------------|
| Critical | 0–300 |
| High | 301–500 |
| Medium | 501–700 |
| Low | 701–950 |

**404 — domain not found**:
```json
{ "detail": "No vendor found for domain: example.com" }
```

### GET /vendiant/domain/{domain}/report

Requires `reports:read` scope.

```bash
curl -H "X-API-Key: vnd_your_key" \
  http://localhost:5006/vendiant/domain/example.com/report
```

```json
{
  "domain": "example.com",
  "overall_risk_score": 950.0,
  "risk_level": "low",
  "vendor_info": {
    "id": 16,
    "name": "Example Corp",
    "domain": "example.com",
    "grade": "A",
    "tier": "Tier 1",
    "industry": "General Merchandise & Superstores"
  },
  "category_scores": {
    "Website": { "count": 0, "severity_breakdown": { "Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0 }, "scores": [] },
    "Domain Reputation": { "count": 0, "severity_breakdown": { "Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0 }, "scores": [] }
  },
  "scan_summary": { "Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0 },
  "subdomain_count": 42,
  "scan_format": "full_scan_all",
  "scan_timestamp": "2026-01-07 22:19:07",
  "generated_at": "2026-05-18T10:00:00.000000",
  "scan_status": {
    "scan_active": false,
    "scan_stage_message": "Scan completed",
    "job_id": null,
    "last_scan_completed": "2026-01-07 22:19:07"
  }
}
```

### POST /vendiant/vendor

Requires `vendors:add` scope.

```bash
curl -X POST http://localhost:5006/vendiant/vendor \
  -H "X-API-Key: vnd_your_key" \
  -H "Content-Type: application/json" \
  -d '{"name": "Acme Corp", "domain": "acme.com"}'
```

**Request body**:
```json
{
  "name": "Acme Corp",
  "domain": "acme.com"
}
```

**201 Created**:
```json
{
  "status": "success",
  "message": "Vendor 'Acme Corp' with domain 'acme.com' added successfully and main domain scan initiated (job: single_scan_1_1234567890)",
  "data": {
    "id": 101,
    "name": "Acme Corp",
    "domain": "acme.com",
    "tier": "",
    "portfolio": "",
    "created_at": "2026-05-18T10:00:00.000000",
    "updated_at": "2026-05-18T10:00:00.000000",
    "background_scan": {
      "initiated": true,
      "job_id": "single_scan_1_1234567890",
      "message": "Main domain security scan initiated (subdomains excluded for faster onboarding)",
      "scan_type": "main_domain_only"
    }
  },
  "meta": null
}
```

A main-domain security scan is automatically triggered on vendor creation. To run a full scan including subdomains, use `POST /vendiant/domain/{domain}/fullscan` afterwards.

**Validation errors (422)**:
```json
{ "detail": [{ "type": "missing", "loc": ["body", "name"], "msg": "Field required" }] }
```

**Duplicate domain (409)**:
```json
{ "detail": "Vendor with domain acme.com already exists" }
```

### DELETE /vendiant/domain/{domain}

Requires `vendors:delete` scope.

```bash
curl -X DELETE http://localhost:5006/vendiant/domain/acme.com \
  -H "X-API-Key: vnd_your_key"
```

```json
{
  "status": "success",
  "message": "Vendor with domain 'acme.com' deleted successfully",
  "data": null,
  "meta": null
}
```

### POST /vendiant/domain/{domain}/fullscan

Requires `scans:run` scope. Triggers a full scan including subdomain discovery and all security checks. Runs in the background — poll `GET /vendiant/domain/{domain}/score` for status.

```bash
curl -X POST http://localhost:5006/vendiant/domain/acme.com/fullscan \
  -H "X-API-Key: vnd_your_key"
```

**Scan started (200)**:
```json
{
  "status": "success",
  "job_id": "single_scan_4_1760961309",
  "message": "Full scan initiated for acme.com. Scan is now running in the background and includes subdomain discovery and all security checks.",
  "domain": "acme.com",
  "include_subdomains": true
}
```

**Scan already running (200)**:
```json
{
  "status": "success",
  "job_id": "single_scan_4_1760961309",
  "message": "Scan is already in progress for acme.com. Running security checks...",
  "domain": "acme.com",
  "include_subdomains": true
}
```

**Typical workflow**:
1. Add vendor: `POST /vendiant/vendor` — triggers a fast main-domain scan automatically
2. Full scan: `POST /vendiant/domain/{domain}/fullscan` — triggers subdomain discovery + all checks
3. Poll results: `GET /vendiant/domain/{domain}/score` — `scan_status.scan_active` goes `false` when done
4. Full report: `GET /vendiant/domain/{domain}/report`

### Rate Limit Headers

All authenticated responses include:

```
X-RateLimit-Limit: 50
X-RateLimit-Remaining: 47
X-RateLimit-Reset: 1716019260
```

---

## API Key Management

### Interactive CLI

```bash
cd api_layer
python3 utils/api_key_creation.py
```

Options:
1. **Create API Key** — guided prompts for name, group, expiry
2. **List API Keys** — view active credentials and their groups
3. **Revoke API Key** — disable a credential
4. **View Audit Statistics** — usage analytics
5. **Exit**

### Programmatic Creation

```bash
PYTHONPATH=/path/to/vendiant/api_layer python3 -c "
from auth.api_key_manager import APIKeyManager
mgr = APIKeyManager()

# Admin key (all scopes)
key, key_id = mgr.generate_api_key('my-admin', group_name='admin')

# Read-only key
key, key_id = mgr.generate_api_key('my-reader', group_name='read_only')

# Fine-grained key (specific scopes only)
key, key_id = mgr.generate_api_key(
    'scan-bot',
    group_name='finegrained',
    finegrained_scopes=['scans:run', 'vendors:read']
)

print('Key:', key)  # Store this — it is never shown again
"
```

> **Important**: The plaintext key is returned only once at creation time. Only the Argon2 hash is stored in the database.

---

## Environment Variables

### Project root `.env`

```bash
# Full connection URL (used by api_layer)
DATABASE_URL=postgresql://<user>:<password>@<host>:5432/vendiant

# POSTGRES_* — used by Docker/Podman compose and postgres service
POSTGRES_HOST=localhost
POSTGRES_PORT=5432
POSTGRES_DB=vendiant
POSTGRES_USER=<user>
POSTGRES_PASSWORD=<password>

# DB_* — required by Dashboard/db_config.py (backend)
DB_HOST=localhost
DB_PORT=5432
DB_NAME=vendiant
DB_USER=<user>
DB_PASSWORD=<password>

# Backend URL (api_layer proxies to this)
BACKEND_API_URL=http://localhost:5005

# CORS — comma-separated list of allowed origins
# In production all non-localhost origins must use HTTPS
CORS_ORIGINS=http://localhost:8081

# Frontend
NEXT_PUBLIC_API_URL=
NEXT_PUBLIC_BASE_URL=http://localhost:8081

# External API keys
OPENAI_API_KEY=
ABUSE_API_KEY=

# Network scanning / breach monitoring: see docs/NETWORK_SCANNING.md and
# docs/BREACH_MONITORING.md

# Single sign-on (docs/AUTHENTICATION.md)
SSO_JWKS_URL=
SSO_ISSUER=
SSO_AUDIENCE=
```

### Container overrides (podman-compose.yml)

In containers, `DB_HOST` / `BACKEND_API_URL` are overridden to use service names:

```yaml
DB_HOST: postgres
BACKEND_API_URL: http://backend:5005
```

---

## Monitoring & Security

### Audit Logging

Every authenticated request is logged to the `request_audit_log` table:

| Field | Description |
|-------|-------------|
| `credential_id` | ID of the API key used |
| `key_name` | Name assigned to the key |
| `endpoint_path` | Full request path |
| `http_method` | GET / POST / DELETE |
| `client_ip` | Originating IP (respects `X-Forwarded-For`) |
| `user_agent` | Client user-agent string |
| `success` | Boolean |
| `response_code` | HTTP status code |
| `request_data` | Sanitized request parameters |
| `created_at` | ISO timestamp |

### Rate Limiting

- **50 requests/minute** per API key (applies across all scopes)
- Configurable `request_limit` per key at creation time
- Enforced with a 1-minute sliding window
- `429 Too Many Requests` returned when exceeded

### Security Properties

- API keys are **Argon2id**-hashed before storage (time_cost=3, memory=64MB)
- Plaintext keys are never stored or logged
- Production CORS rejects non-HTTPS non-localhost origins
- All string inputs are sanitized against log-injection and XSS
- All routes run as a non-root user in containers (UID 1001)

---

## Troubleshooting

### "relation 'vendors' does not exist"

The backend's `db_config.py` reads `DB_*` env vars, not `POSTGRES_*`. Make sure your `.env` has both sets (see [Environment Variables](#environment-variables)) **and** you started the backend with those vars in scope:

```bash
# Correct
DB_HOST=localhost DB_NAME=vendiant DB_USER=... DB_PASSWORD=... python3 Dashboard/app_new.py

# Wrong — these aren't read by db_config.py
POSTGRES_HOST=localhost POSTGRES_DB=vendiant python3 Dashboard/app_new.py
```

### "ModuleNotFoundError: No module named 'config'"

The API layer must run with `PYTHONPATH` pointing to the `api_layer` directory:

```bash
cd api_layer
PYTHONPATH=$(pwd) ../.venv/bin/uvicorn main:app --port 5006
```

### HEALTHCHECK warning with Podman

Podman builds OCI format by default, which doesn't support `HEALTHCHECK` in image metadata:

```
HEALTHCHECK is not supported for OCI image format and will be ignored. Must use `docker` format
```

Fix by setting the format before building:

```bash
BUILDAH_FORMAT=docker podman build --format docker -t vendiant-api:latest -f api_layer/Containerfile ./api_layer
```

The `./podman-build.sh` script sets this automatically.

### "Invalid API key" on a known-good key

1. Confirm the API layer is connecting to the right database:
   ```bash
   # Check what database the api_layer process uses
   PYTHONPATH=api_layer python3 -c "
   from config.settings import get_config
   c = get_config()
   print(c.DATABASE_URL)
   "
   ```
2. Confirm the key exists and is enabled:
   ```bash
   psql -U <user> -d vendiant -c \
     "SELECT id, name, credential_prefix, is_enabled, expires_at FROM api_credentials;"
   ```
3. Check that `expires_at` is either NULL or in the future.

### 403 on an endpoint

Check which scope your key has vs what the endpoint requires:

| Endpoint | Required scope |
|----------|---------------|
| `GET /vendiant/vendors` | `vendors:list` |
| `GET /vendiant/domain/*/score` | `vendors:read` |
| `GET /vendiant/domain/*/report` | `reports:read` |
| `POST /vendiant/vendor` | `vendors:add` |
| `DELETE /vendiant/domain/*` | `vendors:delete` |
| `POST /vendiant/domain/*/fullscan` | `scans:run` |

`read_only` keys only have `vendors:list`, `vendors:read`, `reports:read`.

### Checking running services

```bash
# Confirm both services are listening
lsof -i :5005 -i :5006 | grep LISTEN

# Health checks
curl http://localhost:5005/health
curl http://localhost:5006/vendiant/health
```

# Authentication and access control

Vendiant does not implement logins. It expects to run behind an **SSO
gateway** (identity-aware proxy) that authenticates users against your
identity provider and forwards a signed JWT with every request. The Next.js
middleware verifies that JWT, maps the user's groups to a dashboard role,
and passes a trusted identity to the backend.

Any gateway that issues a verifiable JWT works, for example:

| Gateway | JWT header | JWKS URL |
|---------|------------|----------|
| Cloudflare Access | `cf-access-jwt-assertion` (default) | `https://<team>.cloudflareaccess.com/cdn-cgi/access/certs` |
| oauth2-proxy (`--pass-access-token`) | `x-forwarded-access-token` | your IdP's JWKS |
| Pomerium | `x-pomerium-jwt-assertion` | `https://<authenticate-host>/.well-known/pomerium/jwks.json` |
| Google IAP | `x-goog-iap-jwt-assertion` | `https://www.gstatic.com/iap/verify/public_key-jwk` |
| Teleport, Authelia, Keycloak Gatekeeper, ... | per product | per product |

The identity provider behind the gateway (Entra ID, Google
Workspace, Keycloak, ...) is irrelevant to Vendiant; it only needs to
expose group membership in the token.

## Environment variables

| Variable | Default | Meaning |
|----------|---------|---------|
| `SSO_JWKS_URL` | *(required)* | JWKS endpoint used to verify the token |
| `SSO_ISSUER` | *(required)* | Expected `iss` claim |
| `SSO_AUDIENCE` | *(required)* | Expected `aud` claim |
| `SSO_JWT_HEADER` | `cf-access-jwt-assertion` | Request header that carries the JWT (`Authorization: Bearer` is accepted too) |
| `SSO_GROUPS_CLAIM` | `groups` | Claim containing the user's groups; `group`, `roles`, `custom.group(s)` are tried as fallbacks |
| `NEXT_PUBLIC_SSO_LOGOUT_URL` | *(empty)* | Where **Sign out** sends the browser |
| `NEXT_PUBLIC_SSO_GROUP_ADMIN` | `vendiant-admin` | Group → `admin` role |
| `NEXT_PUBLIC_SSO_GROUP_VENDOR_MANAGEMENT` | `vendiant-vendor-management` | Group → `vendor-management` |
| `NEXT_PUBLIC_SSO_GROUP_USER` | `vendiant-user` | Group → `user-extended` |
| `NEXT_PUBLIC_SSO_GROUP_VENDORS_ONLY` | `vendiant-vendors-only` | Group → `user-basic` |
| `SSO_GROUP_ADMIN` (backend) | `vendiant-admin` | Must equal `NEXT_PUBLIC_SSO_GROUP_ADMIN`; gates Access Management APIs |
| `ENABLE_MOCK_AUTH` | `false` | Local development only: every request is an admin. Ignored in production and whenever `SSO_JWKS_URL` is set. |

`NEXT_PUBLIC_*` values are baked into the frontend at build time: pass them
as `--build-arg` (or `build.args` in compose) when you change them.

## Roles and permissions

Group membership resolves to one of four roles (highest wins): `admin`,
`vendor-management`, `user-extended`, `user-basic`. Users in none of the
configured groups are denied. Each role has default permissions
(`frontend/lib/rbac.ts`, mirrored in `Dashboard/effective_permissions.py`).
Admins can override them per user in **Access Management**; a user with an
assignment uses exactly those permissions, otherwise the role defaults
apply. First-time users are auto-provisioned with their role's default
grant.

## Trust model

1. The gateway authenticates the user and sets the JWT header.
2. `frontend/middleware.ts` verifies the JWT (signature, issuer, audience,
   expiry) with `jose`, checks group membership and injects
   `x-user-id`, `x-user-email`, `x-user-name`, `x-user-groups` and
   `x-user-role` into the request.
3. Server-side proxies (`app/api/[...path]/route.ts` and friends) forward
   those as `X-User-*` headers to the FastAPI backend.
4. The backend trusts `X-User-*` **only** because it is reachable solely
   from the frontend container on the private Docker network. Do not
   expose port 5005 publicly.

The API layer (`/vendiant/...`, port 5006) is separate: it authenticates
integrations with API keys and scopes, not SSO.

## Access Management user directory

The user picker in Access Management is fed by `Dashboard/user_directory.py`:

| Variable | Meaning |
|----------|---------|
| `USER_DIRECTORY_URL` | JSON endpoint listing people (`[{name,email}]`, or an object with `employees`/`users`/`members`/`Resources`; SCIM `/Users` works) |
| `USER_DIRECTORY_API_KEY` | Sent as `Authorization: Bearer ...` (or in `USER_DIRECTORY_API_KEY_HEADER`) |
| `USER_DIRECTORY_FILE` | Local JSON or CSV (`name,email`) file |

Without either, the picker lists everyone already known to the dashboard
(existing assignments and sign-ins). Admins can always type an email
directly.

## Local development without a gateway

Two options, both of which sign every request in as an admin
(`dev@localhost`):

```bash
# 1. Whole stack in containers, frontend in dev mode (rebuild after code changes)
docker compose -f docker-compose.yml -f docker-compose.dev.yml up --build

# 2. Frontend on the host with live reload (backend from compose)
docker compose up -d postgres backend vendiant_api
cd frontend && ENABLE_MOCK_AUTH=true npm run dev   # http://localhost:3005
```

Mock auth only applies when `ENABLE_MOCK_AUTH=true`, `NODE_ENV` is not
`production` and `SSO_JWKS_URL` is empty. The production image is built with
`NODE_ENV=production`, so it can never run with mock auth, whatever `.env`
says.

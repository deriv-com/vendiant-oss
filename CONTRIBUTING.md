# Contributing

Thanks for helping improve Vendiant.

## Development setup

1. Clone the repository and create your environment file:
   ```bash
   cp .env.example .env    # at minimum: DB_PASSWORD, EMPLOYEE_EMAIL_DOMAINS
   ```
2. Quickest path: run the full stack with the dev override (mock auth, never expose it):
   ```bash
   docker compose -f docker-compose.yml -f docker-compose.dev.yml up --build
   ```
   Open http://localhost:8081.
3. Or run services individually:
   ```bash
   # backend
   python -m venv .venv && source .venv/bin/activate
   pip install -r requirements.txt
   cd Dashboard && python app_new.py                                   # http://localhost:5005

   # frontend
   cd frontend && npm install && ENABLE_MOCK_AUTH=true npm run dev     # http://localhost:3005

   # api layer
   cd api_layer && pip install -r requirements.txt && python main.py   # http://localhost:5006
   ```
4. For TLS scanning, fetch testssl.sh at the pinned commit (see [README](README.md#local-development)).
   It is not vendored and is gitignored.

## Pull requests

- Keep changes focused; one logical change per PR when possible.
- Run checks before pushing:
  ```bash
  cd frontend && npm run lint && npx tsc --noEmit && npm run build
  python -m pytest Dashboard api_layer
  ```
- Do not commit secrets, `.env`, real scan results, breach records, or customer/vendor data.
  Scanner output paths are gitignored; keep it that way. Use `data/*.example.json` for sample data.
- Do not vendor third-party tools or binaries. Fetch them at a pinned version and record
  them in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
- Update the relevant docs (`README.md`, `docs/`, `API_Docs.md`, `Webhook_Docs.md`) when changing
  configuration, endpoints, or deployment-facing behaviour.

## Code style

- Python: match existing module patterns; explicit error handling for security-sensitive paths
  (auth, permission checks, outbound requests, SQL).
- Use parameterised queries only; never build SQL with string formatting.
- New backend routes must enforce the same role/permission checks as existing Dashboard routes.
- TypeScript: `tsc --noEmit` must pass.
- Keep company-specific values (domains, SSO groups, branding, alert destinations) in
  environment variables, not in code.
- Scanning integrations go behind the pluggable provider interfaces
  (see [docs/NETWORK_SCANNING.md](docs/NETWORK_SCANNING.md)) rather than hard-coded tools.

## Scanning ethics

Only scan domains you own or are authorised to assess. Do not add features whose primary purpose
is intrusive testing (exploitation, credential stuffing, denial of service) of third parties.

## Licensing

Contributions are accepted under the repository [LICENSE](LICENSE) (MIT). Third-party components
keep their own licenses; see [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

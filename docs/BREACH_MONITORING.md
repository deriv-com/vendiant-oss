# Breach monitoring

The **Breach Monitor** page shows credential and identity exposures for your
own organisation: which employee or client identities appear in breach
dumps or infostealer logs, whether a password was exposed, which source
leaked it, and what to do about it. Records are stored in PostgreSQL,
alerted to Slack, exportable to Excel, and can be resolved, marked false
positive or suppressed through an ignore list.

Vendiant does not ship a breach feed. It integrates with the breach
management platform you already pay for, through two channels:

| Channel | Direction | What it does |
|---------|-----------|--------------|
| **Search API** (`BREACH_MONITOR_*_SEARCH_URL`) | Vendiant → platform | Scheduled sync of all records for your domains, plus interactive queries by domain, email or web address from the dashboard |
| **Webhook** (`/vendiant/webhooks/breach-monitor`) | platform → Vendiant | Real-time ingestion of alerts pushed by the platform |

Either channel alone works; most deployments use both.

## Configuration

| Variable | Required | Meaning |
|----------|----------|---------|
| `EMPLOYEE_EMAIL_DOMAINS` | yes | Comma-separated domains that count as *your organisation*. Drives the employees/clients split, the organisation filter and the default sync scope. |
| `BREACH_MONITOR_BREACH_SEARCH_URL` | for API sync/queries | Breach search endpoint |
| `BREACH_MONITOR_BOTNET_SEARCH_URL` | optional | Botnet / infostealer search endpoint (skipped when unset) |
| `BREACH_MONITOR_USERNAME` | for API | Tenant / account name, sent as `X-Username` |
| `BREACH_MONITOR_TOKEN` | for API | API token, sent as `X-Token` |
| `BREACH_MONITOR_APP_TOKEN` | for API | Application token, sent as `X-AppToken` |
| `BREACH_MONITOR_APP_TOKEN_1` | optional | Second application token for the interactive query pool |
| `BREACH_MONITOR_DOMAIN_GROUPS` | optional | JSON list of domain groups to sync, e.g. `[["example.com"],["example.org"]]`. Defaults to one group per `EMPLOYEE_EMAIL_DOMAINS` entry. |
| `BREACH_MONITOR_API_QUOTA_INITIAL` | optional | Starting value of the persisted API-call budget shown in the dashboard |
| `DB_NAME_BREACHES` | optional | Store breach tables in a separate database (defaults to `DB_NAME`) |

The search client (`Dashboard/breach_monitor_search.py`) speaks a simple,
common protocol: `POST <url>` with

```json
{"domain": [["example.com"]], "next_id": ""}
```

or `{"email": ["user@example.com"], "date_from": "", "next_id": ""}` and expects

```json
{"data": {"results": [ ...records... ],
          "query": {"pagination": {"total": 120, "count": 25, "page": 0}},
          "next_id": "cursor-for-next-page"}}
```

Pagination stops on an empty page, a short page (fewer than 25 rows), a
missing `next_id`, or when every record on a page is already stored
(incremental catch-up). Transient failures (connection errors, 429, 5xx)
are retried three times with backoff; a failure after that raises a Slack
"External API failure" alert.

If your platform's API has a different shape, adapt `_post_with_retry()`
and the `data`/`results`/`next_id` extraction in
`run_breach_search_paginated()`. Everything downstream (storage, UI, Slack,
export) only depends on the normalised record format below.

## Record format

```json
{
  "type": "breach",
  "validated": 1,
  "information": {
    "uid": "provider-record-id",        // required, unique per record
    "email": "user@example.com",
    "username": "user",
    "domain": "example.com",
    "password": 1,                      // 1 if a password was exposed
    "password_plain": "...",            // optional; shown to admins only
    "web_address": "https://site-that-leaked.example",
    "date": "2024-01-31",
    "fullname": "...", "company": "...", "country": "..."   // optional extras
  },
  "source": {
    "name": "Example dump 2024",
    "description": "...",
    "confidence": "high",
    "breach_type": "credential dump",   // "botnet" marks infostealer records
    "source": "dark web forum",
    "recommendations": "Reset password, enable MFA",
    "score_attribution": 90,
    "score_authentication": 80
  }
}
```

`information.uid` is the de-duplication key (`breach_monitor_records.breach_monitor_uid`).
Records are upserted, so re-delivery is harmless.

## Webhook ingestion

Expose the API layer (`/vendiant/...` through nginx) and register
`https://<your-host>/vendiant/webhooks/breach-monitor` as the platform's
outbound webhook. Authentication uses a dashboard API key created with the
sole `webhook` scope (Settings → API Keys), sent as `X-API-Key` or
`Authorization: Bearer vnd_...`. Accepted body shapes, retry semantics and
sample payloads are in [`Webhook_Docs.md`](../Webhook_Docs.md). Flat
"hashed monitoring" alerts (`{"uid": ..., "masked": {...}}`) are normalised
into the record format automatically.

## Scheduled sync, quota and Slack

- `Dashboard/scheduler_config.py` runs the domain sync (breach, then
  botnet) on a schedule; **Refresh** on the Breach Monitor page runs the
  same job on demand (admin only, rate limited).
- A persisted counter (`breach_monitor_api_quota`) tracks remaining API
  calls so a runaway sync cannot burn your plan; it is shown in the
  dashboard header.
- New employee leaks alert Slack immediately; client leaks go into a daily
  digest. The **Slack ignore list** suppresses alerts per email, incident
  or password.

## Local / offline data

With no API configured the page still works from a JSON export at
`data/breach_records.json` (or `data/<employee-domain>.json`). Copy
`data/breach_records.example.json` to see the page populated. `data/*.json`
is git-ignored: never commit a real export.

## API endpoints

All under `/api/breach-monitor` (proxied by the Next.js app with the
signed-in user's identity headers):

| Method | Path | Purpose |
|--------|------|---------|
| GET | `` | Stored records with filters (`leak_view`, `org_filter`, `date_from`, ...) |
| GET | `/config` | Employee domains and organisation filter values |
| GET | `/stats`, `/quota`, `/health`, `/incidents` | Counters, remaining API calls, health, incident names |
| GET | `/refresh` | Run the domain sync now (admin) |
| POST | `/query` | Interactive query by domain, email or web address |
| POST | `/search` | Filter stored records |
| GET/POST | `/export` | Excel export |
| PATCH | `/breaches/{uid}/resolve` etc. | Resolve / unresolve / false-positive, plus `bulk-*` variants |
| GET/POST/DELETE | `/ignore-list` | Slack suppression rules |

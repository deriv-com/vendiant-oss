# Vendiant Breach Monitor Webhook Documentation

This document describes how to send breach platform outbound alert callbacks to Vendiant.

---

## Overview


| Item              | Value                                                        |
| ----------------- | ------------------------------------------------------------ |
| **Full URL**      | `https://vendiant-api.example.com/vendiant/webhooks/breach-monitor` |
| **Method**        | `POST` only                                                  |
| **Content-Type**  | `application/json`                                           |
| **Max body size** | 5 MiB                                                        |


The webhook ingests breach platform breach breach records, upserts them into the database, and fires Slack alerts for newly discovered UIDs.

**HTTP 200** means the payload was accepted and persisted. Any other status may cause Breach Monitor to retry delivery.

---



## Authentication

Webhook requests require a **dedicated webhook-only API key**. 

### Sending credentials

Use either header:

```http
X-API-Key: vnd_your_webhook_only_key_here
```

```http
Authorization: Bearer vnd_your_webhook_only_key_here
```



### Example headers

```json
{
  "X-API-Key": "vnd_examplewebhook_kH1exn_PPQaGq1eVsmbgRteIST-zTU",
  "Content-Type": "application/json",
  "Accept": "application/json"
}
```

---



## Payload format

Each record must include a non-empty `information.uid`. Records without a UID are skipped; if no valid records remain, the request returns **400**.

### Single record (most common)

```json
{
  "type": "breach",
  "validated": 0,
  "information": {
    "uid": "3034393234306232386330393234643533613963323732626136313563373035",
    "date": "2026-06-24 14:42:08",
    "email": "user@example.com",
    "domain": "example.com",
    "username": "jdoe",
    "web_address": "https://example.com/login",
    "password": 1,
    "password_plain": "examplePassword123"
  },
  "source": {
    "name": "Combo List 17M",
    "type": "breach",
    "source": "darkweb",
    "breach_type": "password-combo",
    "confidence": "low",
    "url_source": "unanalyzed breach",
    "description": "In June 2026, exposed credentials were found in underground communities.",
    "ingested_date": "2026-06-25 17:33:43",
    "recommendations": "Update your password immediately and review other services using the same password.",
    "score_attribution": 0,
    "score_authentication": 0
  }
}
```



### Batch via `results`

```json
{
  "results": [
    {
      "type": "breach",
      "information": {
        "uid": "abc123uid456",
        "email": "alice@example.com",
        "domain": "example.com",
        "password": 1
      },
      "source": {
        "name": "Breach Source A",
        "confidence": "low"
      }
    },
    {
      "type": "breach",
      "information": {
        "uid": "def789uid012",
        "email": "bob@example.com",
        "domain": "example.com",
        "password": 0
      },
      "source": {
        "name": "Breach Source B",
        "confidence": "medium"
      }
    }
  ]
}
```



### Search API envelope

```json
{
  "data": {
    "results": [
      {
        "type": "breach",
        "information": {
          "uid": "abc123uid456",
          "email": "user@example.com"
        },
        "source": {
          "name": "Combo List 17M"
        }
      }
    ]
  }
}
```



### Top-level array

```json
[
  {
    "type": "breach",
    "information": {
      "uid": "abc123uid456",
      "email": "user@example.com"
    },
    "source": {
      "name": "Breach Source"
    }
  }
]
```



### Wrapper keys

The parser also unwraps common single-record wrappers: `alert`, `record`, `breach`, `item`, and `payload`.

---



## Field reference



### Required


| Field | Location          | Description                                           |
| ----- | ----------------- | ----------------------------------------------------- |
| `uid` | `information.uid` | Unique Breach Monitor record identifier (non-empty string) |




### `information` (recommended)


| Field            | Type       | Description                                |
| ---------------- | ---------- | ------------------------------------------ |
| `uid`            | string     | **Required.** Breach Monitor UID                |
| `date`           | string     | Event / exposure timestamp                 |
| `email`          | string     | Affected email address                     |
| `domain`         | string     | Associated domain                          |
| `username`       | string     | Username, if present                       |
| `web_address`    | string     | URL associated with the credential         |
| `password`       | int / bool | `1` if password was exposed, `0` otherwise |
| `password_plain` | string     | Plaintext password (when available)        |




### `source` (recommended)


| Field                  | Type   | Description                            |
| ---------------------- | ------ | -------------------------------------- |
| `name`                 | string | Breach / incident name                 |
| `type`                 | string | e.g. `breach`                          |
| `source`               | string | e.g. `darkweb`                         |
| `breach_type`          | string | e.g. `password-combo`, `hacked-leaked` |
| `confidence`           | string | e.g. `low`, `medium`, `high`           |
| `description`          | string | Human-readable breach description      |
| `recommendations`      | string | Remediation guidance                   |
| `ingested_date`        | string | When Breach Monitor ingested the record     |
| `score_attribution`    | int    | Attribution score                      |
| `score_authentication` | int    | Authentication score                   |




### Top-level record fields


| Field       | Type   | Default           | Description                    |
| ----------- | ------ | ----------------- | ------------------------------ |
| `type`      | string | `breach breach` | Record type                    |
| `validated` | int    | `0`               | Validation flag from Breach Monitor |


---



## Request examples



### cURL

```bash
curl -X POST "https://vendiant-api.example.com/vendiant/webhooks/breach-monitor" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: vnd_your_webhook_only_key_here" \
  -d '{
    "type": "breach",
    "validated": 0,
    "information": {
      "uid": "3034393234306232386330393234643533613963323732626136313563373035",
      "date": "2026-06-24 14:42:08",
      "email": "user@example.com",
      "domain": "example.com",
      "password": 1
    },
    "source": {
      "name": "Combo List 17M",
      "type": "breach",
      "source": "darkweb",
      "confidence": "low",
      "description": "Exposed credentials found in underground communities."
    }
  }'
```



### Python

```python
import requests

WEBHOOK_URL = "https://vendiant-api.example.com/vendiant/webhooks/breach-monitor"
API_KEY = "vnd_your_webhook_only_key_here"

payload = {
    "type": "breach",
    "information": {
        "uid": "3034393234306232386330393234643533613963323732626136313563373035",
        "email": "user@example.com",
        "domain": "example.com",
        "password": 1,
    },
    "source": {
        "name": "Combo List 17M",
        "confidence": "low",
    },
}

response = requests.post(
    WEBHOOK_URL,
    json=payload,
    headers={"X-API-Key": API_KEY},
    timeout=30,
)

print(response.status_code, response.json())
```



### JavaScript (fetch)

```javascript
const response = await fetch(
  "https://vendiant-api.example.com/vendiant/webhooks/breach-monitor",
  {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-API-Key": "vnd_your_webhook_only_key_here",
    },
    body: JSON.stringify({
      type: "breach",
      information: {
        uid: "3034393234306232386330393234643533613963323732626136313563373035",
        email: "user@example.com",
        domain: "example.com",
        password: 1,
      },
      source: {
        name: "Combo List 17M",
        confidence: "low",
      },
    }),
  }
);

console.log(await response.json());
```

---



## Responses

All responses include a `code` field mirroring the HTTP status, plus a `status` of `ok` or `error`.

### Success (HTTP 200)

```json
{
  "status": "ok",
  "code": 200,
  "received": 1,
  "rows_written": 1,
  "new_uid_rows": 1,
  "existing_uid_updates": 0
}
```


| Field                  | Description                                      |
| ---------------------- | ------------------------------------------------ |
| `received`             | Number of valid records parsed from the payload  |
| `rows_written`         | Records successfully upserted                    |
| `new_uid_rows`         | Records with UIDs not previously in the database |
| `existing_uid_updates` | Records that updated an existing UID             |


### Error responses

**Missing or invalid API key (HTTP 401)**

```json
{
  "status": "error",
  "code": 401,
  "message": "Unauthorized"
}
```

**Empty body (HTTP 400)**

```json
{
  "status": "error",
  "code": 400,
  "message": "Empty request body"
}
```

**Invalid JSON (HTTP 400)**

```json
{
  "status": "error",
  "code": 400,
  "message": "Invalid JSON body"
}
```

**No valid records (HTTP 400)**

```json
{
  "status": "error",
  "code": 400,
  "message": "No valid Breach Monitor records in payload (each record needs information.uid)"
}
```

**Body too large (HTTP 413)**

```json
{
  "status": "error",
  "code": 413,
  "message": "Request body too large"
}
```

**Server / persistence failure (HTTP 500)**

```json
{
  "status": "error",
  "code": 500,
  "message": "Failed to process webhook"
}
```

---



## breach platform configuration

When registering the outbound webhook in the breach platform:


| Setting            | Value                                                        |
| ------------------ | ------------------------------------------------------------ |
| **Callback URL**   | `https://vendiant-api.example.com/vendiant/webhooks/breach-monitor` |
| **HTTP method**    | `POST`                                                       |
| **Content-Type**   | `application/json`                                           |
| **Authentication** | `X-API-Key` header with your webhook-only key                |


Treat **HTTP 200** as successful delivery. Non-2xx responses may cause Breach Monitor to retry.

---


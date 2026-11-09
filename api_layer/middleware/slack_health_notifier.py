import json
import logging
import os
from datetime import datetime, timezone
from typing import Any, Optional

import requests

logger = logging.getLogger(__name__)

_STATUS_LABELS = {
    400: "Bad Request",
    401: "Unauthorized — missing or invalid API key",
    403: "Forbidden — insufficient permissions",
    404: "Not Found",
    405: "Method Not Allowed",
    409: "Conflict — resource already exists",
    422: "Unprocessable Entity — validation failed",
    429: "Too Many Requests — rate limit hit",
    500: "Internal Server Error",
    502: "Bad Gateway — backend unreachable",
    503: "Service Unavailable",
    504: "Gateway Timeout",
}

_COLOUR_MAP = {
    range(500, 600): "#FF0000",  # red   — server errors
    range(400, 500): "#FFA500",  # orange — client errors
}

_REDACT_KEYS = {"password", "passwd", "token", "secret", "api_key", "key", "auth", "authorization"}


def _colour_for(status_code: int) -> str:
    for r, colour in _COLOUR_MAP.items():
        if status_code in r:
            return colour
    return "#36a64f"


def _redact(data: Any) -> Any:
    if not isinstance(data, dict):
        return data
    return {
        k: "[REDACTED]" if any(s in k.lower() for s in _REDACT_KEYS) else _redact(v)
        for k, v in data.items()
    }


def _parse_error_response(raw: Optional[str]) -> list[dict]:
    """
    Parse a JSON error response body into a list of Slack fields.
    Handles FastAPI HTTPException, Pydantic validation errors, and plain text.
    """
    if not raw:
        return []

    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return [{"title": "Error Body", "value": raw[:500], "short": False}]

    detail = data.get("detail")
    fields = []

    if isinstance(detail, str):
        fields.append({"title": "Reason", "value": detail, "short": False})

    elif isinstance(detail, list):
        # Pydantic validation errors — list of {loc, msg, type}
        lines = []
        for err in detail[:8]:
            loc = " → ".join(str(p) for p in err.get("loc", []) if p != "body")
            msg = err.get("msg", "")
            lines.append(f"• `{loc}`: {msg}")
        fields.append({"title": f"Validation Errors ({len(detail)})", "value": "\n".join(lines), "short": False})

    elif isinstance(detail, dict):
        # Structured error e.g. rate-limit detail
        summary = detail.get("error") or detail.get("message") or ""
        if summary:
            fields.append({"title": "Reason", "value": summary, "short": False})
        extra = {k: v for k, v in detail.items() if k not in ("error", "message")}
        if extra:
            fields.append({"title": "Detail", "value": f"```{json.dumps(extra, indent=2)[:600]}```", "short": False})

    else:
        fields.append({"title": "Response", "value": str(data)[:400], "short": False})

    return fields


def _slack_escape(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _request_payload_fields(body: Optional[dict]) -> list[dict]:
    """Surface only whitelisted request fields, Slack-escaped, to Slack."""
    if not body:
        return []

    safe = _redact(body)

    allowed_fields = {"name", "domain", "vendor_name", "vendor", "email", "url"}
    filtered = {k: v for k, v in safe.items() if k in allowed_fields}

    lines = []
    for k, v in filtered.items():
        lines.append(f"*{k}*: `{_slack_escape(str(v))}`")

    return [{"title": "Request Payload", "value": "\n".join(lines), "short": False}] if lines else []


def _build_payload(
    method: str,
    path: str,
    status_code: int,
    client_ip: str,
    error_detail: Optional[str],
    duration_ms: Optional[float],
    key_name: Optional[str],
    request_body: Optional[dict],
    ip_spoofing_attempted: bool = False,
    claimed_ip: Optional[str] = None,
) -> dict:
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    status_label = _STATUS_LABELS.get(status_code, "Error")
    title = f":rotating_light: {status_code} {status_label}  |  `{method} {path}`"

    # Format IP with spoofing warning if detected
    ip_display = client_ip or "unknown"
    if ip_spoofing_attempted and claimed_ip:
        ip_display = f"{ip_display} (IP spoofing attempted: claimed {claimed_ip})"
    elif ip_spoofing_attempted:
        ip_display = f"{ip_display} (IP spoofing attempted)"

    fields = [
        {"title": "Endpoint", "value": f"`{method} {path}`", "short": True},
        {"title": "Status", "value": f"{status_code} — {status_label}", "short": True},
        {"title": "Client IP", "value": ip_display, "short": True},
        {"title": "Time (UTC)", "value": ts, "short": True},
    ]
    if key_name:
        fields.append({"title": "API Key", "value": key_name, "short": True})
    if duration_ms is not None:
        fields.append({"title": "Duration", "value": f"{duration_ms:.1f} ms", "short": True})

    # Structured error fields parsed from response body
    fields.extend(_parse_error_response(error_detail))

    # Request payload (name, domain, etc.)
    fields.extend(_request_payload_fields(request_body))

    return {
        "attachments": [
            {
                "color": _colour_for(status_code),
                "title": title,
                "fields": fields,
                "footer": "Vendiant API Layer · Health Monitor",
                "ts": int(datetime.now(timezone.utc).timestamp()),
            }
        ]
    }


def _post_to_slack(url: str, payload: dict) -> None:
    """Blocking Slack POST — always called from a background thread."""
    try:
        resp = requests.post(url, json=payload, timeout=4)
        if resp.status_code == 200:
            logger.info("Slack health webhook posted successfully")
        else:
            logger.warning("Slack health webhook returned %s: %s", resp.status_code, resp.text[:200])
    except Exception as exc:
        logger.error("Failed to post to Slack health webhook: %s", exc)


def notify_error(
    method: str,
    path: str,
    status_code: int,
    client_ip: str,
    error_detail: Optional[str] = None,
    duration_ms: Optional[float] = None,
    key_name: Optional[str] = None,
    request_body: Optional[dict] = None,
    webhook_url: Optional[str] = None,
    ip_spoofing_attempted: bool = False,
    claimed_ip: Optional[str] = None,
) -> None:
    """
    Dispatch a health-check alert to Slack in a background thread.
    Returns immediately so the async event loop is never blocked.
    """
    logger.info("notify_error called: %s %s (status=%s, ip=%s, spoofing=%s, claimed=%s)", method, path, status_code, client_ip, ip_spoofing_attempted, claimed_ip)
    url = (
        webhook_url
        or os.getenv("SLACK_HEALTH_CHECK_WEBHOOK_URL")
        or os.getenv("SLACK_WEBHOOK_URL")
        or ""
    )
    if not url:
        logger.warning("No Slack webhook URL configured — skipping health notification")
        return

    payload = _build_payload(method, path, status_code, client_ip, error_detail, duration_ms, key_name, request_body, ip_spoofing_attempted, claimed_ip)
    logger.info("Posting to Slack webhook URL (first 50 chars): %s", url[:50] if url else "NONE")
    import threading
    threading.Thread(target=_post_to_slack, args=(url, payload), daemon=True).start()

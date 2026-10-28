"""
Slack health check notifications for background scan failures and external API errors.
All posts are fire-and-forget (daemon thread) so scan execution is never blocked.
"""

import json
import logging
import os
import threading
import time
from datetime import datetime, timezone
from typing import Optional

import requests

# ---------------------------------------------------------------------------
# Deduplication for external API alerts.
# Tracks (api_name, error_type) → last_alerted_timestamp.
# Prevents spamming when the same API fails for every subdomain in a scan.
# ---------------------------------------------------------------------------
_api_alert_cache: dict[tuple, float] = {}
_api_alert_cache_lock = threading.Lock()
_API_ALERT_COOLDOWN_SECONDS = 300  # 5 minutes


def _should_alert_api(api_name: str, error_type: str) -> bool:
    """Return True if enough time has passed since the last alert for this (api, error) pair."""
    key = (api_name.lower(), error_type.lower())
    now = time.monotonic()
    with _api_alert_cache_lock:
        last = _api_alert_cache.get(key, 0)
        if now - last >= _API_ALERT_COOLDOWN_SECONDS:
            _api_alert_cache[key] = now
            return True
    return False

logger = logging.getLogger(__name__)

# Users tagged on scan, Breach Monitor and external API failure alerts. Mentions must go in the
# top-level "text" field — Slack does not notify for mentions inside attachments.
_FAILURE_MENTION_USER_IDS = ("U0950FUA2EP", "U0957EG0BD2", "U062BKX3DK2")


def _with_failure_mentions(payload: dict) -> dict:
    payload["text"] = " ".join(f"<@{uid}>" for uid in _FAILURE_MENTION_USER_IDS)
    return payload

_STEP_COLOURS = {
    "step":    "#FFA500",  # orange — individual step failure
    "overall": "#FF0000",  # red    — entire scan failed
    "score":   "#FF6600",  # dark orange — overall score update failed
}


def _build_step_failure_payload(
    domain: str,
    step_name: str,
    error: str,
    job_id: Optional[str],
    kind: str,
) -> dict:
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    if kind == "overall":
        title = f":x: Overall scan FAILED — `{domain}`"
    else:
        title = f":warning: Scan step failed — `{step_name}` for `{domain}`"

    fields = [
        {"title": "Domain",    "value": domain,     "short": True},
        {"title": "Scan Step", "value": step_name,  "short": True},
        {"title": "Time (UTC)","value": ts,          "short": True},
    ]
    if job_id:
        fields.append({"title": "Job ID", "value": f"`{job_id}`", "short": True})
    if error:
        fields.append({
            "title": "Error",
            "value": f"```{error[:800]}```",
            "short": False,
        })

    return _with_failure_mentions({
        "attachments": [
            {
                "color": _STEP_COLOURS.get(kind, "#FFA500"),
                "title": title,
                "fields": fields,
                "footer": "Vendiant Backend · Scan Health Monitor",
                "ts": int(datetime.now(timezone.utc).timestamp()),
            }
        ]
    })


def _post(payload: dict) -> None:
    url = os.getenv("SLACK_HEALTH_CHECK_WEBHOOK_URL", "")
    if not url:
        return
    try:
        resp = requests.post(url, json=payload, timeout=5)
        if resp.status_code != 200:
            logger.warning("Slack scan-health webhook returned %s", resp.status_code)
    except Exception as exc:
        logger.error("Failed to post scan-health alert to Slack: %s", exc)


def notify_scan_step_failure(
    domain: str,
    step_name: str,
    error: str,
    job_id: Optional[str] = None,
) -> None:
    """Fire a Slack alert for a single failed scan step. Non-blocking."""
    payload = _build_step_failure_payload(domain, step_name, error, job_id, kind="step")
    threading.Thread(target=_post, args=(payload,), daemon=True).start()


def notify_scan_overall_failure(
    domain: str,
    error: str,
    job_id: Optional[str] = None,
) -> None:
    """Fire a Slack alert when the entire domain scan fails. Non-blocking."""
    payload = _build_step_failure_payload(domain, "Overall Scan", error, job_id, kind="overall")
    threading.Thread(target=_post, args=(payload,), daemon=True).start()


def notify_score_update_failure(
    domain: str,
    error: str,
    job_id: Optional[str] = None,
) -> None:
    """Fire a Slack alert when the post-scan overall score update fails. Non-blocking."""
    payload = _build_step_failure_payload(domain, "Overall Score Update", error, job_id, kind="score")
    threading.Thread(target=_post, args=(payload,), daemon=True).start()


# ---------------------------------------------------------------------------
# External API failure notifications
# ---------------------------------------------------------------------------

_API_COLOURS = {
    "auth":        "#FF0000",   # red    — invalid / missing key
    "rate_limit":  "#FF6600",   # orange — quota exhausted
    "unavailable": "#FFA500",   # amber  — service down / timeout
    "error":       "#FFA500",   # amber  — generic API error
}

_API_ICONS = {
    "Network Scanner": ":satellite_antenna:",
    "AbuseIPDB":   ":shield:",
    "OpenAI":      ":robot_face:",
    "Breach Monitor":   ":mag:",
}


def _classify_api_error(error: str, status_code: Optional[int] = None) -> str:
    """Return a short error-type label used for dedup and colour selection."""
    msg = error.lower()
    code = status_code or 0
    if code == 401 or "invalid api key" in msg or "unauthorized" in msg or "authentication" in msg or "no api key" in msg:
        return "auth"
    if code == 429 or "rate limit" in msg or "too many requests" in msg or "quota" in msg:
        return "rate_limit"
    if code >= 500 or "timeout" in msg or "unavailable" in msg or "connection" in msg:
        return "unavailable"
    return "error"


def _build_api_failure_payload(
    api_name: str,
    domain: Optional[str],
    error: str,
    error_type: str,
    status_code: Optional[int],
    attempts: Optional[int] = None,
) -> dict:
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    icon = _API_ICONS.get(api_name, ":warning:")
    title = f"{icon} External API failure — *{api_name}*"

    type_labels = {
        "auth":        "Authentication failure — check API key",
        "rate_limit":  "Rate limit / quota exceeded",
        "unavailable": "Service unavailable / timeout",
        "error":       "API error",
    }

    # Who owns the failure and what (if anything) to do — so on-call can tell
    # a provider outage from a problem on our side at a glance.
    fault_labels = {
        "auth":        "Our side — API key rejected",
        "rate_limit":  "Our side — plan quota / rate limit hit",
        "unavailable": f"Provider side — {api_name} slow or down",
        "error":       "Unclear — inspect error detail",
    }
    action_labels = {
        "auth":        f"Check the {api_name} key in your .env / secrets store (expired, revoked or missing) and rotate if needed.",
        "rate_limit":  f"Check {api_name} usage against our plan; lookups will fail until the quota resets.",
        "unavailable": f"No action needed unless it repeats. If it persists, check {api_name}'s status page.",
        "error":       "Review the error detail and backend logs.",
    }

    fields = [
        {"title": "API",        "value": api_name,                        "short": True},
        {"title": "Error Type", "value": type_labels.get(error_type, error_type), "short": True},
        {"title": "Likely Fault", "value": fault_labels.get(error_type, "Unknown"), "short": True},
        {"title": "Time (UTC)", "value": ts,                              "short": True},
    ]
    if attempts:
        fields.append({"title": "Attempts", "value": f"{attempts} (all failed)", "short": True})
    if status_code:
        fields.append({"title": "HTTP Status", "value": str(status_code), "short": True})
    if domain:
        fields.append({"title": "Domain (context)", "value": domain, "short": True})
    if error:
        fields.append({"title": "Error Detail", "value": f"```{error[:600]}```", "short": False})
    fields.append({"title": "What to do", "value": action_labels.get(error_type, action_labels["error"]), "short": False})

    return {
        "attachments": [
            {
                "color": _API_COLOURS.get(error_type, "#FFA500"),
                "title": title,
                "fields": fields,
                "footer": "Vendiant Backend · External API Monitor",
                "ts": int(datetime.now(timezone.utc).timestamp()),
            }
        ]
    }


def _build_breach_monitor_operation_failure_payload(
    operation: str,
    error: str,
    domain: Optional[str],
) -> dict:
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    fields = [
        {"title": "Operation", "value": operation, "short": True},
        {"title": "Time (UTC)", "value": ts, "short": True},
    ]
    if domain:
        fields.append({"title": "Context", "value": domain, "short": True})
    if error:
        fields.append({"title": "Error", "value": f"```{error[:800]}```", "short": False})

    return _with_failure_mentions({
        "attachments": [
            {
                "color": "#FF0000",
                "title": ":mag: Breach Monitor operation failed",
                "fields": fields,
                "footer": "Vendiant Backend · Breach Monitor",
                "ts": int(datetime.now(timezone.utc).timestamp()),
            }
        ]
    })


def notify_breach_monitor_operation_failure(
    operation: str,
    error: str,
    *,
    domain: Optional[str] = None,
) -> None:
    """
    Fire a Slack alert when a Breach Monitor sync, webhook ingest, or batch job fails.
    Non-blocking — dispatches in a daemon thread.
    """
    payload = _build_breach_monitor_operation_failure_payload(operation, error, domain)
    threading.Thread(target=_post, args=(payload,), daemon=True).start()


def notify_external_api_failure(
    api_name: str,
    error: str,
    domain: Optional[str] = None,
    status_code: Optional[int] = None,
    attempts: Optional[int] = None,
) -> None:
    """
    Fire a deduplicated Slack alert for an external API failure.
    ``attempts`` is the number of tries made before giving up, if the caller retried.
    The same (api_name, error_type) pair will not re-alert within 5 minutes.
    Non-blocking — dispatches in a daemon thread.
    """
    error_type = _classify_api_error(error, status_code)

    if not _should_alert_api(api_name, error_type):
        logger.debug("Suppressing duplicate %s %s alert (cooldown active)", api_name, error_type)
        return

    payload = _with_failure_mentions(
        _build_api_failure_payload(api_name, domain, error, error_type, status_code, attempts)
    )
    threading.Thread(target=_post, args=(payload,), daemon=True).start()

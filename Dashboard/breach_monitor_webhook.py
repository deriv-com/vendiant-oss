"""
breach platform outbound webhook payload parsing and ingestion.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from fastapi import BackgroundTasks

logger = logging.getLogger(__name__)

# SHA-256("1") — Breach Monitor hashed monitoring payloads use this when a password was exposed.
_PASSWORD_EXPOSED_HASH = "6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b"
# SHA-256("0")
_PASSWORD_NOT_EXPOSED_HASH = "5feceb66ffc86f38d952786c6d696c79c2dbc239dd4e91b46729d73a27fb57e9"


def _is_breach_monitor_api_record(obj: Any) -> bool:
    """True when ``obj`` looks like a the breach platform breach record (requires information.uid)."""
    if not isinstance(obj, dict):
        return False
    info = obj.get("information")
    if not isinstance(info, dict):
        return False
    return bool((info.get("uid") or "").strip())


def _is_flat_monitoring_record(obj: Any) -> bool:
    """True for Breach Monitor monitoring callbacks with a top-level ``uid`` (hashed asset alerts)."""
    if not isinstance(obj, dict) or _is_breach_monitor_api_record(obj):
        return False
    return bool((obj.get("uid") or "").strip())


def _password_exposed_flag(flat: Dict[str, Any], masked: Dict[str, Any]) -> int:
    masked_pwd = str(masked.get("password", "")).strip()
    if masked_pwd == "1":
        return 1
    if masked_pwd == "0":
        return 0

    raw_pwd = flat.get("password")
    if isinstance(raw_pwd, str):
        lowered = raw_pwd.strip().lower()
        if lowered == _PASSWORD_EXPOSED_HASH:
            return 1
        if lowered == _PASSWORD_NOT_EXPOSED_HASH:
            return 0

    try:
        if raw_pwd is not None and int(raw_pwd) in (0, 1):
            return int(raw_pwd)
    except (TypeError, ValueError):
        pass

    pwd_info = flat.get("password_info")
    if isinstance(pwd_info, dict):
        if pwd_info.get("password_clear") == 1:
            return 1
        if pwd_info.get("password_is_encrypted") == 0 and masked_pwd not in ("", "0"):
            # Non-flag masked password implies exposure when encryption flag is off.
            if masked_pwd not in ("0", "1"):
                return 1

    return 0


def _flat_monitoring_to_api_record(flat: Dict[str, Any]) -> Dict[str, Any]:
    """
    Convert a flat hashed monitoring alert into the nested search-API record shape.

    Display fields prefer ``masked`` (human-readable); hashed top-level values are kept
    only when no masked counterpart exists.
    """
    masked = flat.get("masked") if isinstance(flat.get("masked"), dict) else {}
    uid = (flat.get("uid") or "").strip()

    information: Dict[str, Any] = {"uid": uid}
    if flat.get("date"):
        information["date"] = flat["date"]

    for field in (
        "email",
        "domain",
        "username",
        "web_address",
        "fullname",
        "name",
        "address",
        "city",
        "company",
        "country",
        "state",
        "zip",
        "telephone",
    ):
        masked_val = masked.get(field)
        if masked_val is not None and str(masked_val).strip():
            information[field] = str(masked_val).strip()
            continue
        flat_val = flat.get(field)
        if flat_val is not None and str(flat_val).strip():
            information[field] = str(flat_val).strip()

    information["password"] = _password_exposed_flag(flat, masked)

    masked_pwd = str(masked.get("password", "")).strip()
    if masked_pwd and masked_pwd not in ("0", "1"):
        information["password_plain"] = masked_pwd
    elif flat.get("password_plain"):
        information["password_plain"] = str(flat["password_plain"]).strip()

    if isinstance(flat.get("password_info"), dict):
        information["password_info"] = flat["password_info"]

    source = flat.get("source") if isinstance(flat.get("source"), dict) else {}
    if not source:
        source = {
            "name": "Breach Monitor Monitoring Alert",
            "type": "breach",
            "source": "darkweb",
            "confidence": "unknown",
            "description": (
                "Credential exposure detected via Breach Monitor domain or web-address monitoring."
            ),
            "recommendations": (
                "Update the affected account password immediately and review other services "
                "where the same or similar password may be in use."
            ),
        }

    return {
        "type": flat.get("type") or "breach",
        "validated": int(flat.get("validated", 0) or 0),
        "information": information,
        "source": source,
    }


def _has_masked_monitoring_information(inf: Dict[str, Any]) -> bool:
    """True when ``information`` JSONB stores a flat hashed alert with readable ``masked`` fields."""
    if not isinstance(inf, dict):
        return False
    masked = inf.get("masked")
    return isinstance(masked, dict) and bool(masked) and bool((inf.get("uid") or "").strip())


def resolve_stored_information(inf: Dict[str, Any]) -> Dict[str, Any]:
    """
    Prefer ``masked`` values when ``information`` was persisted as a flat hashed alert.

    Used when loading existing rows whose denormalized columns still contain SHA-256 hashes.
    """
    if not _has_masked_monitoring_information(inf):
        return inf if isinstance(inf, dict) else {}
    return _flat_monitoring_to_api_record(inf)["information"]


def resolve_stored_record_for_display(record: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize a stored breach row for API/dashboard output."""
    if not isinstance(record, dict):
        return record
    inf = record.get("information")
    if not isinstance(inf, dict) or not _has_masked_monitoring_information(inf):
        return record
    normalized = _flat_monitoring_to_api_record(inf)
    out = dict(record)
    out["information"] = normalized["information"]
    src = record.get("source")
    if not isinstance(src, dict) or not (src.get("name") or "").strip():
        out["source"] = normalized["source"]
    return out


def _normalize_breach_monitor_record(obj: Any) -> Optional[Dict[str, Any]]:
    """Return a nested API record, or ``None`` when ``obj`` is not a recognizable alert."""
    if not isinstance(obj, dict):
        return None
    if _is_breach_monitor_api_record(obj):
        return obj
    if _is_flat_monitoring_record(obj):
        return _flat_monitoring_to_api_record(obj)
    return None


def _collect_normalized_records(items: Any) -> List[Dict[str, Any]]:
    if not isinstance(items, list):
        return []
    out: List[Dict[str, Any]] = []
    for item in items:
        norm = _normalize_breach_monitor_record(item)
        if norm is not None:
            out.append(norm)
    return out


def extract_breach_monitor_results(payload: Any) -> List[Dict[str, Any]]:
    """
    Normalize Breach Monitor callback bodies into a list of API result dicts.

    Supports:
    - Single record: ``{ "type", "information", "source", ... }``
    - Flat monitoring alert: ``{ "uid", "masked": { ... }, ... }``
    - Search API envelope: ``{ "data": { "results": [...] } }``
    - ``{ "results": [...] }``
    - Top-level array of records
    - Common wrappers: ``alert``, ``record``, ``breach``, ``item``
    """
    if payload is None:
        return []

    if isinstance(payload, list):
        return _collect_normalized_records(payload)

    if not isinstance(payload, dict):
        return []

    norm = _normalize_breach_monitor_record(payload)
    if norm is not None:
        return [norm]

    data = payload.get("data")
    if isinstance(data, dict):
        norm = _normalize_breach_monitor_record(data)
        if norm is not None:
            return [norm]
        found = _collect_normalized_records(data.get("results"))
        if found:
            return found

    found = _collect_normalized_records(payload.get("results"))
    if found:
        return found

    for key in ("alert", "record", "breach", "item", "payload"):
        inner = payload.get(key)
        norm = _normalize_breach_monitor_record(inner)
        if norm is not None:
            return [norm]
        found = _collect_normalized_records(inner)
        if found:
            return found
        if isinstance(inner, dict):
            nested = extract_breach_monitor_results(inner)
            if nested:
                return nested

    return []


_MAX_LOGGED_UIDS = 50


def _record_uids(results: List[Dict[str, Any]]) -> str:
    """Comma-separated ``information.uid`` values for logging (capped)."""
    # UIDs come straight from the webhook payload; escape CR/LF so a crafted
    # value can't forge extra log lines.
    uids = [
        str((r.get("information") or {}).get("uid") or "")
        .strip()
        .replace("\r", "\\r")
        .replace("\n", "\\n")
        or "?"
        for r in results
    ]
    out = ",".join(uids[:_MAX_LOGGED_UIDS])
    if len(uids) > _MAX_LOGGED_UIDS:
        out += f",...(+{len(uids) - _MAX_LOGGED_UIDS} more)"
    return out


def process_breach_monitor_webhook_payload(
    payload: Any,
    background_tasks: "Optional[BackgroundTasks]" = None,
) -> Dict[str, Any]:
    """
    Upsert webhook records and notify Slack for newly discovered UIDs.

    Returns summary counts. Raises ``ValueError`` for unparseable payloads and
    ``RuntimeError`` when persistence fails after valid records were extracted.

    ``background_tasks``, when provided, defers the Slack notification fan-out
    (one HTTP call per new leak) until after the HTTP response is sent, so a
    large batch of new leaks can't hold the request/DB connection open while
    Slack is called synchronously. Falls back to sending inline when omitted
    (e.g. direct/offline calls, tests) so behaviour without FastAPI is unchanged.
    """
    try:
        from Dashboard.db_service import BreachMonitorRecordsService
    except ImportError:
        from db_service import BreachMonitorRecordsService

    results = extract_breach_monitor_results(payload)
    if not results:
        raise ValueError(
            "No valid Breach Monitor records in payload (each record needs uid or information.uid)"
        )

    # Logged up front so a failed delivery and Breach Monitor's redelivery of it can
    # be matched by uid in the logs.
    uids = _record_uids(results)
    logger.info("Breach Monitor webhook received: records=%s uids=%s", len(results), uids)

    svc = BreachMonitorRecordsService()
    new_summaries: List[Dict[str, Any]] = []
    written, new_rows, upd_rows = svc.upsert_api_results_with_stats(
        results,
        out_new_summaries=new_summaries,
    )

    if written == 0:
        logger.error("Breach Monitor webhook persist failed: uids=%s", uids)
        raise RuntimeError("Failed to persist Breach Monitor webhook records")

    if new_rows > 0:
        try:
            from slack.slack_service import send_breach_monitor_scheduled_sync_new_leaks_alert
        except ImportError:
            from Dashboard.slack.slack_service import send_breach_monitor_scheduled_sync_new_leaks_alert

        if background_tasks is not None:
            background_tasks.add_task(
                send_breach_monitor_scheduled_sync_new_leaks_alert, new_rows, new_summaries
            )
        else:
            send_breach_monitor_scheduled_sync_new_leaks_alert(new_rows, new_summaries)

    logger.info(
        "Breach Monitor webhook processed: received=%s written=%s new=%s updated=%s",
        len(results),
        written,
        new_rows,
        upd_rows,
    )

    return {
        "received": len(results),
        "rows_written": written,
        "new_uid_rows": new_rows,
        "existing_uid_updates": upd_rows,
    }

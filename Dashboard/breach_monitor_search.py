"""
Breach-platform search client: shared HTTP client, pagination and DB upsert.

Works with any breach-intelligence API that accepts a POST with a list of
domains (or emails) plus a ``next_id`` cursor and returns
``{"data": {"results": [...], "query": {"pagination": {...}}, "next_id": ...}}``.
Endpoint URLs and credentials come from the environment:

    BREACH_MONITOR_BREACH_SEARCH_URL   breach search endpoint (required)
    BREACH_MONITOR_BOTNET_SEARCH_URL   botnet / infostealer endpoint (optional)
    BREACH_MONITOR_USERNAME            account / tenant name sent as X-Username
    BREACH_MONITOR_TOKEN               API token sent as X-Token
    BREACH_MONITOR_APP_TOKEN           application token sent as X-AppToken
    BREACH_MONITOR_DOMAIN_GROUPS       JSON list of domain groups to sync

Domain batch format (both endpoints):
  {"domain": [["a.com"],["b.com"]], "next_id": ""}
"""

from __future__ import annotations

import json
import logging
import os
import re
import time
from typing import Any, Dict, List, Optional, Tuple

import requests

try:
    from Dashboard.db_service import BreachMonitorRecordsService
    from Dashboard.breach_monitor_quota import BreachMonitorQuotaService
except ImportError:
    from db_service import BreachMonitorRecordsService
    from breach_monitor_quota import BreachMonitorQuotaService

logger = logging.getLogger(__name__)


def _notify_breach_monitor_api_error(
    error: str,
    *,
    context: Optional[str] = None,
    status_code: Optional[int] = None,
    attempts: Optional[int] = None,
) -> None:
    try:
        from scan_health_notifier import notify_external_api_failure
    except ImportError:
        from Dashboard.scan_health_notifier import notify_external_api_failure

    notify_external_api_failure(
        "Breach Monitor",
        error,
        domain=context,
        status_code=status_code,
        attempts=attempts,
    )


def _request_exception_status(exc: requests.exceptions.RequestException) -> Optional[int]:
    resp = getattr(exc, "response", None)
    if resp is not None:
        return getattr(resp, "status_code", None)
    return None


BREACH_MONITOR_BREACH_SEARCH_URL = os.getenv("BREACH_MONITOR_BREACH_SEARCH_URL", "").strip()
BREACH_MONITOR_BOTNET_SEARCH_URL = os.getenv("BREACH_MONITOR_BOTNET_SEARCH_URL", "").strip()
MAX_PAGES = 100
REQUEST_TIMEOUT = 120
REQUEST_MAX_ATTEMPTS = 3  # Total attempts per page request before alerting
REQUEST_BACKOFF_SECONDS = 2  # Base delay between attempts (doubles each retry)
RETRYABLE_STATUS = {429, 500, 502, 503, 504}


def _post_with_retry(
    api_url: str,
    headers: Dict[str, str],
    payload: Dict[str, Any],
    *,
    retry_timeouts: bool = True,
) -> Tuple[requests.Response, int]:
    """
    POST to Breach Monitor, retrying connection errors and 429/5xx with exponential backoff.
    Read timeouts are retried only when ``retry_timeouts`` is True (each costs up to
    REQUEST_TIMEOUT seconds, too long for an interactive dashboard query).
    Quota is only consumed by the caller on success, so failed attempts cost nothing.

    Returns ``(response, attempts_made)``; raises the last RequestException when all attempts fail.
    The exception carries ``attempts_made`` as ``exc.attempts``.
    """
    for attempt in range(1, REQUEST_MAX_ATTEMPTS + 1):
        try:
            response = requests.post(api_url, headers=headers, json=payload, timeout=REQUEST_TIMEOUT)
            response.raise_for_status()
            return response, attempt
        except requests.exceptions.RequestException as e:
            if isinstance(e, requests.exceptions.HTTPError):
                retryable = _request_exception_status(e) in RETRYABLE_STATUS
            elif isinstance(e, requests.exceptions.Timeout):
                retryable = retry_timeouts
            else:
                retryable = isinstance(e, requests.exceptions.ConnectionError)
            if not retryable or attempt == REQUEST_MAX_ATTEMPTS:
                e.attempts = attempt
                raise
            delay = REQUEST_BACKOFF_SECONDS * (2 ** (attempt - 1))
            logger.warning(
                "Breach Monitor request failed (attempt %s/%s), retrying in %ss: %s",
                attempt, REQUEST_MAX_ATTEMPTS, delay, e,
            )
            time.sleep(delay)
    raise RuntimeError("unreachable")
BREACH_MONITOR_INTERACTIVE_PAGE_SIZE = 25


def _pagination_int(pagination: Dict[str, Any], key: str, default: int = 0) -> int:
    val = pagination.get(key)
    if val is None:
        return default
    try:
        return int(val)
    except (TypeError, ValueError):
        return default


def breach_monitor_interactive_has_more_pages(next_id: str, pagination: Dict[str, Any]) -> bool:
    """
    Whether the dashboard should show "Load more" for an interactive query.

    the breach platform returns up to 25 rows per page. When ``pagination.total`` is 25 or fewer, all
    results fit on one page even if ``next_id`` is present in the raw API response.
    """
    if not (next_id or "").strip():
        return False
    total = _pagination_int(pagination, "total")
    if total <= BREACH_MONITOR_INTERACTIVE_PAGE_SIZE:
        return False
    count = _pagination_int(pagination, "count")
    if count < BREACH_MONITOR_INTERACTIVE_PAGE_SIZE:
        return False
    return True

_DOMAIN_LABEL_RE = re.compile(r"^[a-zA-Z0-9](?:[a-zA-Z0-9.-]*[a-zA-Z0-9])?$")


def _load_dotenv() -> None:
    try:
        from dotenv import load_dotenv

        load_dotenv()
    except ImportError:
        pass


def breach_monitor_result_uids(results: List[Dict[str, Any]]) -> List[str]:
    """Collect ``information.uid`` values from API result rows (non-empty only)."""
    uids: List[str] = []
    for r in results:
        if not isinstance(r, dict):
            continue
        inf = r.get("information") or {}
        uid = (inf.get("uid") or "").strip()
        if uid:
            uids.append(uid)
    return uids


def get_breach_monitor_headers(
    *,
    app_token_env: str = "BREACH_MONITOR_APP_TOKEN",
) -> Optional[Dict[str, str]]:
    _load_dotenv()
    token = os.getenv("BREACH_MONITOR_TOKEN")
    app_token = os.getenv(app_token_env)
    username = (os.getenv("BREACH_MONITOR_USERNAME") or "").strip()
    if not token or not app_token or not username:
        return None
    return {
        "X-Username": username,
        "X-Token": token,
        "X-AppToken": app_token,
        "Content-Type": "application/json",
    }


def validate_breach_monitor_domain(domain: str) -> str:
    """Return normalized domain or raise ValueError (interactive query / config)."""
    d = (domain or "").strip().lower()
    if not d:
        raise ValueError("Domain is required")
    if not _validate_domain_label(d):
        raise ValueError("Invalid domain format")
    return d


def _validate_domain_label(d: str) -> bool:
    s = d.strip().lower()
    if not s or len(s) > 253:
        return False
    if ".." in s or s.startswith(".") or s.endswith("."):
        return False
    return all(
        _DOMAIN_LABEL_RE.match(part) for part in s.split(".") if part
    )


def load_domain_groups_from_env() -> List[List[str]]:
    """
    Parse BREACH_MONITOR_DOMAIN_GROUPS JSON, e.g.
    '[["example.com"],["example.org"]]' → [["example.com"], ["example.org"]]
    Falls back to one group per EMPLOYEE_EMAIL_DOMAINS entry when unset.
    """
    _load_dotenv()
    raw = os.getenv("BREACH_MONITOR_DOMAIN_GROUPS", "").strip()
    if not raw:
        try:
            from breach_monitor_export import EMPLOYEE_EMAIL_DOMAINS
        except ImportError:
            from Dashboard.breach_monitor_export import EMPLOYEE_EMAIL_DOMAINS
        raw = json.dumps([[d] for d in EMPLOYEE_EMAIL_DOMAINS])
    if raw == "[]":
        logger.error("BREACH_MONITOR_DOMAIN_GROUPS (or EMPLOYEE_EMAIL_DOMAINS) is not configured")
        return []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        logger.error("BREACH_MONITOR_DOMAIN_GROUPS is not valid JSON: %s", e)
        return []

    if not isinstance(data, list) or not data:
        logger.error("BREACH_MONITOR_DOMAIN_GROUPS must be a non-empty JSON array")
        return []

    out: List[List[str]] = []
    for i, group in enumerate(data):
        if not isinstance(group, list) or not group:
            logger.error("BREACH_MONITOR_DOMAIN_GROUPS[%s] must be a non-empty array", i)
            return []
        g: List[str] = []
        for j, dom in enumerate(group):
            if not isinstance(dom, str) or not dom.strip():
                logger.error("BREACH_MONITOR_DOMAIN_GROUPS[%s][%s] must be a non-empty string", i, j)
                return []
            d = dom.strip().lower()
            if not _validate_domain_label(d):
                logger.error("Invalid domain in BREACH_MONITOR_DOMAIN_GROUPS: %s", dom)
                return []
            g.append(d)
        out.append(g)

    if len(out) > 50:
        logger.error("BREACH_MONITOR_DOMAIN_GROUPS: too many domain groups (max 50)")
        return []

    return out


def run_breach_search_paginated(
    base_payload: Dict[str, Any],
    *,
    api_url: str = BREACH_MONITOR_BREACH_SEARCH_URL,
    db_service: BreachMonitorRecordsService,
    start_next_id: str = "",
    upsert_each_page: bool = False,
    accumulate_results: bool = True,
    interactive_query: bool = False,
    out_new_summaries: Optional[List[Dict[str, Any]]] = None,
    app_token_env: str = "BREACH_MONITOR_APP_TOKEN",
) -> Tuple[List[Dict[str, Any]], int, int, int, str, Dict[str, Any]]:
    """
    Call breach/search (or ``api_url``, e.g. botnet/search) with ``next_id`` until the API ends, safety limits hit,
    or a page contains only UIDs that were **already** in ``breach_monitor_records``
    before this page's upsert (incremental catch-up: no newer pages to discover).

    The duplicate-page shortcut is evaluated from DB state **before** upserting the current
    page, so a first-time sync that inserts a full page still advances to ``next_id``.

    ``base_payload`` must not include ``next_id``; one of ``email`` or ``domain`` (or both
    if API allows) plus optional ``date_from`` for email searches.

    When ``interactive_query`` is True (dashboard Query by email/domain): performs a single
    API call per invocation, does not use the duplicate-page DB shortcut (results are not
    persisted), and returns the API ``next_id`` for client-driven pagination.

    Returns ``(merged_results_or_empty, total_rows_upserted, new_uid_rows, existing_uid_updates, next_id_cursor, pagination)``.
    The fifth value is the next pagination token (empty when no further pages). The sixth is the
    API ``query.pagination`` object from the last response (for interactive queries).
    """
    if not api_url:
        msg = "Breach platform endpoint not configured (BREACH_MONITOR_BREACH_SEARCH_URL / BREACH_MONITOR_BOTNET_SEARCH_URL)"
        _notify_breach_monitor_api_error(msg, context="breach-monitor")
        raise ValueError(msg)

    headers = get_breach_monitor_headers(app_token_env=app_token_env)
    if not headers:
        msg = f"Breach platform credentials not configured (BREACH_MONITOR_USERNAME, BREACH_MONITOR_TOKEN, {app_token_env})"
        _notify_breach_monitor_api_error(msg, context=api_url, status_code=401)
        raise ValueError(msg)

    quota_svc = BreachMonitorQuotaService()
    if quota_svc.get_remaining() <= 0:
        logger.warning("Breach Monitor: API call quota is 0; skipping breach search")
        _notify_breach_monitor_api_error(
            "Breach Monitor API call quota exhausted (0 remaining)",
            context=api_url,
            status_code=429,
        )
        return ([], 0, 0, 0, "", {})

    current_next_id = start_next_id or ""
    page_count = 0
    all_results: List[Dict[str, Any]] = []
    total_upserted = 0
    total_new_uid_rows = 0
    total_existing_uid_updates = 0

    while True:
        if quota_svc.get_remaining() <= 0:
            logger.warning(
                "Breach Monitor: API quota exhausted mid-pagination; stopping further requests"
            )
            _notify_breach_monitor_api_error(
                "Breach Monitor API call quota exhausted during pagination",
                context=api_url,
                status_code=429,
            )
            break

        payload = {**base_payload, "next_id": current_next_id}

        try:
            response, _ = _post_with_retry(
                api_url, headers, payload, retry_timeouts=not interactive_query
            )
            response_data = response.json()
            left = quota_svc.consume_successful_calls(1)
            logger.debug("Breach Monitor API quota remaining after this call: %s", left)
        except requests.exceptions.RequestException as e:
            logger.error("Breach Monitor search request failed: %s", e)
            _notify_breach_monitor_api_error(
                str(e),
                context=api_url,
                status_code=_request_exception_status(e),
                attempts=getattr(e, "attempts", None),
            )
            break
        except json.JSONDecodeError as e:
            logger.error("Breach Monitor search invalid JSON: %s", e)
            _notify_breach_monitor_api_error(
                f"Invalid JSON in Breach Monitor API response: {e}",
                context=api_url,
            )
            break

        data = response_data.get("data", {})
        pagination = data.get("query", {}).get("pagination", {})
        count = pagination.get("count", 0)
        total = pagination.get("total", 0)

        logger.info(
            "Breach Monitor page %s: count=%s total=%s",
            page_count + 1,
            count,
            total,
        )

        results = data.get("results", [])
        if not isinstance(results, list):
            results = []

        if accumulate_results:
            all_results.extend(results)

        if interactive_query:
            next_cursor = (data.get("next_id") or "") if isinstance(data, dict) else ""
            page_pagination = pagination if isinstance(pagination, dict) else {}
            if not breach_monitor_interactive_has_more_pages(next_cursor, page_pagination):
                next_cursor = ""
            return (
                all_results,
                total_upserted,
                total_new_uid_rows,
                total_existing_uid_updates,
                next_cursor,
                page_pagination,
            )

        page_uids = breach_monitor_result_uids(results)
        # Must be evaluated before upsert: after insert, every uid on the page would
        # appear "already stored" and would incorrectly stop a fresh full sync on page 1.
        already_all_in_db_before_page = bool(page_uids) and db_service.breach_monitor_uids_all_exist_in_db(
            page_uids
        )

        if upsert_each_page and results:
            if out_new_summaries is not None:
                w, n_ins, n_upd = db_service.upsert_api_results_with_stats(
                    results, out_new_summaries=out_new_summaries
                )
            else:
                w, n_ins, n_upd = db_service.upsert_api_results_with_stats(results)
            total_upserted += w
            total_new_uid_rows += n_ins
            total_existing_uid_updates += n_upd
            logger.info(
                "Breach Monitor sync page %s: stored %s rows (%s new uid(s), %s update(s))",
                page_count + 1,
                w,
                n_ins,
                n_upd,
            )

        if already_all_in_db_before_page:
            logger.info(
                "Stopping Breach Monitor pagination: every UID on this page was already "
                "in the database before this page was applied (incremental sync caught up)"
            )
            break

        if count == 0:
            logger.info("Breach Monitor pagination end: count=0")
            break

        if count < 25:
            logger.info("Breach Monitor pagination end: partial page count=%s", count)
            break

        current_next_id = data.get("next_id", "") or ""
        if not current_next_id:
            logger.info("Breach Monitor pagination end: no next_id")
            break

        page_count += 1
        if page_count > MAX_PAGES:
            logger.warning("Breach Monitor pagination: max page limit %s reached", MAX_PAGES)
            break

    return all_results, total_upserted, total_new_uid_rows, total_existing_uid_updates, "", {}


def sync_breach_monitor_domain_breaches_to_db() -> Tuple[int, int, int, List[Dict[str, Any]]]:
    """
    Fetch domain-group breach data from the breach platform and upsert into PostgreSQL.
    Domain groups come from BREACH_MONITOR_DOMAIN_GROUPS (JSON).

    Returns ``(total_rows_upserted, new_uid_rows, existing_uid_updates, new_record_summaries)``.
    ``new_record_summaries`` is a list of safe preview dicts (one per new UID) for notifications.
    """
    _load_dotenv()
    groups = load_domain_groups_from_env()
    if not groups:
        logger.warning("Breach Monitor domain sync skipped: no valid BREACH_MONITOR_DOMAIN_GROUPS")
        return (0, 0, 0, [])

    svc = BreachMonitorRecordsService()
    base = {"domain": groups}
    new_summaries: List[Dict[str, Any]] = []
    _, rows, new_rows, upd_rows, _, _ = run_breach_search_paginated(
        base,
        db_service=svc,
        start_next_id="",
        upsert_each_page=True,
        accumulate_results=False,
        interactive_query=False,
        out_new_summaries=new_summaries,
    )
    logger.info(
        "Breach Monitor domain sync finished: total_rows=%s, new_uid_rows=%s, existing_uid_updates=%s",
        rows,
        new_rows,
        upd_rows,
    )
    return (rows, new_rows, upd_rows, new_summaries)


def sync_breach_monitor_domain_botnet_to_db() -> Tuple[int, int, int, List[Dict[str, Any]]]:
    """
    Fetch domain-group **botnet** (infostealer) records from the breach platform and upsert into PostgreSQL.

    Uses the same ``BREACH_MONITOR_DOMAIN_GROUPS`` payload shape as breach search.

    Returns ``(total_rows_upserted, new_uid_rows, existing_uid_updates, new_record_summaries)``.
    """
    _load_dotenv()
    if not BREACH_MONITOR_BOTNET_SEARCH_URL:
        logger.info("Breach Monitor botnet sync skipped: BREACH_MONITOR_BOTNET_SEARCH_URL not set")
        return (0, 0, 0, [])
    groups = load_domain_groups_from_env()
    if not groups:
        logger.warning("Breach Monitor botnet sync skipped: no valid BREACH_MONITOR_DOMAIN_GROUPS")
        return (0, 0, 0, [])

    svc = BreachMonitorRecordsService()
    base = {"domain": groups}
    new_summaries: List[Dict[str, Any]] = []
    _, rows, new_rows, upd_rows, _, _ = run_breach_search_paginated(
        base,
        api_url=BREACH_MONITOR_BOTNET_SEARCH_URL,
        db_service=svc,
        start_next_id="",
        upsert_each_page=True,
        accumulate_results=False,
        interactive_query=False,
        out_new_summaries=new_summaries,
    )
    logger.info(
        "Breach Monitor botnet sync finished: total_rows=%s, new_uid_rows=%s, existing_uid_updates=%s",
        rows,
        new_rows,
        upd_rows,
    )
    return (rows, new_rows, upd_rows, new_summaries)


def sync_breach_monitor_all_domain_intel_to_db() -> Tuple[int, int, int, List[Dict[str, Any]]]:
    """
    Run breach search then botnet search (same domains, sequential), merge upsert totals
    and new-leak summaries for Slack. Used by scheduler and dashboard refresh.

    Returns ``(total_rows_upserted, new_uid_rows, existing_uid_updates, new_record_summaries)``.
    """
    br, bn, bu, bs = sync_breach_monitor_domain_breaches_to_db()
    tr, tn, tu, ts = sync_breach_monitor_domain_botnet_to_db()
    total_rows = br + tr
    total_new = bn + tn
    total_existing_updates = bu + tu
    combined = bs + ts
    logger.info(
        "Breach Monitor combined domain intel: breach rows=%s new=%s; botnet rows=%s new=%s; "
        "combined total_rows=%s new_uid_rows=%s",
        br,
        bn,
        tr,
        tn,
        total_rows,
        total_new,
    )
    return (total_rows, total_new, total_existing_updates, combined)

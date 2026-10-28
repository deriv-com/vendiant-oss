"""
Breach Monitor API Routes
Handles Breach Monitor breach intelligence data endpoints
"""

import os
import json
import logging
import time
from collections import defaultdict
from datetime import date
from pathlib import Path
from threading import Lock
from fastapi import APIRouter, HTTPException, Body, Depends, Request, Query
from fastapi.responses import Response
from typing import Dict, Any, List, Optional, Set
from pydantic import BaseModel, Field

import re

try:
    from Dashboard.db_service import BreachMonitorRecordsService, BreachMonitorIgnoreListService
    from Dashboard.breach_monitor_search import (
        run_breach_search_paginated,
        sync_breach_monitor_all_domain_intel_to_db,
        sync_breach_monitor_domain_breaches_to_db,
        validate_breach_monitor_domain,
        BREACH_MONITOR_BOTNET_SEARCH_URL,
    )
    from Dashboard.breach_monitor_quota import BreachMonitorQuotaService
    from Dashboard.audit_service import audit_service, _client_ip as _audit_client_ip
    from Dashboard.breach_monitor_export import (
        EXPORT_UID_DB_BATCH_SIZE,
        MAX_EXPORT_UID_COUNT,
        build_breach_monitor_excel,
        export_filename,
        filter_breach_monitor_breaches,
        filter_breach_monitor_breaches_by_uids,
        normalize_breach_monitor_export_uids,
    )
except ImportError:
    from db_service import BreachMonitorRecordsService, BreachMonitorIgnoreListService
    from breach_monitor_search import (
        run_breach_search_paginated,
        sync_breach_monitor_all_domain_intel_to_db,
        sync_breach_monitor_domain_breaches_to_db,
        validate_breach_monitor_domain,
        BREACH_MONITOR_BOTNET_SEARCH_URL,
    )
    from breach_monitor_quota import BreachMonitorQuotaService
    from audit_service import audit_service, _client_ip as _audit_client_ip
    from breach_monitor_export import (
        EXPORT_UID_DB_BATCH_SIZE,
        MAX_EXPORT_UID_COUNT,
        build_breach_monitor_excel,
        export_filename,
        filter_breach_monitor_breaches,
        filter_breach_monitor_breaches_by_uids,
        normalize_breach_monitor_export_uids,
    )

_EMAIL_RE = re.compile(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$")

_breach_monitor_ignore_svc: Optional[BreachMonitorIgnoreListService] = None


def _get_ignore_svc() -> BreachMonitorIgnoreListService:
    global _breach_monitor_ignore_svc
    if _breach_monitor_ignore_svc is None:
        _breach_monitor_ignore_svc = BreachMonitorIgnoreListService()
    return _breach_monitor_ignore_svc


def _ignore_list_email_map(
    entries: List[Dict[str, Any]],
) -> Dict[str, Optional[tuple]]:
    """
    Map normalized email -> None (suppress all) or (Set[incident_names], Set[passwords]).
    Matches BreachMonitorIgnoreListService.should_suppress semantics.
    """
    out: Dict[str, Optional[tuple]] = {}
    for row in entries:
        em = (row.get("email") or "").strip().lower()
        if not em:
            continue
        names = {str(n).strip() for n in (row.get("incident_names") or []) if n and str(n).strip()}
        pwds = {str(p) for p in (row.get("passwords") or []) if p}
        if not names and not pwds:
            out[em] = None
        else:
            out[em] = (names, pwds)
    return out


def _breach_slack_suppressed(
    raw_email: str,
    incident_name: str,
    emap: Dict[str, Optional[tuple]],
    password: str = "",
) -> bool:
    em = (raw_email or "").strip().lower()
    if not em or em not in emap:
        return False
    rule = emap[em]
    if rule is None:
        return True
    names, pwds = rule
    if incident_name and incident_name in names:
        return True
    if password and password in pwds:
        return True
    return False


def annotate_breach_monitor_results_slack_ignore(results: List[Dict[str, Any]]) -> None:
    """
    Set slack_notifications_suppressed on each breach dict (in place).
    Uses one ignore-list load per call.
    """
    if not results:
        return
    try:
        entries = _get_ignore_svc().get_all()
    except Exception as exc:
        logging.warning("annotate_breach_monitor_results_slack_ignore: ignore list unavailable: %s", exc)
        for breach in results:
            breach["slack_notifications_suppressed"] = False
        return
    emap = _ignore_list_email_map(entries)
    for breach in results:
        info = breach.get("information") or {}
        source = breach.get("source") or {}
        raw_email = str(info.get("email") or "").strip()
        incident = str(source.get("name") or "").strip()
        password = str(info.get("password_plain") or "").strip()
        breach["slack_notifications_suppressed"] = bool(
            _breach_slack_suppressed(raw_email, incident, emap, password)
        )


# --- Auth (must match headers set by frontend proxy for authenticated users) ---
# Feature gates use Access Management assignments when present, else SSO role defaults
# (see Dashboard/effective_permissions.py — aligned with frontend/lib/rbac.ts).
try:
    from Dashboard.effective_permissions import (
        request_has_permission,
        require_permission,
    )
except ImportError:
    from effective_permissions import (
        request_has_permission,
        require_permission,
    )

require_internal_breach_access = require_permission("view_internal_breaches")
require_internal_breach_query = require_permission("query_internal_breaches")
require_password_access = require_permission("view_internal_breaches")


async def require_admin(request: Request) -> None:
    role = (request.headers.get("X-User-Role") or "").strip().lower()
    if role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")


def _is_request_admin(request: Request) -> bool:
    """True when X-User-Role matches admin (same semantics as require_admin)."""
    return (request.headers.get("X-User-Role") or "").strip().lower() == "admin"


def _can_view_passwords(request: Request) -> bool:
    """True when effective permissions include internal breach access."""
    return request_has_permission(request, "view_internal_breaches")


def _redact_breach_monitor_password_plain_from_results(results: List[Dict[str, Any]]) -> None:
    """Remove plaintext password material from each breach ``information`` dict (in place)."""
    for breach in results:
        info = breach.get("information")
        if isinstance(info, dict):
            info.pop("password_plain", None)


def _maybe_redact_breach_monitor_password_plain(results: List[Dict[str, Any]], request: Request) -> None:
    """Strip ``password_plain`` for callers without password-view access."""
    if _can_view_passwords(request):
        return
    _redact_breach_monitor_password_plain_from_results(results)


# --- Rate limit: heavy refresh endpoint (per client IP, sliding window) ---
_BREACH_MONITOR_REFRESH_WINDOW_SEC = 3600.0
_BREACH_MONITOR_REFRESH_MAX_PER_WINDOW = 10
_breach_monitor_refresh_times: Dict[str, List[float]] = defaultdict(list)
_breach_monitor_refresh_lock = Lock()


def _client_ip(request: Request) -> str:
    return _audit_client_ip(request) or "unknown"


def _audit_breach_monitor_action(
    request: Request,
    *,
    action: str,
    resource_id: str,
    details: Optional[Dict[str, Any]] = None,
) -> None:
    """Record a Breach Monitor admin action (ignore-list or breach resolve) in audit_logs."""
    try:
        user_email = (request.headers.get("X-User-Email") or "").strip()
        if not user_email:
            return
        audit_service.log_action(
            user_id=request.headers.get("X-User-ID", "unknown"),
            user_email=user_email,
            action=action,
            user_name=request.headers.get("X-User-Name"),
            user_role=request.headers.get("X-User-Role"),
            resource_type="breach-monitor",
            resource_id=resource_id[:500],
            details=details or {},
            ip_address=_client_ip(request),
            user_agent=request.headers.get("User-Agent"),
        )
    except Exception as e:
        logging.warning("Breach Monitor action audit log failed (%s): %s", action, e)


def _audit_breach_monitor_interactive_query(
    request: Request,
    *,
    query_kind: str,
    results_count: int,
    request_had_next_id: bool,
    response_next_id: str,
    domain: Optional[str] = None,
    email_value: Optional[str] = None,
) -> None:
    """
    Record dashboard Breach Monitor API query (domain or email) in audit_logs.
    """
    try:
        user_email = (request.headers.get("X-User-Email") or "").strip()
        if not user_email:
            return

        user_id = request.headers.get("X-User-ID", "unknown")
        user_name = request.headers.get("X-User-Name")
        user_role = request.headers.get("X-User-Role")
        user_agent = request.headers.get("User-Agent")
        ip_address = _client_ip(request)

        details: Dict[str, Any] = {
            "query_kind": query_kind,
            "pagination_continuation": request_had_next_id,
            "results_returned": results_count,
            "api_has_more_pages": bool((response_next_id or "").strip()),
        }
        resource_id = "breach_monitor_query"
        if query_kind == "domain" and domain:
            details["domain"] = domain
            details["queried_value"] = domain
            resource_id = domain[:500]
        elif query_kind == "email" and email_value:
            ev = email_value.strip().lower()
            parts = ev.split("@", 1)
            if len(parts) == 2:
                details["email_domain"] = parts[1][:253]
                details["email_username"] = parts[0]
                details["queried_value"] = ev
            else:
                details["queried_value"] = ev
                details["email_query_format"] = "non_standard"
            resource_id = ev[:500]

        audit_service.log_action(
            user_id=user_id,
            user_email=user_email,
            action="BREACH_MONITOR_QUERY",
            user_name=user_name,
            user_role=user_role,
            resource_type="breach-monitor",
            resource_id=resource_id[:500],
            details=details,
            ip_address=ip_address,
            user_agent=user_agent,
        )
    except Exception as e:
        logging.warning("Breach Monitor interactive query audit log failed: %s", e)


async def enforce_breach_monitor_refresh_rate_limit(request: Request) -> None:
    ip = _client_ip(request)
    now = time.time()
    with _breach_monitor_refresh_lock:
        bucket = _breach_monitor_refresh_times[ip]
        bucket[:] = [t for t in bucket if now - t < _BREACH_MONITOR_REFRESH_WINDOW_SEC]
        if len(bucket) >= _BREACH_MONITOR_REFRESH_MAX_PER_WINDOW:
            raise HTTPException(
                status_code=429,
                detail="Too many Breach Monitor refresh requests; try again later.",
            )
        bucket.append(now)

router = APIRouter(prefix="/api/breach-monitor", tags=["breach-monitor"])


def _parse_breach_monitor_date_param(param_name: str, raw: Optional[str]) -> Optional[date]:
    if raw is None:
        return None
    s = str(raw).strip()
    if not s:
        return None
    try:
        return date.fromisoformat(s[:10])
    except ValueError:
        raise HTTPException(
            status_code=422,
            detail=f"Invalid {param_name}: expected YYYY-MM-DD",
        )

# Get the Breach Monitor data directory
PROJECT_ROOT = Path(__file__).parent.parent.parent
BREACH_MONITOR_DATA_DIR = PROJECT_ROOT / "data"

_breach_monitor_db_service: Optional[BreachMonitorRecordsService] = None


def _get_breach_monitor_db_service() -> BreachMonitorRecordsService:
    global _breach_monitor_db_service
    if _breach_monitor_db_service is None:
        _breach_monitor_db_service = BreachMonitorRecordsService()
    return _breach_monitor_db_service


def _extract_results_from_file_payload(file_data: Any) -> List[Dict[str, Any]]:
    """Normalize JSON file contents to a list of Breach Monitor API result dicts."""
    out: List[Dict[str, Any]] = []
    if isinstance(file_data, dict) and "data" in file_data:
        results = file_data.get("data", {}).get("results", [])
        if results:
            out.extend(results)
    elif isinstance(file_data, list):
        out.extend(file_data)
    return out


def collect_breach_monitor_results_from_json_files() -> List[Dict[str, Any]]:
    """
    Read consolidated / fallback JSON files from disk (used after refresh script to sync DB).
    Order: data/breach_records.json, repo-root breach_records.json, then fallbacks.
    """
    all_results: List[Dict[str, Any]] = []

    primary_file = BREACH_MONITOR_DATA_DIR / "breach_records.json"
    root_file = PROJECT_ROOT / "breach_records.json"
    # Optional per-domain exports: data/<employee-domain>.json
    from breach_monitor_export import EMPLOYEE_EMAIL_DOMAINS
    fallback_files = [BREACH_MONITOR_DATA_DIR / f"{d}.json" for d in EMPLOYEE_EMAIL_DOMAINS]

    if primary_file.exists():
        try:
            with open(primary_file, "r", encoding="utf-8") as f:
                file_data = json.load(f)
            all_results.extend(_extract_results_from_file_payload(file_data))
            print(f"Loaded {len(all_results)} breaches from {primary_file.name}")
        except json.JSONDecodeError as e:
            print(f"Error loading JSON from {primary_file}: {e}")
        except Exception as e:
            print(f"Error reading {primary_file}: {e}")

    if not all_results and root_file.exists():
        try:
            with open(root_file, "r", encoding="utf-8") as f:
                file_data = json.load(f)
            all_results.extend(_extract_results_from_file_payload(file_data))
            print(f"Loaded {len(all_results)} breaches from {root_file.name}")
        except Exception as e:
            print(f"Error reading {root_file}: {e}")

    if not all_results:
        for data_file in fallback_files:
            if not data_file.exists():
                continue
            try:
                with open(data_file, "r", encoding="utf-8") as f:
                    file_data = json.load(f)
                chunk = _extract_results_from_file_payload(file_data)
                if chunk:
                    all_results.extend(chunk)
            except json.JSONDecodeError as e:
                print(f"Error loading JSON from {data_file}: {e}")
                continue
            except Exception as e:
                print(f"Error reading {data_file}: {e}")
                continue

    return all_results


# Pydantic models for request/response
class BreachMonitorQueryRequest(BaseModel):
    """Request model for Breach Monitor queries"""
    type: str  # "domain", "email", or "web_address"
    domain: Optional[str] = None
    email: Optional[str] = None
    web_address: Optional[str] = None  # comma-separated list of web addresses
    emails: Optional[str] = None  # optional comma-separated emails for web_address queries
    next_id: Optional[str] = None
    date_from: Optional[str] = None


_BREACH_MONITOR_DATE_FIELDS = frozenset({"ingested", "exposure"})


def _parse_breach_monitor_date_field(raw: Optional[str]) -> str:
    """Normalize date_field query/body value; default ingested. Invalid → 422."""
    if raw is None or not str(raw).strip():
        return "ingested"
    field = str(raw).strip().lower()
    if field not in _BREACH_MONITOR_DATE_FIELDS:
        raise HTTPException(
            status_code=422,
            detail="Invalid date_field: expected ingested or exposure",
        )
    return field


class BreachMonitorExportRequest(BaseModel):
    """Export filters + optional selected leak UIDs (POST body; avoids URI length limits)."""

    leak_view: str = "employees"
    org_filter: str = "all"
    slack_ignore_filter: str = "all"
    intel_type_filter: str = "all"
    password_filter: str = "all"
    resolve_status_filter: str = "all"
    search: Optional[str] = Field(None, max_length=500)
    date_from: Optional[str] = Field(None, max_length=10)
    date_to: Optional[str] = Field(None, max_length=10)
    date_field: str = Field(
        "ingested",
        description="Which date the range applies to: ingested or exposure",
        max_length=16,
    )
    uids: Optional[List[str]] = Field(
        None,
        description="Optional Breach Monitor UIDs; when set, export only these leaks.",
        max_length=MAX_EXPORT_UID_COUNT,
    )


def load_breach_monitor_data(
    date_from: Optional[date] = None,
    date_to: Optional[date] = None,
    date_field: str = "ingested",
) -> Dict[str, Any]:
    """
    Load Breach Monitor breach data from PostgreSQL (breach_monitor_records).

    Returns:
        Dict containing breach data in Breach Monitor API format
    """
    svc = _get_breach_monitor_db_service()
    payload = svc.get_breach_monitor_api_payload(
        date_from=date_from,
        date_to=date_to,
        date_field=date_field,
    )
    results = payload.get("data", {}).get("results", [])
    annotate_breach_monitor_results_slack_ignore(results)
    n = len(results)
    print(f"Loaded {n} Breach Monitor breach records from database")
    return payload


def _build_breach_monitor_excel_response(
    request: Request,
    *,
    leak_view: str,
    org_filter: str,
    slack_ignore_filter: str,
    intel_type_filter: str,
    password_filter: str,
    resolve_status_filter: str,
    search: Optional[str],
    date_from: Optional[str],
    date_to: Optional[str],
    date_field: Optional[str],
    uids: Optional[List[str]],
) -> Response:
    """Shared Excel export for GET (small queries) and POST (selected UIDs / filters)."""
    # Validate query/body params before the broad export handler so 422s are never
    # converted to 500 by the except Exception block below.
    df = _parse_breach_monitor_date_param("date_from", date_from)
    dt = _parse_breach_monitor_date_param("date_to", date_to)
    if df is not None and dt is not None and df > dt:
        raise HTTPException(
            status_code=422,
            detail="date_from must be on or before date_to",
        )
    resolved_date_field = _parse_breach_monitor_date_field(date_field)
    try:
        selected_uids = normalize_breach_monitor_export_uids(uids)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))

    try:
        # Selected-UID exports load only those rows from the DB in batches.
        # Filter-only exports still load the (date-scoped) full result set.
        if selected_uids:
            svc = _get_breach_monitor_db_service()
            results = svc.get_api_results_by_uids(
                selected_uids,
                batch_size=EXPORT_UID_DB_BATCH_SIZE,
                date_from=df,
                date_to=dt,
                date_field=resolved_date_field,
            )
            annotate_breach_monitor_results_slack_ignore(results)
        else:
            data = load_breach_monitor_data(
                date_from=df,
                date_to=dt,
                date_field=resolved_date_field,
            )
            results = data.get("data", {}).get("results", [])

        include_password = _can_view_passwords(request)
        if not include_password:
            _redact_breach_monitor_password_plain_from_results(results)

        filtered = filter_breach_monitor_breaches(
            results,
            leak_view=leak_view,
            org_filter=org_filter,
            slack_ignore_filter=slack_ignore_filter,
            intel_type_filter=intel_type_filter,
            password_filter=password_filter,
            resolve_status_filter=resolve_status_filter,
            search=search or "",
        )
        if selected_uids:
            filtered = filter_breach_monitor_breaches_by_uids(filtered, selected_uids)

        excel_bytes = build_breach_monitor_excel(
            filtered,
            include_password=include_password,
            sheet_title="Employee Leaks" if leak_view.strip().lower() == "employees" else "Client Leaks",
        )
        filename = export_filename(leak_view)

        _audit_breach_monitor_action(
            request,
            action="BREACH_MONITOR_EXPORT",
            resource_id=filename,
            details={
                "leak_view": leak_view,
                "org_filter": org_filter,
                "slack_ignore_filter": slack_ignore_filter,
                "intel_type_filter": intel_type_filter,
                "password_filter": password_filter,
                "resolve_status_filter": resolve_status_filter,
                "search_applied": bool((search or "").strip()),
                "date_from": date_from,
                "date_to": date_to,
                "date_field": resolved_date_field,
                "selected_uids_count": len(selected_uids),
                "row_count": len(filtered),
                "password_column_included": include_password,
            },
        )

        return Response(
            content=excel_bytes,
            media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"',
                "Cache-Control": "no-store",
            },
        )
    except HTTPException:
        raise
    except Exception as e:
        logging.error("Breach Monitor Excel export failed: %s", e)
        raise HTTPException(
            status_code=500,
            detail="Failed to export Breach Monitor credential leaks",
        )


@router.post("/export")
async def export_breach_monitor_breaches_excel_post(
    request: Request,
    body: BreachMonitorExportRequest = Body(...),
    _: None = Depends(require_internal_breach_access),
) -> Response:
    """
    Export filtered Breach Monitor credential leaks as Excel (.xlsx).

    Prefer POST when exporting selected rows — large ``uids`` lists exceed
    reverse-proxy URI limits on GET (HTTP 414).
    """
    return _build_breach_monitor_excel_response(
        request,
        leak_view=body.leak_view,
        org_filter=body.org_filter,
        slack_ignore_filter=body.slack_ignore_filter,
        intel_type_filter=body.intel_type_filter,
        password_filter=body.password_filter,
        resolve_status_filter=body.resolve_status_filter,
        search=body.search,
        date_from=body.date_from,
        date_to=body.date_to,
        date_field=body.date_field,
        uids=body.uids,
    )


@router.get("/export")
async def export_breach_monitor_breaches_excel(
    request: Request,
    leak_view: str = Query("employees", description="clients or employees"),
    org_filter: str = Query("all", description="all or one of the configured EMPLOYEE_EMAIL_DOMAINS"),
    slack_ignore_filter: str = Query(
        "all",
        description="all, hide_ignored, or ignored_only",
    ),
    intel_type_filter: str = Query(
        "all",
        description="all, botnet, or other",
    ),
    password_filter: str = Query(
        "all",
        description="all, with_password, or without_password",
    ),
    resolve_status_filter: str = Query(
        "all",
        description="all, active, resolved, or false_positive",
    ),
    search: Optional[str] = Query(None, description="Free-text search"),
    date_from: Optional[str] = Query(
        None,
        description="Inclusive start date (YYYY-MM-DD).",
    ),
    date_to: Optional[str] = Query(
        None,
        description="Inclusive end date (YYYY-MM-DD).",
    ),
    date_field: str = Query(
        "ingested",
        description="Date column for the range: ingested or exposure",
    ),
    uids: Optional[List[str]] = Query(
        None,
        description="Optional Breach Monitor UIDs; prefer POST /export for large selections.",
    ),
    _: None = Depends(require_internal_breach_access),
) -> Response:
    """
    Export filtered Breach Monitor credential leaks as Excel (.xlsx).

    For large selected-UID exports use POST /api/breach-monitor/export to avoid HTTP 414.
    """
    if uids and len(uids) > 25:
        raise HTTPException(
            status_code=414,
            detail="Too many uids for GET; use POST /api/breach-monitor/export with a JSON body",
        )
    return _build_breach_monitor_excel_response(
        request,
        leak_view=leak_view,
        org_filter=org_filter,
        slack_ignore_filter=slack_ignore_filter,
        intel_type_filter=intel_type_filter,
        password_filter=password_filter,
        resolve_status_filter=resolve_status_filter,
        search=search,
        date_from=date_from,
        date_to=date_to,
        date_field=date_field,
        uids=uids,
    )


@router.get("")
async def get_breach_monitor_breaches(
    request: Request,
    date_from: Optional[str] = Query(
        None,
        description="Inclusive start date (YYYY-MM-DD).",
    ),
    date_to: Optional[str] = Query(
        None,
        description="Inclusive end date (YYYY-MM-DD).",
    ),
    date_field: str = Query(
        "ingested",
        description="Date column for the range: ingested or exposure",
    ),
    _: None = Depends(require_internal_breach_access),
) -> Dict[str, Any]:
    """
    Get all Breach Monitor breach intelligence data
    
    Returns:
        Breach Monitor breach data in standard API format
        
    Raises:
        HTTPException: If data cannot be loaded
    """
    try:
        df = _parse_breach_monitor_date_param("date_from", date_from)
        dt = _parse_breach_monitor_date_param("date_to", date_to)
        if df is not None and dt is not None and df > dt:
            raise HTTPException(
                status_code=422,
                detail="date_from must be on or before date_to",
            )
        resolved_date_field = _parse_breach_monitor_date_field(date_field)
        data = load_breach_monitor_data(
            date_from=df,
            date_to=dt,
            date_field=resolved_date_field,
        )
        _maybe_redact_breach_monitor_password_plain(
            data.get("data", {}).get("results", []),
            request,
        )

        # Log the retrieval
        total_breaches = len(data.get('data', {}).get('results', []))
        print(f"Retrieved {total_breaches} Breach Monitor breach records")

        return data

    except HTTPException:
        raise
    except Exception as e:
        print(f"Error retrieving Breach Monitor data: {e}")
        raise HTTPException(
            status_code=500,
            detail="Failed to retrieve Breach Monitor data",
        )


@router.get("/quota")
async def get_breach_monitor_api_quota(
    _: None = Depends(require_internal_breach_access),
) -> Dict[str, Any]:
    """Remaining Breach Monitor breach search API calls (decremented on each successful search request)."""
    try:
        remaining = BreachMonitorQuotaService().get_remaining()
        return {"status": 200, "calls_remaining": remaining}
    except Exception as e:
        print(f"Error reading Breach Monitor API quota: {e}")
        raise HTTPException(
            status_code=500,
            detail="Failed to read API quota",
        )


@router.get("/stats")
async def get_breach_monitor_stats(
    _: None = Depends(require_internal_breach_access),
) -> Dict[str, Any]:
    """
    Get statistics about Breach Monitor breach data
    
    Returns:
        Statistics including total breaches, unique emails, etc.
    """
    try:
        data = load_breach_monitor_data()
        results = data.get('data', {}).get('results', [])
        
        # Calculate statistics
        unique_emails = len(set(
            breach.get('information', {}).get('email') 
            for breach in results 
            if breach.get('information', {}).get('email')
        ))
        
        unique_sources = len(set(
            breach.get('source', {}).get('name') 
            for breach in results 
            if breach.get('source', {}).get('name')
        ))
        
        # Count by domain
        domains = {}
        for breach in results:
            domain = breach.get('information', {}).get('domain', 'unknown')
            domains[domain] = domains.get(domain, 0) + 1
        
        return {
            "status": 200,
            "data": {
                "total_breaches": len(results),
                "unique_emails": unique_emails,
                "unique_sources": unique_sources,
                "breaches_by_domain": domains
            }
        }
        
    except Exception as e:
        print(f"Error calculating Breach Monitor stats: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to calculate stats: {str(e)}"
        )


@router.get("/refresh")
async def refresh_breach_monitor_data(
    _: None = Depends(require_admin),
    __: None = Depends(enforce_breach_monitor_refresh_rate_limit),
) -> Dict[str, Any]:
    """
    Pull Breach Monitor breach + botnet domain data from the breach platform (BREACH_MONITOR_DOMAIN_GROUPS) and upsert into PostgreSQL.
    Same logic as the 4-hour scheduled sync (including Slack for new leaks). Admin only; rate-limited per client IP.
    """
    try:
        rows, new_uid_rows, uid_updates, new_summaries = sync_breach_monitor_all_domain_intel_to_db()
        print(
            f"Breach Monitor refresh: breach+botnet rows={rows}, new_uid_rows={new_uid_rows}, "
            f"existing_uid_updates={uid_updates}"
        )
        if new_uid_rows > 0:
            from slack.slack_service import send_breach_monitor_scheduled_sync_new_leaks_alert

            send_breach_monitor_scheduled_sync_new_leaks_alert(new_uid_rows, new_summaries)
        data = load_breach_monitor_data()
        return data
    except ValueError as e:
        # API/config errors are reported from breach_monitor_search; no duplicate health alert.
        raise HTTPException(status_code=503, detail=str(e))
    except HTTPException:
        raise
    except Exception as e:
        print(f"Error refreshing Breach Monitor data: {e}")
        try:
            from scan_health_notifier import notify_breach_monitor_operation_failure
        except ImportError:
            from Dashboard.scan_health_notifier import notify_breach_monitor_operation_failure

        notify_breach_monitor_operation_failure("Manual refresh", str(e))
        raise HTTPException(
            status_code=500,
            detail=f"Failed to refresh data: {str(e)}",
        )


@router.post("/search")
async def search_breach_monitor_breaches(
    request: Request,
    email: str = None,
    domain: str = None,
    source: str = None,
    _: None = Depends(require_internal_breach_query),
) -> Dict[str, Any]:
    """
    Search Breach Monitor breaches by criteria
    
    Args:
        email: Email address to search for
        domain: Domain to search for
        source: Breach source to search for
    
    Returns:
        Filtered breach results
    """
    try:
        data = load_breach_monitor_data()
        results = data.get('data', {}).get('results', [])
        
        # Filter results
        filtered_results = []
        for breach in results:
            info = breach.get('information', {})
            source_info = breach.get('source', {})
            
            if email and email.lower() not in info.get('email', '').lower():
                continue
            if domain and domain.lower() not in info.get('domain', '').lower():
                continue
            if source and source.lower() not in source_info.get('name', '').lower():
                continue
                
            filtered_results.append(breach)

        _maybe_redact_breach_monitor_password_plain(filtered_results, request)

        return {
            "status": 200,
            "description": "OK",
            "data": {
                "results": filtered_results,
                "query": {
                    "pagination": {
                        "total": len(filtered_results),
                        "count": len(filtered_results),
                        "page": 0
                    }
                },
                "search_criteria": {
                    "email": email,
                    "domain": domain,
                    "source": source
                }
            }
        }
        
    except Exception as e:
        print(f"Error searching Breach Monitor data: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Search failed: {str(e)}"
        )


@router.post("/query")
async def query_breach_monitor_data(
    query_request: BreachMonitorQueryRequest,
    request: Request,
    _: None = Depends(require_internal_breach_query),
) -> Dict[str, Any]:
    """
    Query Breach Monitor breach data by domain or email.

    Requires ``query_internal_breaches``. One API call per request; results are
    **not** written to the database (display-only).
    Returns up to one page of results (typically 25) plus ``next_id`` when more pages exist.
    The client passes ``next_id`` on subsequent requests to load the next page.
    """
    try:
        query_type = query_request.type
        next_id = query_request.next_id or ''

        if query_type in ("domain", "email", "web_address"):
            if BreachMonitorQuotaService().get_remaining() <= 0:
                try:
                    from scan_health_notifier import notify_external_api_failure
                except ImportError:
                    from Dashboard.scan_health_notifier import notify_external_api_failure

                notify_external_api_failure(
                    "Breach Monitor",
                    "Breach Monitor API call quota exhausted (interactive query)",
                    status_code=429,
                )
                raise HTTPException(
                    status_code=429,
                    detail="Breach Monitor API call quota exhausted",
                )

        if query_type == 'domain':
            raw_domain = (query_request.domain or "").strip()
            if not raw_domain:
                raise ValueError("Domain is required")
            domains = [
                validate_breach_monitor_domain(part)
                for part in raw_domain.split(",")
                if part.strip()
            ]
            if not domains:
                raise ValueError("At least one domain is required")
            # API shape: one group per domain string: [["a.com"],["b.com"]]
            base_payload: Dict[str, Any] = {"domain": [[d] for d in domains]}
            dom = ", ".join(domains)
            svc = _get_breach_monitor_db_service()
            all_results, _, _, _, next_cursor, api_pagination = run_breach_search_paginated(
                base_payload,
                db_service=svc,
                start_next_id=next_id,
                upsert_each_page=False,
                accumulate_results=True,
                interactive_query=True,
            )
            nc = next_cursor or ""
            page_pagination = (
                api_pagination
                if isinstance(api_pagination, dict) and api_pagination
                else {
                    "total": len(all_results),
                    "count": len(all_results),
                    "page": 0,
                }
            )
            _audit_breach_monitor_interactive_query(
                request,
                query_kind="domain",
                results_count=len(all_results),
                request_had_next_id=bool((next_id or "").strip()),
                response_next_id=nc,
                domain=dom,
            )
            annotate_breach_monitor_results_slack_ignore(all_results)
            return {
                "status": 200,
                "description": "OK",
                "data": {
                    "results": all_results,
                    "query": {
                        "pagination": page_pagination,
                    },
                    "next_id": nc,
                },
            }

        elif query_type == 'email':
            raw_email = (query_request.email or '').strip()
            if not raw_email:
                raise ValueError("Email is required")
            emails: List[str] = []
            for part in raw_email.split(","):
                addr = part.strip().lower()
                if not addr:
                    continue
                if not _EMAIL_RE.match(addr):
                    raise ValueError(f"Invalid email format: {part.strip()}")
                emails.append(addr)
            if not emails:
                raise ValueError("At least one email is required")

            base_payload: Dict[str, Any] = {
                "email": [[e] for e in emails] if len(emails) > 1 else [emails[0]],
                "date_from": query_request.date_from or "",
            }
            email = ", ".join(emails)
            svc = _get_breach_monitor_db_service()
            all_results, _, _, _, next_cursor, api_pagination = run_breach_search_paginated(
                base_payload,
                db_service=svc,
                start_next_id=next_id,
                upsert_each_page=False,
                accumulate_results=True,
                interactive_query=True,
            )

            print(
                f"Interactive email query page: {len(all_results)} record(s), next_id={'set' if next_cursor else 'none'}"
            )
            nc = next_cursor or ""
            page_pagination = (
                api_pagination
                if isinstance(api_pagination, dict) and api_pagination
                else {
                    "total": len(all_results),
                    "count": len(all_results),
                    "page": 0,
                }
            )
            _audit_breach_monitor_interactive_query(
                request,
                query_kind="email",
                results_count=len(all_results),
                request_had_next_id=bool((next_id or "").strip()),
                response_next_id=nc,
                email_value=email,
            )
            annotate_breach_monitor_results_slack_ignore(all_results)
            return {
                "status": 200,
                "description": "OK",
                "data": {
                    "results": all_results,
                    "query": {
                        "pagination": page_pagination,
                    },
                    "next_id": nc,
                },
            }
        
        elif query_type == 'web_address':
            raw = (query_request.web_address or '').strip()
            if not raw:
                raise ValueError("web_address is required")
            # Parse comma-separated addresses into [[addr1],[addr2],...] nested array
            addrs = [a.strip() for a in raw.split(',') if a.strip()]
            if not addrs:
                raise ValueError("At least one web address is required")
            base_payload: Dict[str, Any] = {"web_address": [[a] for a in addrs]}
            # Optional email filter: add when provided
            raw_emails = (query_request.emails or '').strip()
            app_token_env = "BREACH_MONITOR_APP_TOKEN"
            if raw_emails:
                parsed_emails = [e.strip() for e in raw_emails.split(',') if e.strip()]
                if parsed_emails:
                    base_payload["email"] = [[e] for e in parsed_emails]
                    app_token_env = "BREACH_MONITOR_APP_TOKEN_1"
            svc = _get_breach_monitor_db_service()
            all_results, _, _, _, next_cursor, api_pagination = run_breach_search_paginated(
                base_payload,
                api_url=BREACH_MONITOR_BOTNET_SEARCH_URL,
                db_service=svc,
                start_next_id=next_id,
                upsert_each_page=False,
                accumulate_results=True,
                interactive_query=True,
                app_token_env=app_token_env,
            )
            nc = next_cursor or ""
            page_pagination = (
                api_pagination
                if isinstance(api_pagination, dict) and api_pagination
                else {
                    "total": len(all_results),
                    "count": len(all_results),
                    "page": 0,
                }
            )
            _audit_breach_monitor_interactive_query(
                request,
                query_kind="web_address",
                results_count=len(all_results),
                request_had_next_id=bool((next_id or "").strip()),
                response_next_id=nc,
                domain=raw[:500],
            )
            annotate_breach_monitor_results_slack_ignore(all_results)
            return {
                "status": 200,
                "description": "OK",
                "data": {
                    "results": all_results,
                    "query": {
                        "pagination": page_pagination,
                    },
                    "next_id": nc,
                },
            }

        else:
            raise ValueError("Invalid query type. Must be 'domain', 'email', or 'web_address'")
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"Error querying Breach Monitor data: {e}")
        err_msg = str(e)
        if "credentials not configured" in err_msg.lower() or "quota" in err_msg.lower():
            try:
                from scan_health_notifier import notify_external_api_failure
            except ImportError:
                from Dashboard.scan_health_notifier import notify_external_api_failure

            status_code = 429 if "quota" in err_msg.lower() else None
            notify_external_api_failure("Breach Monitor", err_msg, status_code=status_code)
        raise HTTPException(
            status_code=400,
            detail=f"Query failed: {err_msg}"
        )


class IgnoreListUpsertRequest(BaseModel):
    email: str
    incident_names: List[str] = []
    passwords: List[str] = []
    notes: Optional[str] = None


@router.get("/breach-passwords")
async def get_breach_monitor_breach_passwords(
    email: str,
    _: None = Depends(require_password_access),
) -> Dict[str, Any]:
    """Return all distinct plaintext passwords recorded for an email (admin or user-extended)."""
    email = (email or "").strip().lower()
    if not email or not _EMAIL_RE.match(email):
        raise HTTPException(status_code=422, detail="A valid email address is required")
    try:
        svc = _get_breach_monitor_db_service()
        passwords = svc.get_passwords_for_email(email)
        return {"status": 200, "passwords": passwords}
    except Exception as e:
        logging.error("get_breach_monitor_breach_passwords: %s", e)
        raise HTTPException(status_code=500, detail="Failed to fetch passwords")


@router.get("/incidents")
async def get_breach_monitor_incident_names(
    _: None = Depends(require_admin),
) -> Dict[str, Any]:
    """Return all distinct breach incident names from breach_monitor_records (admin)."""
    try:
        svc = _get_breach_monitor_db_service()
        names = svc.get_distinct_incident_names()
        return {"status": 200, "incidents": names}
    except Exception as e:
        logging.error("get_breach_monitor_incident_names: %s", e)
        raise HTTPException(status_code=500, detail="Failed to fetch incident names")


@router.get("/ignore-list")
async def get_breach_monitor_ignore_list(
    _: None = Depends(require_admin),
) -> Dict[str, Any]:
    """Return all Breach Monitor Slack ignore-list entries (admin)."""
    try:
        entries = _get_ignore_svc().get_all()
        return {"status": 200, "data": entries}
    except Exception as e:
        logging.error("get_breach_monitor_ignore_list: %s", e)
        raise HTTPException(status_code=500, detail="Failed to fetch ignore list")


@router.post("/ignore-list")
async def upsert_breach_monitor_ignore_list(
    body: IgnoreListUpsertRequest,
    request: Request,
    _: None = Depends(require_admin),
) -> Dict[str, Any]:
    """
    Add or update a Breach Monitor Slack ignore-list entry (admin).

    - ``email`` – required; must be a valid e-mail address.
    - ``incident_names`` – optional list of breach incident names to suppress.
      An empty list means *all* future Slack alerts for this email are suppressed.
    - ``notes`` – optional free-text annotation.
    """
    email = (body.email or "").strip().lower()
    if not email or not _EMAIL_RE.match(email):
        raise HTTPException(status_code=422, detail="A valid email address is required")

    cleaned_incidents: List[str] = []
    for name in body.incident_names:
        n = (name or "").strip()
        if n:
            cleaned_incidents.append(n)

    cleaned_passwords: List[str] = [p for p in body.passwords if p]

    notes = (body.notes or "").strip() or None
    created_by = (request.headers.get("X-User-Email") or "").strip() or None

    row = _get_ignore_svc().upsert(email, cleaned_incidents, cleaned_passwords, notes, created_by)
    if row is None:
        raise HTTPException(status_code=500, detail="Failed to save ignore-list entry")
    _audit_breach_monitor_action(
        request,
        action="BREACH_MONITOR_IGNORE_LIST_ADD",
        resource_id=email,
        details={
            "email": email,
            "incident_names": cleaned_incidents,
            "password_count": len(cleaned_passwords),
            "suppress_all": len(cleaned_incidents) == 0 and len(cleaned_passwords) == 0,
            "notes": notes,
        },
    )
    return {"status": 200, "data": row}


@router.delete("/ignore-list/{entry_id}")
async def delete_breach_monitor_ignore_list_entry(
    entry_id: int,
    request: Request,
    _: None = Depends(require_admin),
) -> Dict[str, Any]:
    """Delete a Breach Monitor Slack ignore-list entry by id (admin)."""
    if entry_id <= 0:
        raise HTTPException(status_code=422, detail="Invalid entry id")
    ok = _get_ignore_svc().delete(entry_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Entry not found or could not be deleted")
    _audit_breach_monitor_action(
        request,
        action="BREACH_MONITOR_IGNORE_LIST_REMOVE",
        resource_id=str(entry_id),
        details={"entry_id": entry_id},
    )
    return {"status": 200, "message": "Entry deleted"}


class BulkResolveRequest(BaseModel):
    breach_monitor_uids: List[str]


@router.patch("/breaches/{breach_monitor_uid}/resolve")
async def resolve_breach_monitor_breach(
    breach_monitor_uid: str,
    request: Request,
    _: None = Depends(require_admin),
) -> Dict[str, Any]:
    """Mark a single Breach Monitor breach record as resolved (admin)."""
    uid = breach_monitor_uid.strip()
    if not uid:
        raise HTTPException(status_code=422, detail="breach_monitor_uid is required")
    resolved_by = (request.headers.get("X-User-Email") or "").strip() or "unknown"
    svc = _get_breach_monitor_db_service()
    ok = svc.resolve_breach(uid, resolved_by)
    if not ok:
        raise HTTPException(status_code=404, detail="Breach record not found")
    _audit_breach_monitor_action(
        request,
        action="BREACH_MONITOR_BREACH_RESOLVE",
        resource_id=uid,
        details={"breach_monitor_uid": uid, "resolved_by": resolved_by},
    )
    return {"status": 200, "message": "Breach marked as resolved", "breach_monitor_uid": uid}


@router.patch("/breaches/{breach_monitor_uid}/unresolve")
async def unresolve_breach_monitor_breach(
    breach_monitor_uid: str,
    request: Request,
    _: None = Depends(require_admin),
) -> Dict[str, Any]:
    """Reopen a previously resolved Breach Monitor breach record (admin)."""
    uid = breach_monitor_uid.strip()
    if not uid:
        raise HTTPException(status_code=422, detail="breach_monitor_uid is required")
    svc = _get_breach_monitor_db_service()
    ok = svc.unresolve_breach(uid)
    if not ok:
        raise HTTPException(status_code=404, detail="Breach record not found")
    _audit_breach_monitor_action(
        request,
        action="BREACH_MONITOR_BREACH_UNRESOLVE",
        resource_id=uid,
        details={"breach_monitor_uid": uid},
    )
    return {"status": 200, "message": "Breach reopened as active", "breach_monitor_uid": uid}


@router.post("/breaches/bulk-resolve")
async def bulk_resolve_breach_monitor_breaches(
    body: BulkResolveRequest,
    request: Request,
    _: None = Depends(require_admin),
) -> Dict[str, Any]:
    """Mark multiple Breach Monitor breach records as resolved (admin)."""
    uids = [u.strip() for u in body.breach_monitor_uids if u and u.strip()]
    if not uids:
        raise HTTPException(status_code=422, detail="breach_monitor_uids must be a non-empty list")
    resolved_by = (request.headers.get("X-User-Email") or "").strip() or "unknown"
    svc = _get_breach_monitor_db_service()
    updated = svc.bulk_resolve_breaches(uids, resolved_by)
    _audit_breach_monitor_action(
        request,
        action="BREACH_MONITOR_BREACH_RESOLVE",
        resource_id=f"bulk:{updated}",
        details={"breach_monitor_uids": uids, "resolved_by": resolved_by, "updated_count": updated, "bulk": True},
    )
    return {"status": 200, "message": f"{updated} breach(es) marked as resolved", "updated": updated}


@router.post("/breaches/bulk-unresolve")
async def bulk_unresolve_breach_monitor_breaches(
    body: BulkResolveRequest,
    request: Request,
    _: None = Depends(require_admin),
) -> Dict[str, Any]:
    """Reopen multiple Breach Monitor breach records (admin)."""
    uids = [u.strip() for u in body.breach_monitor_uids if u and u.strip()]
    if not uids:
        raise HTTPException(status_code=422, detail="breach_monitor_uids must be a non-empty list")
    svc = _get_breach_monitor_db_service()
    updated = svc.bulk_unresolve_breaches(uids)
    _audit_breach_monitor_action(
        request,
        action="BREACH_MONITOR_BREACH_UNRESOLVE",
        resource_id=f"bulk:{updated}",
        details={"breach_monitor_uids": uids, "updated_count": updated, "bulk": True},
    )
    return {"status": 200, "message": f"{updated} breach(es) reopened as active", "updated": updated}


@router.patch("/breaches/{breach_monitor_uid}/mark-false-positive")
async def mark_breach_monitor_breach_false_positive(
    breach_monitor_uid: str,
    request: Request,
    _: None = Depends(require_admin),
) -> Dict[str, Any]:
    """Mark a single Breach Monitor breach record as a false positive (admin)."""
    uid = breach_monitor_uid.strip()
    if not uid:
        raise HTTPException(status_code=422, detail="breach_monitor_uid is required")
    marked_by = (request.headers.get("X-User-Email") or "").strip() or "unknown"
    svc = _get_breach_monitor_db_service()
    ok = svc.mark_false_positive(uid, marked_by)
    if not ok:
        raise HTTPException(status_code=404, detail="Breach record not found")
    _audit_breach_monitor_action(
        request,
        action="BREACH_MONITOR_BREACH_FALSE_POSITIVE",
        resource_id=uid,
        details={"breach_monitor_uid": uid, "marked_by": marked_by},
    )
    return {"status": 200, "message": "Breach marked as false positive", "breach_monitor_uid": uid}


@router.patch("/breaches/{breach_monitor_uid}/unmark-false-positive")
async def unmark_breach_monitor_breach_false_positive(
    breach_monitor_uid: str,
    request: Request,
    _: None = Depends(require_admin),
) -> Dict[str, Any]:
    """Reopen a false-positive Breach Monitor breach record as active (admin)."""
    uid = breach_monitor_uid.strip()
    if not uid:
        raise HTTPException(status_code=422, detail="breach_monitor_uid is required")
    marked_by = (request.headers.get("X-User-Email") or "").strip() or "unknown"
    svc = _get_breach_monitor_db_service()
    ok = svc.unmark_false_positive(uid)
    if not ok:
        raise HTTPException(status_code=404, detail="Breach record not found")
    _audit_breach_monitor_action(
        request,
        action="BREACH_MONITOR_BREACH_FALSE_POSITIVE_REMOVE",
        resource_id=uid,
        details={"breach_monitor_uid": uid, "marked_by": marked_by},
    )
    return {"status": 200, "message": "Breach reopened as active", "breach_monitor_uid": uid}


class BulkFalsePositiveRequest(BaseModel):
    breach_monitor_uids: List[str]


@router.post("/breaches/bulk-mark-false-positive")
async def bulk_mark_breach_monitor_breaches_false_positive(
    body: BulkFalsePositiveRequest,
    request: Request,
    _: None = Depends(require_admin),
) -> Dict[str, Any]:
    """Mark multiple Breach Monitor breach records as false positives (admin)."""
    uids = [u.strip() for u in body.breach_monitor_uids if u and u.strip()]
    if not uids:
        raise HTTPException(status_code=422, detail="breach_monitor_uids must be a non-empty list")
    marked_by = (request.headers.get("X-User-Email") or "").strip() or "unknown"
    svc = _get_breach_monitor_db_service()
    updated = svc.bulk_mark_false_positive(uids, marked_by)
    _audit_breach_monitor_action(
        request,
        action="BREACH_MONITOR_BREACH_FALSE_POSITIVE",
        resource_id=f"bulk:{updated}",
        details={"breach_monitor_uids": uids, "marked_by": marked_by, "updated_count": updated, "bulk": True},
    )
    return {"status": 200, "message": f"{updated} breach(es) marked as false positive", "updated": updated}


@router.post("/breaches/bulk-unmark-false-positive")
async def bulk_unmark_breach_monitor_breaches_false_positive(
    body: BulkFalsePositiveRequest,
    request: Request,
    _: None = Depends(require_admin),
) -> Dict[str, Any]:
    """Reopen multiple false-positive Breach Monitor breach records as active (admin)."""
    uids = [u.strip() for u in body.breach_monitor_uids if u and u.strip()]
    if not uids:
        raise HTTPException(status_code=422, detail="breach_monitor_uids must be a non-empty list")
    marked_by = (request.headers.get("X-User-Email") or "").strip() or "unknown"
    svc = _get_breach_monitor_db_service()
    updated = svc.bulk_unmark_false_positive(uids)
    _audit_breach_monitor_action(
        request,
        action="BREACH_MONITOR_BREACH_FALSE_POSITIVE_REMOVE",
        resource_id=f"bulk:{updated}",
        details={"breach_monitor_uids": uids, "marked_by": marked_by, "updated_count": updated, "bulk": True},
    )
    return {"status": 200, "message": f"{updated} breach(es) reopened as active", "updated": updated}


@router.get("/config")
async def breach_monitor_config() -> Dict[str, Any]:
    """Non-secret configuration the dashboard needs: employee domains for the org filter."""
    from breach_monitor_export import EMPLOYEE_EMAIL_DOMAINS
    return {
        "status": 200,
        "employee_email_domains": list(EMPLOYEE_EMAIL_DOMAINS),
        "org_filters": ["all", *EMPLOYEE_EMAIL_DOMAINS],
    }


@router.get("/health")
async def breach_monitor_health() -> Dict[str, Any]:
    """
    Health check for Breach Monitor data availability
    
    Returns:
        Status information about available Breach Monitor data
    """
    try:
        primary_json = BREACH_MONITOR_DATA_DIR / "breach_records.json"
        root_json = PROJECT_ROOT / "breach_records.json"

        svc = _get_breach_monitor_db_service()
        total_breaches = svc.count_records()

        return {
            "status": 200,
            "healthy": total_breaches > 0,
            "storage": "database",
            "total_breaches_available": total_breaches,
            "data_directory": str(BREACH_MONITOR_DATA_DIR),
            "optional_json_files_present": {
                "data/breach_records.json": primary_json.exists(),
                "breach_records.json (repo root)": root_json.exists(),
            },
            "configured": {
                "breach_search_url": bool(os.getenv("BREACH_MONITOR_BREACH_SEARCH_URL")),
                "botnet_search_url": bool(os.getenv("BREACH_MONITOR_BOTNET_SEARCH_URL")),
                "credentials": bool(
                    os.getenv("BREACH_MONITOR_TOKEN")
                    and os.getenv("BREACH_MONITOR_APP_TOKEN")
                    and os.getenv("BREACH_MONITOR_USERNAME")
                ),
            },
        }

    except Exception as e:
        print(f"Error checking Breach Monitor health: {e}")
        return {
            "status": 503,
            "healthy": False,
            "error": str(e)
        }


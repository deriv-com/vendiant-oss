"""
Breach Monitor credential leak Excel export.

Applies the same filter semantics as the dashboard (BreachMonitorPanel.tsx) and
writes one row per leak with column labels matching the detail modal.
"""

from __future__ import annotations

import re
from datetime import date, datetime, timezone
from io import BytesIO
from typing import Any, Dict, List, Optional, Tuple

from openpyxl import Workbook
from openpyxl.styles import Font
from openpyxl.utils import get_column_letter

import os


def _employee_domains_from_env() -> Tuple[str, ...]:
    """Domains whose identities count as *employees* (EMPLOYEE_EMAIL_DOMAINS, comma-separated)."""
    raw = os.getenv("EMPLOYEE_EMAIL_DOMAINS", "")
    return tuple(sorted({d.strip().lower() for d in raw.split(",") if d.strip()}))


EMPLOYEE_EMAIL_DOMAINS: Tuple[str, ...] = _employee_domains_from_env()

LEAK_VIEWS = frozenset({"clients", "employees"})
# Organisation filter: "all" or any configured employee domain.
ORG_FILTERS = frozenset({"all", *EMPLOYEE_EMAIL_DOMAINS})
SLACK_IGNORE_FILTERS = frozenset({"all", "hide_ignored", "ignored_only"})
INTEL_TYPE_FILTERS = frozenset({"all", "botnet", "other"})
PASSWORD_FILTERS = frozenset({"all", "with_password", "without_password"})
RESOLVE_STATUS_FILTERS = frozenset({"all", "active", "resolved", "false_positive"})

BASE_COLUMNS: Tuple[str, ...] = (
    "Email",
    "Username",
    "Domain",
    "Exposure Date",
    "Password Exposed",
    "Validated",
    "Name",
    "Breach Type",
    "Source",
    "Confidence",
    "Record Type",
    "Ingested Date",
    "Description",
    "Recommendations",
    "Web Address",
    "Slack Ignored",
    "Status",
    "Resolved At",
    "Resolved By",
    "False Positive At",
    "False Positive By",
)

PASSWORD_COLUMN = "Password"


def _normalize_enum(value: Optional[str], allowed: frozenset, default: str) -> str:
    v = (value or "").strip().lower()
    return v if v in allowed else default


def breach_is_botnet(breach: Dict[str, Any]) -> bool:
    src = breach.get("source") or {}
    breach_type = str(src.get("breach_type") or "").lower()
    if breach_type == "botnet":
        return True
    source_type = str(src.get("type") or "").lower()
    if source_type == "botnet":
        return True
    record_type = str(breach.get("type") or "").lower()
    return "botnet" in record_type


def breach_is_employee_record(breach: Dict[str, Any]) -> bool:
    info = breach.get("information") or {}
    domain = str(info.get("domain") or "").lower().strip()
    if not domain:
        return False
    for employee_domain in EMPLOYEE_EMAIL_DOMAINS:
        if domain == employee_domain or domain.endswith(f".{employee_domain}"):
            return True
    return False


def breach_matches_leak_view(breach: Dict[str, Any], leak_view: str) -> bool:
    is_employee = breach_is_employee_record(breach)
    return is_employee if leak_view == "employees" else not is_employee


def breach_matches_org_filter(breach: Dict[str, Any], org_filter: str) -> bool:
    if org_filter == "all":
        return True
    info = breach.get("information") or {}
    email = str(info.get("email") or "").lower()
    domain = str(info.get("domain") or "").lower()
    username = str(info.get("username") or "").lower()
    org = org_filter.strip().lower()
    if org in EMPLOYEE_EMAIL_DOMAINS:
        return (
            domain == org
            or domain.endswith(f".{org}")
            or email.endswith(f"@{org}")
            or username.endswith(f"@{org}")
        )
    return True


def breach_matches_intel_type_filter(breach: Dict[str, Any], intel_type_filter: str) -> bool:
    if intel_type_filter == "all":
        return True
    is_botnet = breach_is_botnet(breach)
    if intel_type_filter == "botnet":
        return is_botnet
    return not is_botnet


def breach_indicates_password_exposure(breach: Dict[str, Any]) -> bool:
    info = breach.get("information") or {}
    pwd_raw = info.get("password")
    if pwd_raw is not None:
        try:
            if int(pwd_raw) != 0:
                return True
        except (TypeError, ValueError):
            if pwd_raw:
                return True
    if info.get("password_plain"):
        return True
    return False


def breach_matches_search(breach: Dict[str, Any], search_term: str) -> bool:
    term = search_term.strip().lower()
    if not term:
        return True
    info = breach.get("information") or {}
    src = breach.get("source") or {}
    haystacks = (
        info.get("email"),
        info.get("username"),
        info.get("web_address"),
        src.get("name"),
        src.get("description"),
    )
    return any(term in str(h or "").lower() for h in haystacks)


def ingestion_time_ms(breach: Dict[str, Any]) -> int:
    raw = str((breach.get("source") or {}).get("ingested_date") or "").strip()
    if not raw:
        return 0
    normalized = raw if "T" in raw else raw.replace(" ", "T")
    try:
        parsed = datetime.fromisoformat(normalized.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return int(parsed.timestamp() * 1000)
    except ValueError:
        return 0


def sort_breaches_by_ingestion_desc(breaches: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return sorted(breaches, key=ingestion_time_ms, reverse=True)


def filter_breach_monitor_breaches(
    breaches: List[Dict[str, Any]],
    *,
    leak_view: str = "employees",
    org_filter: str = "all",
    slack_ignore_filter: str = "all",
    intel_type_filter: str = "all",
    password_filter: str = "all",
    resolve_status_filter: str = "all",
    search: str = "",
) -> List[Dict[str, Any]]:
    """Mirror BreachMonitorPanel.tsx filteredBreaches pipeline."""
    leak_view = _normalize_enum(leak_view, LEAK_VIEWS, "employees")
    org_filter = _normalize_enum(org_filter, ORG_FILTERS, "all")
    slack_ignore_filter = _normalize_enum(slack_ignore_filter, SLACK_IGNORE_FILTERS, "all")
    intel_type_filter = _normalize_enum(intel_type_filter, INTEL_TYPE_FILTERS, "all")
    password_filter = _normalize_enum(password_filter, PASSWORD_FILTERS, "all")
    resolve_status_filter = _normalize_enum(resolve_status_filter, RESOLVE_STATUS_FILTERS, "all")
    search = (search or "")[:500]

    rows = [b for b in breaches if breach_matches_leak_view(b, leak_view)]
    rows = [b for b in rows if breach_matches_org_filter(b, org_filter)]

    if slack_ignore_filter == "hide_ignored":
        rows = [b for b in rows if not b.get("slack_notifications_suppressed")]
    elif slack_ignore_filter == "ignored_only":
        rows = [b for b in rows if b.get("slack_notifications_suppressed")]

    rows = [b for b in rows if breach_matches_intel_type_filter(b, intel_type_filter)]

    if password_filter != "all":
        want_password = password_filter == "with_password"
        rows = [
            b
            for b in rows
            if breach_indicates_password_exposure(b) == want_password
        ]

    if resolve_status_filter != "all":
        if resolve_status_filter == "false_positive":
            rows = [b for b in rows if (b.get("status") or "") == "false_positive"]
        elif resolve_status_filter == "resolved":
            rows = [b for b in rows if (b.get("status") or "") == "resolved"]
        else:
            rows = [b for b in rows if (b.get("status") or "active") == "active"]

    if search.strip():
        rows = [b for b in rows if breach_matches_search(b, search)]

    return sort_breaches_by_ingestion_desc(rows)


# Soft per-request safety cap. Large selections are fetched from the DB in
# EXPORT_UID_DB_BATCH_SIZE chunks and written to Excel in streaming mode.
MAX_EXPORT_UID_COUNT = 100_000
EXPORT_UID_DB_BATCH_SIZE = 500
_UID_RE = re.compile(r"^[a-zA-Z0-9_-]{1,128}$")


def normalize_breach_monitor_export_uids(uids: Optional[List[str]]) -> List[str]:
    """Validate and dedupe Breach Monitor UIDs for export selection."""
    if not uids:
        return []
    seen: set[str] = set()
    out: List[str] = []
    for raw in uids:
        uid = (raw or "").strip()
        if not uid or uid in seen or not _UID_RE.match(uid):
            continue
        seen.add(uid)
        out.append(uid)
        if len(out) > MAX_EXPORT_UID_COUNT:
            raise ValueError(f"Too many selected leaks (max {MAX_EXPORT_UID_COUNT})")
    return out


def filter_breach_monitor_breaches_by_uids(
    breaches: List[Dict[str, Any]],
    uids: List[str],
) -> List[Dict[str, Any]]:
    """Keep only breaches whose breach_monitor_uid is in uids, preserving selection order."""
    if not uids:
        return breaches
    by_uid = {
        str(b.get("breach_monitor_uid") or "").strip(): b
        for b in breaches
        if str(b.get("breach_monitor_uid") or "").strip()
    }
    ordered: List[Dict[str, Any]] = []
    seen: set[str] = set()
    for uid in uids:
        if uid in by_uid and uid not in seen:
            ordered.append(by_uid[uid])
            seen.add(uid)
    return ordered


def _format_date_cell(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, datetime):
        return value.strftime("%Y-%m-%d")
    s = str(value).strip()
    if not s:
        return ""
    return s.split("T")[0] if "T" in s else s[:10]


def _yes_no(value: Any) -> str:
    if value in (True, 1, "1", "yes", "Yes", "true", "True"):
        return "Yes"
    if value in (False, 0, "0", "no", "No", "false", "False", None, ""):
        return "No"
    try:
        return "Yes" if int(value) != 0 else "No"
    except (TypeError, ValueError):
        return "Yes" if value else "No"


def _status_label(breach: Dict[str, Any]) -> str:
    status = (breach.get("status") or "active").lower()
    if status == "resolved":
        return "Resolved"
    if status == "false_positive":
        return "False Positive"
    return "Active"


def breach_to_export_row(breach: Dict[str, Any], *, include_password: bool) -> Dict[str, str]:
    info = breach.get("information") or {}
    src = breach.get("source") or {}
    row: Dict[str, str] = {
        "Email": str(info.get("email") or ""),
        "Username": str(info.get("username") or ""),
        "Domain": str(info.get("domain") or ""),
        "Exposure Date": str(info.get("date") or "Unknown"),
        "Password Exposed": _yes_no(breach_indicates_password_exposure(breach)),
        "Validated": _yes_no(breach.get("validated")),
        "Name": str(src.get("name") or ""),
        "Breach Type": str(src.get("breach_type") or ""),
        "Source": str(src.get("source") or ""),
        "Confidence": str(src.get("confidence") or ""),
        "Record Type": str(breach.get("type") or ""),
        "Ingested Date": _format_date_cell(src.get("ingested_date")) or "Unknown",
        "Description": str(src.get("description") or ""),
        "Recommendations": str(src.get("recommendations") or ""),
        "Web Address": str(info.get("web_address") or ""),
        "Slack Ignored": _yes_no(breach.get("slack_notifications_suppressed")),
        "Status": _status_label(breach),
        "Resolved At": _format_date_cell(breach.get("resolved_at")),
        "Resolved By": str(breach.get("resolved_by") or ""),
        "False Positive At": _format_date_cell(breach.get("false_positive_at")),
        "False Positive By": str(breach.get("false_positive_by") or ""),
    }
    if include_password:
        plain = str(info.get("password_plain") or "").strip()
        if plain:
            row[PASSWORD_COLUMN] = plain
        elif breach_indicates_password_exposure(breach):
            row[PASSWORD_COLUMN] = "Not available for this record"
        else:
            row[PASSWORD_COLUMN] = ""
    return row


def export_columns(include_password: bool) -> Tuple[str, ...]:
    if not include_password:
        return BASE_COLUMNS
    cols = list(BASE_COLUMNS)
    insert_at = cols.index("Password Exposed") + 1
    cols.insert(insert_at, PASSWORD_COLUMN)
    return tuple(cols)


def build_breach_monitor_excel(
    breaches: List[Dict[str, Any]],
    *,
    include_password: bool,
    sheet_title: str = "Credential Leaks",
) -> bytes:
    columns = export_columns(include_password)
    title = sheet_title[:31]

    # write_only streams rows and keeps memory flat for large exports.
    if len(breaches) >= 1_000:
        wb = Workbook(write_only=True)
        ws = wb.create_sheet(title=title)
        ws.append(list(columns))
        for breach in breaches:
            row_data = breach_to_export_row(breach, include_password=include_password)
            ws.append([row_data.get(header, "") for header in columns])
        buf = BytesIO()
        wb.save(buf)
        return buf.getvalue()

    wb = Workbook()
    ws = wb.active
    ws.title = title

    header_font = Font(bold=True)
    for col_idx, header in enumerate(columns, start=1):
        cell = ws.cell(row=1, column=col_idx, value=header)
        cell.font = header_font

    for row_idx, breach in enumerate(breaches, start=2):
        row_data = breach_to_export_row(breach, include_password=include_password)
        for col_idx, header in enumerate(columns, start=1):
            ws.cell(row=row_idx, column=col_idx, value=row_data.get(header, ""))

    for col_idx, header in enumerate(columns, start=1):
        letter = get_column_letter(col_idx)
        max_len = len(header)
        for row_idx in range(2, min(len(breaches) + 2, 102)):
            val = ws.cell(row=row_idx, column=col_idx).value
            if val is not None:
                max_len = max(max_len, min(len(str(val)), 80))
        ws.column_dimensions[letter].width = min(max(max_len + 2, 12), 60)

    buf = BytesIO()
    wb.save(buf)
    return buf.getvalue()


def export_filename(leak_view: str, exported_at: Optional[datetime] = None) -> str:
    when = (exported_at or datetime.now(timezone.utc)).strftime("%Y%m%d")
    view = _normalize_enum(leak_view, LEAK_VIEWS, "employees")
    return f"breach-monitor-{view}-credential-leaks-{when}.xlsx"

"""
User directory for the Access Management picker.

Access Management lets an admin assign dashboard permissions to a person by
email. This module supplies the list of people to pick from. It is
intentionally generic; configure whichever source you have:

``USER_DIRECTORY_URL``
    HTTP endpoint returning JSON. Accepted shapes: a list of
    ``{"name": ..., "email": ...}`` objects, or an object with an
    ``employees``/``users``/``members``/``value``/``Resources`` list (SCIM
    ``/Users`` responses are handled: ``userName``/``emails[0].value`` and
    ``displayName``). ``USER_DIRECTORY_API_KEY`` is sent as a bearer token;
    set ``USER_DIRECTORY_API_KEY_HEADER`` to use a custom header name instead.

``USER_DIRECTORY_FILE``
    Local JSON (same shapes) or CSV (``name,email`` columns) file.

Fallback (always on)
    Everyone already known to the dashboard: existing Access Management rows
    plus anyone who has signed in (audit log). This keeps the picker usable
    with no directory at all; admins can also type any email directly.
"""

from __future__ import annotations

import csv
import json
import logging
import os
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

import requests

try:
    from Dashboard.db_config import DatabaseConnection
except ImportError:
    from db_config import DatabaseConnection

logger = logging.getLogger(__name__)

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def _extract_people(payload: Any) -> List[Dict[str, str]]:
    """Normalise a directory payload into [{name, email}]."""
    if isinstance(payload, dict):
        for key in ("employees", "users", "members", "value", "Resources", "data", "results"):
            if isinstance(payload.get(key), list):
                payload = payload[key]
                break
    if not isinstance(payload, list):
        return []
    out: List[Dict[str, str]] = []
    for item in payload:
        if not isinstance(item, dict):
            continue
        email = item.get("email") or item.get("mail") or item.get("userName") or ""
        if not email and isinstance(item.get("emails"), list) and item["emails"]:
            first = item["emails"][0]
            email = first.get("value") if isinstance(first, dict) else str(first)
        name = item.get("name") or item.get("displayName") or item.get("full_name") or ""
        if isinstance(name, dict):  # SCIM {"givenName": ..., "familyName": ...}
            name = " ".join(str(v) for v in (name.get("givenName"), name.get("familyName")) if v)
        out.append({"name": str(name or "").strip(), "email": str(email or "").strip()})
    return out


def _merge(*sources: Iterable[Dict[str, str]]) -> List[Dict[str, str]]:
    seen: set[str] = set()
    merged: List[Dict[str, str]] = []
    for source in sources:
        for person in source:
            email = (person.get("email") or "").strip().lower()
            if not email or not _EMAIL_RE.match(email) or email in seen:
                continue
            seen.add(email)
            merged.append({"name": (person.get("name") or "").strip() or email, "email": email})
    merged.sort(key=lambda p: (p["name"] or "").lower())
    return merged


def _from_url() -> List[Dict[str, str]]:
    url = (os.getenv("USER_DIRECTORY_URL") or "").strip()
    if not url:
        return []
    headers = {"Accept": "application/json", "User-Agent": "Vendiant/1.0"}
    api_key = (os.getenv("USER_DIRECTORY_API_KEY") or "").strip()
    if api_key:
        header_name = (os.getenv("USER_DIRECTORY_API_KEY_HEADER") or "Authorization").strip()
        headers[header_name] = f"Bearer {api_key}" if header_name.lower() == "authorization" else api_key
    try:
        resp = requests.get(url, headers=headers, timeout=60)
        resp.raise_for_status()
        return _extract_people(resp.json())
    except requests.RequestException as exc:
        raise RuntimeError(f"User directory unreachable: {exc}") from exc
    except ValueError as exc:
        raise RuntimeError("User directory returned invalid JSON") from exc


def _from_file() -> List[Dict[str, str]]:
    raw = (os.getenv("USER_DIRECTORY_FILE") or "").strip()
    if not raw:
        return []
    path = Path(raw)
    if not path.exists():
        raise RuntimeError(f"USER_DIRECTORY_FILE not found: {path}")
    if path.suffix.lower() == ".csv":
        with open(path, newline="", encoding="utf-8") as fh:
            return _extract_people(list(csv.DictReader(fh)))
    with open(path, encoding="utf-8") as fh:
        return _extract_people(json.load(fh))


def _from_database() -> List[Dict[str, str]]:
    """People already known to the dashboard (assignments + sign-ins)."""
    query = """
        SELECT user_email AS email, user_name AS name FROM dashboard_user_permissions
        UNION
        SELECT DISTINCT LOWER(TRIM(user_email)) AS email, MAX(user_name) AS name
        FROM audit_logs
        WHERE user_email IS NOT NULL AND TRIM(user_email) <> ''
        GROUP BY LOWER(TRIM(user_email))
    """
    try:
        with DatabaseConnection() as db:
            rows = db.execute_query(query) or []
        return [{"name": r.get("name") or "", "email": r.get("email") or ""} for r in rows]
    except Exception as exc:  # the directory must never take Access Management down
        logger.warning("user directory DB fallback failed: %s", exc)
        return []


def list_directory_users() -> List[Dict[str, str]]:
    """Return the merged, de-duplicated directory as [{name, email}]."""
    external: List[Dict[str, str]] = []
    errors: List[str] = []
    for loader in (_from_url, _from_file):
        try:
            external.extend(loader())
        except RuntimeError as exc:
            errors.append(str(exc))
            logger.error("%s", exc)
    people = _merge(external, _from_database())
    if not people and errors:
        raise RuntimeError("; ".join(errors))
    return people


# Backward-compatible names used by older routes
list_all_iam_employees = list_directory_users


def search_iam_employees(query: str = "", limit: int = 0) -> List[Dict[str, str]]:
    return list_directory_users()

"""Shared datetime helpers for API JSON responses."""

from datetime import datetime, timezone
from typing import Optional


def serialize_timestamp(value: Optional[datetime]) -> Optional[str]:
    """
    Serialize a datetime for JSON API responses as UTC ISO-8601.

    Naive datetimes are treated as UTC (legacy request_audit_log rows).
    """
    if value is None:
        return None

    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    else:
        value = value.astimezone(timezone.utc)

    return value.isoformat().replace("+00:00", "Z")

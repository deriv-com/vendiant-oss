"""
Persisted counter for remaining breach platform breach API search calls.
"""

from __future__ import annotations

import logging
import os
from typing import Optional

try:
    from Dashboard.db_config import DatabaseConnection
except ImportError:
    from db_config import DatabaseConnection

logger = logging.getLogger(__name__)

DEFAULT_INITIAL_QUOTA = 35999


class BreachMonitorQuotaService:
    """Single-row table ``breach_monitor_api_quota`` (id=1)."""

    _CREATE_SQL = """
    CREATE TABLE IF NOT EXISTS breach_monitor_api_quota (
        id SMALLINT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
        calls_remaining BIGINT NOT NULL,
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    """

    def _ensure_table(self) -> None:
        try:
            with DatabaseConnection() as db:
                db.execute_insert(self._CREATE_SQL)
        except Exception as e:
            logger.error("breach_monitor_api_quota ensure table: %s", e)

    def _initial_from_env(self) -> int:
        raw = os.getenv("BREACH_MONITOR_API_QUOTA_INITIAL", str(DEFAULT_INITIAL_QUOTA)).strip()
        try:
            n = int(raw)
            return max(0, min(n, 2_000_000_000))
        except (TypeError, ValueError):
            return DEFAULT_INITIAL_QUOTA

    def get_remaining(self) -> int:
        """Return current remaining call budget (creates row from env if missing)."""
        self._ensure_table()
        initial = self._initial_from_env()
        try:
            with DatabaseConnection() as db:
                row = db.execute_single_query(
                    "SELECT calls_remaining FROM breach_monitor_api_quota WHERE id = 1"
                )
                if row and row.get("calls_remaining") is not None:
                    return int(row["calls_remaining"])
                ins = db.execute_insert(
                    """
                    INSERT INTO breach_monitor_api_quota (id, calls_remaining)
                    VALUES (1, %s)
                    ON CONFLICT (id) DO NOTHING
                    """,
                    (initial,),
                )
                if ins:
                    return initial
                row2 = db.execute_single_query(
                    "SELECT calls_remaining FROM breach_monitor_api_quota WHERE id = 1"
                )
                if row2 and row2.get("calls_remaining") is not None:
                    return int(row2["calls_remaining"])
        except Exception as e:
            logger.error("BreachMonitorQuotaService.get_remaining: %s", e)
        return initial

    def consume_successful_calls(self, n: int = 1) -> int:
        """
        Decrement after one or more successful HTTP calls to the Breach Monitor search API.
        Returns the new remaining count (floored at 0).
        """
        if n <= 0:
            return self.get_remaining()
        self.get_remaining()
        self._ensure_table()
        try:
            with DatabaseConnection() as db:
                row = db.execute_returning(
                    """
                    UPDATE breach_monitor_api_quota
                    SET calls_remaining = GREATEST(0, calls_remaining - %s),
                        updated_at = NOW()
                    WHERE id = 1
                    RETURNING calls_remaining
                    """,
                    (n,),
                )
                if row and row.get("calls_remaining") is not None:
                    return int(row["calls_remaining"])
        except Exception as e:
            logger.error("BreachMonitorQuotaService.consume_successful_calls: %s", e)
        return self.get_remaining()

"""
Postgres-backed store for background scan job state.

Replaces the per-process ``background_jobs`` dict so job status is visible
across HPA-scaled backend replicas and the singleton scheduler pod.
"""

from __future__ import annotations

import json
import logging
import os
import secrets
import time
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional, Tuple

from psycopg2.extras import Json

try:
    from Dashboard.db_config import DatabaseConnection
except ImportError:
    from db_config import DatabaseConnection

logger = logging.getLogger(__name__)

MAX_LOG_LINES = 100
COMPLETED_RETENTION_DAYS = 7

# A job is considered orphaned when it still claims a non-terminal status but has
# not written a heartbeat within this window. Every progress/log/status write
# bumps ``updated_at``, so a live scan refreshes it continuously; a job whose
# owning pod was SIGKILLed (OOM, eviction, rollout) can never do so again and
# would otherwise stay "running" forever, blocking the scheduler indefinitely.
# Must exceed the longest legitimate gap between writes (subdomain enumeration
# on a large domain is the worst case). Override with SCAN_JOB_STALE_MINUTES.
STALE_JOB_MINUTES = int(os.getenv("SCAN_JOB_STALE_MINUTES", "60"))
NON_TERMINAL_STATUSES = ("starting", "running")
_SYNC_LIST_FIELDS = frozenset({"logs", "completed", "failed", "domains"})
_JSONB_LIST_COLUMNS = frozenset({"logs", "completed", "failed", "domains"})

_CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS background_scan_jobs (
    job_id VARCHAR(128) PRIMARY KEY,
    status VARCHAR(32) NOT NULL DEFAULT 'starting',
    progress INTEGER NOT NULL DEFAULT 0,
    current_domain TEXT,
    stage VARCHAR(64),
    domains JSONB NOT NULL DEFAULT '[]'::jsonb,
    total_domains INTEGER NOT NULL DEFAULT 0,
    completed JSONB NOT NULL DEFAULT '[]'::jsonb,
    failed JSONB NOT NULL DEFAULT '[]'::jsonb,
    logs JSONB NOT NULL DEFAULT '[]'::jsonb,
    include_subdomains BOOLEAN NOT NULL DEFAULT true,
    checkpoint_vendor TEXT,
    vendor_filters JSONB NOT NULL DEFAULT '{}'::jsonb,
    scan_type VARCHAR(32),
    slack_notify_on_complete BOOLEAN NOT NULL DEFAULT false,
    auto_scan BOOLEAN NOT NULL DEFAULT false,
    error TEXT,
    started_by_pod VARCHAR(128),
    start_time TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    end_time TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
"""

_CREATE_INDEXES_SQL = (
    "CREATE INDEX IF NOT EXISTS idx_background_scan_jobs_status "
    "ON background_scan_jobs (status);",
    "CREATE INDEX IF NOT EXISTS idx_background_scan_jobs_updated_at "
    "ON background_scan_jobs (updated_at DESC);",
)


def generate_job_id(scan_type: str) -> str:
    """Return a unique job id safe across pods (no in-memory counter)."""
    safe_type = (scan_type or "scan").strip().lower().replace(" ", "_")[:32]
    return f"{safe_type}_scan_{int(time.time())}_{secrets.token_hex(4)}"


def _pod_name() -> str:
    return os.getenv("HOSTNAME", "unknown")


def _parse_json_field(value: Any, default: Any) -> Any:
    if value is None:
        return default
    if isinstance(value, (list, dict)):
        return value
    if isinstance(value, str):
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return default
    return default


def _normalize_dt(value: Any) -> Any:
    """Strip tzinfo so DB timestamps match naive datetime.now() usage in app_new."""
    if value is None:
        return None
    if isinstance(value, datetime) and value.tzinfo is not None:
        return value.replace(tzinfo=None)
    return value


def _row_to_job(row: Dict[str, Any]) -> Dict[str, Any]:
    start_time = _normalize_dt(row.get("start_time"))
    end_time = _normalize_dt(row.get("end_time"))
    return {
        "job_id": row["job_id"],
        "status": row.get("status") or "starting",
        "progress": int(row.get("progress") or 0),
        "current_domain": row.get("current_domain"),
        "stage": row.get("stage"),
        "domains": _parse_json_field(row.get("domains"), []),
        "total_domains": int(row.get("total_domains") or 0),
        "completed": _parse_json_field(row.get("completed"), []),
        "failed": _parse_json_field(row.get("failed"), []),
        "logs": _parse_json_field(row.get("logs"), []),
        "include_subdomains": bool(row.get("include_subdomains", True)),
        "checkpoint_vendor": row.get("checkpoint_vendor"),
        "vendor_filters": _parse_json_field(row.get("vendor_filters"), {}),
        "scan_type": row.get("scan_type"),
        "slack_notify_on_complete": bool(row.get("slack_notify_on_complete", False)),
        "auto_scan": bool(row.get("auto_scan", False)),
        "error": row.get("error"),
        "start_time": start_time,
        "end_time": end_time,
    }


class SyncingList(list):
    """List proxy that persists append/replace operations to Postgres."""

    def __init__(self, store: "BackgroundJobsStore", job_id: str, field: str, items: List[Any]):
        super().__init__(items)
        self._store = store
        self._job_id = job_id
        self._field = field

    def append(self, item: Any) -> None:
        super().append(item)
        self._store._append_jsonb_items(self._job_id, self._field, [item])

    def extend(self, items: Iterable[Any]) -> None:
        batch = list(items)
        if not batch:
            return
        super().extend(batch)
        self._store._append_jsonb_items(self._job_id, self._field, batch)


class JobRecord:
    """Dict-like view of one job; writes sync to Postgres."""

    def __init__(self, store: "BackgroundJobsStore", job_id: str):
        self._store = store
        self._job_id = job_id

    def __getitem__(self, key: str) -> Any:
        if key == "status":
            status = self._store._fetch_status(self._job_id)
            if status is None:
                raise KeyError(self._job_id)
            return status
        job = self._store.get_job_dict(self._job_id)
        if job is None:
            raise KeyError(self._job_id)
        value = job.get(key)
        if key in _SYNC_LIST_FIELDS:
            return SyncingList(self._store, self._job_id, key, list(value or []))
        return value

    def __setitem__(self, key: str, value: Any) -> None:
        self._store._update_field(self._job_id, key, value)

    def get(self, key: str, default: Any = None) -> Any:
        job = self._store.get_job_dict(self._job_id)
        if job is None:
            return default
        if key == "status":
            return job.get("status", default)
        if key not in job:
            return default
        return job.get(key, default)


class BackgroundJobsStore:
    """Drop-in replacement for the in-memory ``background_jobs`` dict."""

    _table_ready = False

    def _ensure_table(self) -> None:
        if self._table_ready:
            return
        try:
            with DatabaseConnection() as db:
                db.execute_insert(_CREATE_TABLE_SQL)
                for stmt in _CREATE_INDEXES_SQL:
                    db.execute_insert(stmt)
            self._table_ready = True
        except Exception as exc:
            logger.error("background_scan_jobs ensure table failed: %s", exc)

    def _fetch_status(self, job_id: str) -> Optional[str]:
        self._ensure_table()
        try:
            with DatabaseConnection() as db:
                row = db.execute_single_query(
                    "SELECT status FROM background_scan_jobs WHERE job_id = %s",
                    (job_id,),
                )
                if not row:
                    return None
                return row.get("status")
        except Exception as exc:
            logger.error("fetch status for job %s failed: %s", job_id, exc)
            return None

    def get_job_dict(self, job_id: str) -> Optional[Dict[str, Any]]:
        self._ensure_table()
        try:
            with DatabaseConnection() as db:
                row = db.execute_single_query(
                    "SELECT * FROM background_scan_jobs WHERE job_id = %s",
                    (job_id,),
                )
                if not row:
                    return None
                return _row_to_job(row)
        except Exception as exc:
            logger.error("get job %s failed: %s", job_id, exc)
            return None

    def __contains__(self, job_id: object) -> bool:
        if not isinstance(job_id, str):
            return False
        return self.get_job_dict(job_id) is not None

    def __getitem__(self, job_id: str) -> JobRecord:
        if job_id not in self:
            raise KeyError(job_id)
        return JobRecord(self, job_id)

    def __setitem__(self, job_id: str, data: Dict[str, Any]) -> None:
        self._upsert_job(job_id, data)

    def get(self, job_id: str, default: Any = None) -> Any:
        job = self.get_job_dict(job_id)
        return job if job is not None else default

    def items(self) -> List[Tuple[str, Dict[str, Any]]]:
        self._ensure_table()
        try:
            with DatabaseConnection() as db:
                rows = db.execute_query(
                    """
                    SELECT * FROM background_scan_jobs
                    ORDER BY start_time DESC NULLS LAST
                    """
                )
                if not rows:
                    return []
                jobs = [_row_to_job(row) for row in rows]
                return [(job["job_id"], job) for job in jobs]
        except Exception as exc:
            logger.error("list background scan jobs failed: %s", exc)
            return []

    def values(self) -> List[Dict[str, Any]]:
        return [job for _, job in self.items()]

    def _serialize_value(self, key: str, value: Any) -> Any:
        if key in _SYNC_LIST_FIELDS:
            items = list(value or [])
            if key == "logs":
                return items[-MAX_LOG_LINES:]
            return items
        if key == "vendor_filters":
            return value or {}
        if key in ("start_time", "end_time") and isinstance(value, datetime):
            return value
        return value

    def _upsert_job(self, job_id: str, data: Dict[str, Any]) -> None:
        self._ensure_table()
        payload = dict(data)
        payload["job_id"] = job_id
        logs = payload.get("logs") or []
        if isinstance(logs, list):
            payload["logs"] = logs[-MAX_LOG_LINES:]

        start_time = payload.get("start_time") or datetime.now()
        end_time = payload.get("end_time")

        try:
            with DatabaseConnection() as db:
                db.execute_insert(
                    """
                    INSERT INTO background_scan_jobs (
                        job_id, status, progress, current_domain, stage,
                        domains, total_domains, completed, failed, logs,
                        include_subdomains, checkpoint_vendor, vendor_filters,
                        scan_type, slack_notify_on_complete, auto_scan, error,
                        started_by_pod, start_time, end_time, updated_at
                    ) VALUES (
                        %s, %s, %s, %s, %s,
                        %s, %s, %s, %s, %s,
                        %s, %s, %s,
                        %s, %s, %s, %s,
                        %s, %s, %s, NOW()
                    )
                    ON CONFLICT (job_id) DO UPDATE SET
                        status = EXCLUDED.status,
                        progress = EXCLUDED.progress,
                        current_domain = EXCLUDED.current_domain,
                        stage = EXCLUDED.stage,
                        domains = EXCLUDED.domains,
                        total_domains = EXCLUDED.total_domains,
                        completed = EXCLUDED.completed,
                        failed = EXCLUDED.failed,
                        logs = EXCLUDED.logs,
                        include_subdomains = EXCLUDED.include_subdomains,
                        checkpoint_vendor = EXCLUDED.checkpoint_vendor,
                        vendor_filters = EXCLUDED.vendor_filters,
                        scan_type = EXCLUDED.scan_type,
                        slack_notify_on_complete = EXCLUDED.slack_notify_on_complete,
                        auto_scan = EXCLUDED.auto_scan,
                        error = EXCLUDED.error,
                        end_time = EXCLUDED.end_time,
                        updated_at = NOW()
                    """,
                    (
                        job_id,
                        payload.get("status", "starting"),
                        int(payload.get("progress") or 0),
                        payload.get("current_domain"),
                        payload.get("stage"),
                        Json(payload.get("domains") or []),
                        int(payload.get("total_domains") or 0),
                        Json(payload.get("completed") or []),
                        Json(payload.get("failed") or []),
                        Json(payload.get("logs") or []),
                        bool(payload.get("include_subdomains", True)),
                        payload.get("checkpoint_vendor"),
                        Json(payload.get("vendor_filters") or {}),
                        payload.get("scan_type"),
                        bool(payload.get("slack_notify_on_complete", False)),
                        bool(payload.get("auto_scan", False)),
                        payload.get("error"),
                        payload.get("started_by_pod") or _pod_name(),
                        start_time,
                        end_time,
                    ),
                )
        except Exception as exc:
            logger.error("upsert background scan job %s failed: %s", job_id, exc)

    def _append_jsonb_items(self, job_id: str, field: str, items: List[Any]) -> None:
        """Atomically append to a JSONB array column (safe across pods)."""
        if field not in _JSONB_LIST_COLUMNS or not items:
            return
        self._ensure_table()

        try:
            with DatabaseConnection() as db:
                if field == "logs":
                    db.execute_insert(
                        """
                        UPDATE background_scan_jobs
                        SET logs = (
                            SELECT COALESCE(jsonb_agg(val ORDER BY n), '[]'::jsonb)
                            FROM (
                                SELECT val, n
                                FROM jsonb_array_elements(logs || %s::jsonb)
                                    WITH ORDINALITY AS t(val, n)
                                ORDER BY n DESC
                                LIMIT %s
                            ) last_n
                        ),
                        updated_at = NOW()
                        WHERE job_id = %s
                        """,
                        (Json(items), MAX_LOG_LINES, job_id),
                    )
                else:
                    db.execute_insert(
                        f"""
                        UPDATE background_scan_jobs
                        SET {field} = {field} || %s::jsonb,
                            updated_at = NOW()
                        WHERE job_id = %s
                        """,
                        (Json(items), job_id),
                    )
        except Exception as exc:
            logger.error(
                "atomic append to job %s field %s failed: %s", job_id, field, exc
            )

    def _update_field(self, job_id: str, key: str, value: Any) -> None:
        if key == "job_id":
            return
        self._ensure_table()
        value = self._serialize_value(key, value)

        column_map = {
            "status": "status",
            "progress": "progress",
            "current_domain": "current_domain",
            "stage": "stage",
            "domains": "domains",
            "total_domains": "total_domains",
            "completed": "completed",
            "failed": "failed",
            "logs": "logs",
            "include_subdomains": "include_subdomains",
            "checkpoint_vendor": "checkpoint_vendor",
            "vendor_filters": "vendor_filters",
            "scan_type": "scan_type",
            "slack_notify_on_complete": "slack_notify_on_complete",
            "auto_scan": "auto_scan",
            "error": "error",
            "start_time": "start_time",
            "end_time": "end_time",
        }
        column = column_map.get(key)
        if not column:
            logger.debug("Ignoring unknown background job field: %s", key)
            return

        db_value: Any = value
        if key in _SYNC_LIST_FIELDS or key == "vendor_filters":
            db_value = Json(value)
        elif key == "progress" or key == "total_domains":
            db_value = int(value or 0)
        elif key in ("include_subdomains", "slack_notify_on_complete", "auto_scan"):
            db_value = bool(value)

        try:
            with DatabaseConnection() as db:
                db.execute_insert(
                    f"""
                    UPDATE background_scan_jobs
                    SET {column} = %s, updated_at = NOW()
                    WHERE job_id = %s
                    """,
                    (db_value, job_id),
                )
        except Exception as exc:
            logger.error("update job %s field %s failed: %s", job_id, key, exc)

    def active_jobs(self, scan_types: Optional[Iterable[str]] = None) -> List[Dict[str, Any]]:
        """Return jobs currently claiming a non-terminal status.

        Filtering happens in SQL and, optionally, by ``scan_type``. Callers
        must NOT reimplement this by scanning ``values()``: that loads every
        job row ever written and, with no scan_type filter, lets an unrelated
        API-triggered scan block the auto scheduler.

        Note this reports what the table *claims*. Pair it with
        ``reap_stale_jobs`` so a dead job's claim cannot persist forever.
        """
        self._ensure_table()
        params: List[Any] = [list(NON_TERMINAL_STATUSES)]
        query = """
            SELECT job_id, status, scan_type, current_domain, started_by_pod,
                   start_time, updated_at
            FROM background_scan_jobs
            WHERE status = ANY(%s)
        """
        types = list(scan_types) if scan_types else None
        if types:
            query += " AND scan_type = ANY(%s)"
            params.append(types)
        query += " ORDER BY start_time DESC"
        try:
            with DatabaseConnection() as db:
                rows = db.execute_query(query, tuple(params))
                return [dict(row) for row in (rows or [])]
        except Exception as exc:
            logger.error("active background scan job lookup failed: %s", exc)
            # Fail closed: claiming "something is running" prevents a DB blip
            # from spawning a duplicate full-fleet scan.
            return [{"job_id": "<unknown>", "status": "running", "scan_type": None}]

    def reap_jobs_from_other_pods(self, scan_types: Iterable[str] = ("full",)) -> List[str]:
        """Reap non-terminal jobs owned by a pod that is not this one.

        Call at startup only, and only for scan types produced by a singleton
        deployment (the full-fleet scheduler must run as exactly one backend
        container). Under that invariant, a 'full' job attributed to any other
        container name cannot still be running: this process is the only one
        that starts them.

        This exists because time-based reaping alone recovers slowly from the
        most common failure -- a rollout. The replacement pod starts within
        seconds, so the orphan it inherits is only seconds stale and stays
        ineligible for the full staleness window, blocking scans that whole
        time. Pod identity settles it immediately.
        """
        self._ensure_table()
        me = _pod_name()
        if me == "unknown":
            # No reliable identity (HOSTNAME / POD_NAME unset); fall back to
            # time-based reaping only rather than risk killing a live job.
            logger.debug("Pod name unavailable; skipping cross-pod reap")
            return []
        try:
            with DatabaseConnection() as db:
                if not db.connection:
                    return []
                db.cursor.execute(
                    """
                    UPDATE background_scan_jobs
                    SET status = 'cancelled',
                        error = COALESCE(error, %s),
                        end_time = COALESCE(end_time, NOW()),
                        updated_at = NOW()
                    WHERE status = ANY(%s)
                      AND scan_type = ANY(%s)
                      AND started_by_pod IS DISTINCT FROM %s
                    RETURNING job_id, started_by_pod
                    """,
                    (
                        f"Reaped at startup: owning pod is gone (this pod is {me})",
                        list(NON_TERMINAL_STATUSES),
                        list(scan_types),
                        me,
                    ),
                )
                rows = db.cursor.fetchall() or []
                db.connection.commit()
                reaped = []
                for row in rows:
                    job_id = row["job_id"] if hasattr(row, "keys") else row[0]
                    pod = row["started_by_pod"] if hasattr(row, "keys") else row[1]
                    reaped.append(job_id)
                    logger.warning(
                        "Reaped scan job %s left behind by pod %s (this pod: %s)",
                        job_id, pod, me,
                    )
                return reaped
        except Exception as exc:
            logger.error("cross-pod reap failed: %s", exc)
            return []

    def reap_stale_jobs(self, stale_minutes: int = None) -> List[str]:
        """Mark orphaned jobs terminal so they stop blocking the scheduler.

        A job can only report its own completion. When its process dies
        abruptly no handler runs, so the row keeps claiming ``running``
        forever and ``has_active`` checks never clear. Nothing else in the
        system transitions that row, and ``purge_completed_jobs`` only deletes
        rows that are *already* terminal -- so an orphan is immortal without
        this.

        Liveness is inferred from ``updated_at`` rather than by asking the
        orchestrator whether the container exists: it needs no API access and
        also catches a live container whose scan thread crashed or hung, which
        a liveness check would miss.

        Reaped jobs are set to 'cancelled' rather than 'failed' on purpose --
        the scan threads already check for that exact status between steps
        (see run_full_scan_for_domain_background), so if a job is reaped while
        somehow still alive, its thread shuts itself down cleanly at the next
        checkpoint instead of racing a duplicate scan.

        Returns the job_ids that were reaped.
        """
        if stale_minutes is None:
            stale_minutes = STALE_JOB_MINUTES
        self._ensure_table()
        try:
            with DatabaseConnection() as db:
                if not db.connection:
                    return []
                # The CTE captures updated_at BEFORE the write, so the log can
                # report the real last heartbeat rather than the new timestamp.
                # SKIP LOCKED keeps concurrent reapers on other pods from
                # blocking each other or double-reporting the same rows.
                db.cursor.execute(
                    """
                    WITH stale AS (
                        SELECT job_id,
                               current_domain AS last_domain,
                               updated_at     AS last_heartbeat
                        FROM background_scan_jobs
                        WHERE status = ANY(%s)
                          AND updated_at < NOW() - (%s || ' minutes')::interval
                        FOR UPDATE SKIP LOCKED
                    )
                    UPDATE background_scan_jobs b
                    SET status = 'cancelled',
                        error = COALESCE(b.error, %s),
                        end_time = COALESCE(b.end_time, NOW()),
                        updated_at = NOW()
                    FROM stale
                    WHERE b.job_id = stale.job_id
                    RETURNING b.job_id, stale.last_domain, stale.last_heartbeat
                    """,
                    (
                        list(NON_TERMINAL_STATUSES),
                        str(stale_minutes),
                        f"Reaped: no heartbeat for over {stale_minutes} minutes; "
                        "owning process presumed dead",
                    ),
                )
                rows = db.cursor.fetchall() or []
                db.connection.commit()
                reaped = []
                for row in rows:
                    # DictCursor rows support both index and key access.
                    job_id = row["job_id"] if hasattr(row, "keys") else row[0]
                    domain = row["last_domain"] if hasattr(row, "keys") else row[1]
                    last_seen = row["last_heartbeat"] if hasattr(row, "keys") else row[2]
                    reaped.append(job_id)
                    logger.warning(
                        "Reaped orphaned scan job %s (last domain: %s, last heartbeat: %s) "
                        "- its process died without reporting a terminal status",
                        job_id,
                        domain,
                        last_seen,
                    )
                return reaped
        except Exception as exc:
            logger.error("reap stale background scan jobs failed: %s", exc)
            return []

    def purge_completed_jobs(self, retention_days: int = COMPLETED_RETENTION_DAYS) -> int:
        """Delete finished jobs older than retention_days. Returns rows removed."""
        self._ensure_table()
        try:
            with DatabaseConnection() as db:
                if not db.connection:
                    return 0
                db.cursor.execute(
                    """
                    DELETE FROM background_scan_jobs
                    WHERE status IN ('completed', 'failed', 'cancelled', 'skipped')
                      AND COALESCE(end_time, updated_at) < NOW() - (%s || ' days')::interval
                    """,
                    (str(retention_days),),
                )
                deleted = db.cursor.rowcount or 0
                db.connection.commit()
                if deleted:
                    logger.info("Purged %s completed background scan job(s)", deleted)
                return deleted
        except Exception as exc:
            logger.error("purge completed background scan jobs failed: %s", exc)
            return 0


background_jobs = BackgroundJobsStore()

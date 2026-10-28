"""Environment-driven toggles for automated background schedulers."""

import os


def background_schedulers_enabled() -> bool:
    """
    Master switch for automated background work (news scans, vendor full-scan
    loop, Slack cron analytics). Manual dashboard/API triggers are unaffected.
    Breach Monitor breach ingestion runs via inbound webhook, not a polling scan,
    so it is unaffected by this flag.

    Set ENABLE_BACKGROUND_SCHEDULERS=false on staging so scans run only when
    initiated from the dashboard.
    """
    raw = os.getenv("ENABLE_BACKGROUND_SCHEDULERS", "1").strip().lower()
    return raw in ("1", "true", "yes", "on")

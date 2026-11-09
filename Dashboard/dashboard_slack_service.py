"""
Slack notification helpers for the Dashboard app.

Call sites import this module by name when running from the Dashboard directory.
Implementation lives in slack/slack_service.py (on sys.path via the slack/ folder).
"""
import os
import sys

_slack_dir = os.path.join(os.path.dirname(__file__), "slack")
if _slack_dir not in sys.path:
    sys.path.insert(0, _slack_dir)

from slack_service import (  # noqa: E402
    send_api_audit_log_alert,
    send_api_key_alert,
    send_api_vendor_scan_completed_notification,
    send_audit_log_alert,
    send_breach_alert,
    send_breach_monitor_scheduled_sync_new_leaks_alert,
    send_critical_incident_alert,
    send_low_score_alert,
)

__all__ = [
    "send_api_audit_log_alert",
    "send_api_key_alert",
    "send_api_vendor_scan_completed_notification",
    "send_audit_log_alert",
    "send_breach_alert",
    "send_breach_monitor_scheduled_sync_new_leaks_alert",
    "send_critical_incident_alert",
    "send_low_score_alert",
]

import requests
import logging
from datetime import date, datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
import os
import json
from urllib.parse import urlencode
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Database connection no longer needed since we removed the critical_slack_alerts table

# Slack webhook URL
SLACK_WEBHOOK_URL = os.getenv('SLACK_WEBHOOK_URL')
# Optional dedicated webhook for “API new vendor scan finished” (defaults to SLACK_WEBHOOK_URL)
SLACK_API_VENDOR_SCAN_WEBHOOK_URL = (os.getenv('SLACK_API_VENDOR_SCAN_WEBHOOK_URL') or '').strip()

# SOC Slack user group (S…) or user (U…) — mentioned on employee credential leak Slack alerts
SLACK_SOC_CREDENTIAL_LEAK_MENTION_ID = (
    os.getenv("SLACK_SOC_CREDENTIAL_LEAK_MENTION_ID", "S063BG6SHV1") or ""
).strip()

# Client/customer credential leak alerts mention these users (comma-separated env override)
_DEFAULT_CLIENT_CREDENTIAL_LEAK_MENTION_IDS = (
    "U062BKX3DK2",
    "U04HP69J3MK",
    "U049Z4SHGTW",
)
SLACK_CLIENT_CREDENTIAL_LEAK_MENTION_IDS = [
    sid.strip()
    for sid in (
        os.getenv(
            "SLACK_CLIENT_CREDENTIAL_LEAK_MENTION_IDS",
            ",".join(_DEFAULT_CLIENT_CREDENTIAL_LEAK_MENTION_IDS),
        )
        or ""
    ).split(",")
    if sid.strip()
]

# Dashboard deep links in Slack (set DASHBOARD_FRONTEND_URL to your public URL)
DASHBOARD_FRONTEND_URL = (
    os.getenv("DASHBOARD_FRONTEND_URL")
    or os.getenv("FRONTEND_URL")
    or os.getenv("NEXT_PUBLIC_BASE_URL")
    or "http://localhost:8081"
).strip().rstrip("/")

# Configure console logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] [SLACK BOT] %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

def truncate_text(text: str, max_length: int = 2000) -> str:
    """
    Truncate text to Slack's character limits
    
    Args:
        text: Text to truncate
        max_length: Maximum allowed length
        
    Returns:
        Truncated text with ellipsis if needed
    """
    if not text:
        return ""
    
    text = str(text)
    if len(text) <= max_length:
        return text
    
    return text[:max_length - 3] + "..."


def sanitize_text(text: str) -> str:
    """
    Sanitize text for Slack - remove problematic characters
    
    Args:
        text: Text to sanitize
        
    Returns:
        Sanitized text
    """
    if not text:
        return ""
    
    # Convert to string and replace problematic characters
    text = str(text)
    # Remove null bytes and other control characters
    text = ''.join(char for char in text if ord(char) >= 32 or char in '\n\r\t')
    return text


def _slack_mention_markup(slack_entity_id: str) -> str:
    """
    Build Slack mrkdwn mention for a user group (S…) or user (U…).
    User groups: https://api.slack.com/reference/surfaces/formatting#mentioning-groups
    """
    sid = (slack_entity_id or "").strip()
    if not sid:
        return ""
    if sid.startswith("S"):
        return f"<!subteam^{sid}>"
    if sid.startswith("U") or sid.startswith("W"):
        return f"<@{sid}>"
    return ""


def _slack_mentions_markup(slack_entity_ids: List[str]) -> str:
    """Build Slack mrkdwn mentions for multiple user groups or users."""
    parts = [_slack_mention_markup(sid) for sid in slack_entity_ids]
    return " ".join(part for part in parts if part)


def send_slack_notification(
    blocks: List[Dict[str, Any]],
    text: str = "Dashboard Alert",
    color: str = None,
    alert_type: str = None,
    *,
    mention_slack_id: Optional[str] = None,
    mention_slack_ids: Optional[List[str]] = None,
    webhook_url: Optional[str] = None,
) -> bool:
    """
    Send a notification to Slack using blocks format and save to database
    
    Args:
        blocks: List of Slack block objects
        text: Fallback text for notifications
        color: Optional color for attachment (e.g., "#dc2626" for red)
        alert_type: Type of alert for database logging (e.g., 'critical_alert', 'vendor_analytics')
        mention_slack_id: Optional Slack user group (S…) or user (U…/W…) id to @-notify
        mention_slack_ids: Optional list of Slack ids to @-notify (takes precedence over mention_slack_id)
        webhook_url: Optional incoming webhook URL (defaults to SLACK_WEBHOOK_URL)
        
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        url = (webhook_url or "").strip() or SLACK_WEBHOOK_URL
        if not url:
            logger.warning("No Slack webhook URL configured — skipping notification")
            return False

        if mention_slack_ids:
            mention = _slack_mentions_markup(mention_slack_ids)
        else:
            mention = _slack_mention_markup(mention_slack_id or "")
        # Mention only in top-level `text` (line 1); preview/fallback on line 2 — no duplicate in blocks.
        notification_text = f"{mention}\n{text}" if mention else text

        if color:
            # Use attachment with color for red bar effect
            payload = {
                "text": notification_text,
                "attachments": [{
                    "color": color,
                    "blocks": blocks
                }]
            }
        else:
            payload = {
                "text": notification_text,
                "blocks": blocks
            }
        
        # Debug: Log the payload size
        payload_str = json.dumps(payload)
        logger.info(f"Sending payload with {len(blocks)} blocks, {len(payload_str)} chars")
        
        response = requests.post(
            url,
            json=payload,
            headers={'Content-Type': 'application/json'},
            timeout=30
        )
        
        if response.status_code == 200:
            logger.info(f"Successfully sent Slack notification: {text}")
            
            # Note: Alert sending status is now tracked in source tables with slack_alert_sent_at columns
            # No need for separate critical_slack_alerts tracking table
            
            return True
        else:
            logger.error(f"Failed to send Slack notification. Status: {response.status_code}, Response: {response.text}")
            # Log the payload for debugging
            logger.error(f"Failed payload (first 500 chars): {payload_str[:500]}")
            return False
            
    except Exception as e:
        logger.error(f"Error sending Slack notification: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return False


def send_api_vendor_scan_completed_notification(
    domain: str,
    vendor_name: str,
    job_id: str,
    scan_succeeded: bool,
    overall_score: Optional[Any] = None,
    risk_level: Optional[str] = None,
) -> bool:
    """
    Post to Slack when a background scan started via POST /vendiant/vendor finishes.
    Uses SLACK_API_VENDOR_SCAN_WEBHOOK_URL when set, otherwise SLACK_WEBHOOK_URL.
    """
    hook = SLACK_API_VENDOR_SCAN_WEBHOOK_URL or SLACK_WEBHOOK_URL
    if not hook:
        logger.warning("Slack webhook not configured — skipping API vendor scan completion notification")
        return False

    d = sanitize_text(domain)[:253]
    vn = sanitize_text(vendor_name)[:200]
    jid = sanitize_text(job_id)[:120]

    _OVERALL_MAX = 950

    if scan_succeeded:
        header = "New Vendor Scan Completed"
        color = "#2eb886"
    else:
        header = "New Vendor Scan Failed"
        color = "#dc2626"

    score_display = "—"
    if scan_succeeded and overall_score is not None:
        try:
            n = int(overall_score)
            score_display = f"{n}/{_OVERALL_MAX}"
        except (TypeError, ValueError):
            raw = sanitize_text(str(overall_score))[:32]
            score_display = f"{raw}/{_OVERALL_MAX}"

    risk_display = sanitize_text(str(risk_level or "unknown"))[:40]

    blocks: List[Dict[str, Any]] = [
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*{header}*\n*Vendor:* {vn}\n*Domain:* `{d}`\n*Overall score:* {score_display}\n*Risk:* {risk_display}\n*Job:* `{jid}`",
            },
        },
    ]

    return send_slack_notification(
        blocks=blocks,
        text=truncate_text(header, 400),
        color=color,
        webhook_url=hook,
    )


def format_critical_alerts_message(alerts_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Format critical alerts data into Slack blocks - matches exact format from dashboard
    
    Args:
        alerts_data: Dictionary containing critical alerts from the API
        
    Returns:
        List of Slack block objects
    """
    blocks = []
    blocks.append({"type": "divider"})
    
    # If there are alerts, show detailed cards for each (ALL types including low scores)
    alerts = alerts_data.get('critical_alerts', [])
    if alerts:
        logger.info(f"Formatting {len(alerts)} critical alerts for Slack")
        
        # Prioritize different alert types xxto ensure variety in top 10
        # Get breakdown of alert types
        low_score_alerts = [a for a in alerts if a.get('scan_type') == 'Overall Security Score']
        incident_alerts = [a for a in alerts if a.get('scan_type') == 'Security Incident']
        api_audit_alerts = [a for a in alerts if a.get('scan_type') == 'API Audit Log']
        audit_alerts = [a for a in alerts if a.get('scan_type') == 'Audit Log']
        failed_scan_alerts = [a for a in alerts if a.get('scan_type') == 'Failed Scan']
        credential_leak_alerts = [a for a in alerts if a.get('scan_type') == 'Credential Leak']
        vuln_alerts = [a for a in alerts if a.get('scan_type') not in ['Overall Security Score', 'Security Incident', 'Audit Log', 'API Audit Log', 'Failed Scan', 'Credential Leak']]
        
        logger.info(f"Alert breakdown: {len(low_score_alerts)} low scores, {len(incident_alerts)} incidents, {len(audit_alerts)} audit logs, {len(api_audit_alerts)} API audit logs, {len(failed_scan_alerts)} failed scans, {len(credential_leak_alerts)} credential leaks, {len(vuln_alerts)} vulnerabilities")
        
        # Build prioritized list: audit logs FIRST (vendor removals), then API audit logs, then credential leaks, then low scores, then incidents
        prioritized_alerts = []
        prioritized_alerts.extend(audit_alerts)       # ALL audit logs (vendor removals) - HIGHEST PRIORITY
        prioritized_alerts.extend(api_audit_alerts)   # ALL API audit logs
        prioritized_alerts.extend(credential_leak_alerts)  # ALL credential leaks
        prioritized_alerts.extend(low_score_alerts)   # ALL low security scores
        prioritized_alerts.extend(incident_alerts)    # ALL incidents
        prioritized_alerts.extend(failed_scan_alerts) # ALL failed scans
        
        # Add any remaining alerts that weren't categorized
        remaining = [a for a in alerts if a not in prioritized_alerts]
        prioritized_alerts.extend(remaining)
        
        logger.info(f"Sending ALL {len(prioritized_alerts)} alerts to Slack (no limit)")
        
        # Show ALL alerts (no limit) - each alert will be sent as separate message to avoid Slack block limits
        alerts_to_show = len(prioritized_alerts)
        
        for i, alert in enumerate(prioritized_alerts[:alerts_to_show], 1):
            vendor_name = sanitize_text(alert.get('vendor_name', 'Unknown'))
            domain = sanitize_text(alert.get('domain', 'Unknown'))
            subdomain = sanitize_text(alert.get('subdomain', domain))
            #vulnerability = sanitize_text(alert.get('vulnerability', 'Unknown Issue'))
            description = sanitize_text(alert.get('description', 'No description available'))
            scan_type = sanitize_text(alert.get('scan_type', 'Unknown'))
            
            # Truncate long fields
            #vulnerability = truncate_text(vulnerability, 200)
            description = truncate_text(description, 500)  # Shorter to fit in one section
            
            # Create clickable domain link
            domain_link = f"<https://{subdomain}|{subdomain}>" if subdomain and '.' in subdomain else subdomain
            
            # Header 
            header_text = f"Critical Security Alert - {vendor_name}"
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn", 
                    "text": f"*{truncate_text(header_text, 150)}*"
                }
            })
            
            # Format matching your image exactly - side by side fields
            # Row 1: Vendor and Domain (side by side)
            blocks.append({
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": f"*Vendor*\n{truncate_text(vendor_name, 150)}"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Domain*\n{truncate_text(domain_link, 150)}"
                    }
                ]
            })
            
            # Row 2: Issue Type and Severity (side by side)
            blocks.append({
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": f"*Issue Type*\n{truncate_text(scan_type, 150)}"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Severity*\nCRITICAL"
                    }
                ]
            })
            
            # Details section (full width)
            '''blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Details*\n{truncate_text(vulnerability, 500)}"
                }
            })'''
            
            # Description section (full width)
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Description*\n{truncate_text(description, 1000)}"
                }
            })

            # Source link for news/incident alerts (if available)
            source_url = alert.get('source_url') or alert.get('source')
            if source_url:
                blocks.append({
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*Source:* <{source_url}|View Article>"
                    }
                })
            
            # Footer with platform name and date (matching image format)
            current_date = get_formatted_date()
            blocks.append({
                "type": "context",
                "elements": [{
                    "type": "mrkdwn",
                    "text": f"Vendiant Security Platform  {current_date}"
                }]
            })
            
            blocks.append({"type": "divider"})
        
        if len(alerts) > alerts_to_show:
            blocks.append({
                "type": "context",
                "elements": [{
                    "type": "mrkdwn",
                    "text": f"⚠️ _Showing {alerts_to_show} highest priority alerts of {len(alerts)} total. {len(alerts) - alerts_to_show} more require attention._"
                }]
            })
    else:
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": "✅ *No critical alerts at this time.*\n\nAll systems are secure! 🎉"
            }
        })
    
    return blocks


def format_vendor_analytics_message(analytics_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Format vendor analytics data into Slack blocks - clean table-like format
    
    Args:
        analytics_data: Dictionary containing vendor performance data from the API
        
    Returns:
        List of Slack block objects
    """
    blocks = []
    
    # Header
    blocks.append({
        "type": "header",
        "text": {
            "type": "plain_text",
            "text": "📊 Daily Vendor Analytics Report",
            "emoji": True
        }
    })
    
    blocks.append({
        "type": "section",
        "text": {
            "type": "mrkdwn",
            "text": f"_Report generated: {datetime.now().strftime('%B %d, %Y at %I:%M %p')} UTC_"
        }
    })
    
    blocks.append({"type": "divider"})
    
    # Highest Rated Vendors - Table format like your image
    highest = analytics_data.get('highest', [])
    if highest:
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": "*🏆 Top 5 Highest Rated Vendors*"
            }
        })
        
        # Create wider ASCII-style table header for full vendor names
        table_text = "```\n"
        table_text += "┌────┬─────────────────────────────────────┬──────────────┬──────────────┐\n"
        table_text += "│ No │ Vendor                              │ Rating       │ Tier         │\n"
        table_text += "├────┼─────────────────────────────────────┼──────────────┼──────────────┤\n"
        
        # Add each vendor as a table row
        for i, vendor in enumerate(highest, 1):
            name = sanitize_text(vendor.get('name', 'Unknown'))
            score = vendor.get('score', 0)
            tier = sanitize_text(vendor.get('tier', 'Untiered'))
            grade = get_grade_from_score(score)
            
            # Wider columns - no truncation for vendor names
            name_padded = name[:35].ljust(35)  # Allow up to 35 characters for vendor names
            rating_text = f"{grade} {score}".ljust(12)
            tier_padded = tier[:12].ljust(12)  # Allow up to 12 characters for tier
            
            table_text += f"│ {i}  │ {name_padded} │ {rating_text} │ {tier_padded} │\n"
        
        table_text += "└────┴─────────────────────────────────────┴──────────────┴──────────────┘\n"
        table_text += "```"
        
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": table_text
            }
        })
    
    blocks.append({"type": "divider"})
    
    # Lowest Rated Vendors - Table format like your image
    lowest = analytics_data.get('lowest', [])
    if lowest:
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": "*🔴 Top 5 Lowest Rated Vendors*"
            }
        })
        
        # Create wider ASCII-style table header for full vendor names
        table_text = "```\n"
        table_text += "┌────┬─────────────────────────────────────┬──────────────┬──────────────┐\n"
        table_text += "│ No │ Vendor                              │ Rating       │ Tier         │\n"
        table_text += "├────┼─────────────────────────────────────┼──────────────┼──────────────┤\n"
        
        # Add each vendor as a table row
        for i, vendor in enumerate(lowest, 1):
            name = sanitize_text(vendor.get('name', 'Unknown'))
            score = vendor.get('score', 0)
            tier = sanitize_text(vendor.get('tier', 'Untiered'))
            grade = get_grade_from_score(score)
            
            # Wider columns - no truncation for vendor names
            name_padded = name[:35].ljust(35)  # Allow up to 35 characters for vendor names
            rating_text = f"{grade} {score}".ljust(12)
            tier_padded = tier[:12].ljust(12)  # Allow up to 12 characters for tier
            
            table_text += f"│ {i}  │ {name_padded} │ {rating_text} │ {tier_padded} │\n"
        
        table_text += "└────┴─────────────────────────────────────┴──────────────┴──────────────┘\n"
        table_text += "```"
        
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": table_text
            }
        })
    
    # Footer with context
    blocks.append({"type": "divider"})
    blocks.append({
        "type": "context",
        "elements": [{
            "type": "mrkdwn",
            "text": "💡 _Vendors are ranked by their overall security score (0-950). Monitor low-rated vendors for potential security risks._"
        }]
    })
    
    return blocks


def get_grade_from_score(score: int) -> str:
    """
    Convert a numeric score to a letter grade
    
    Args:
        score: Numeric score (0-950)
        
    Returns:
        Letter grade (A, B, C, D, or F)
    """
    if score >= 801:
        return "A"
    elif score >= 601:
        return "B"
    elif score >= 401:
        return "C"
    elif score >= 201:
        return "D"
    else:
        return "F"

def get_formatted_date() -> str:
    """
    Get current date formatted with ordinal suffix (e.g., "Sep 26th")
    
    Returns:
        Formatted date string
    """
    now = datetime.now()
    day = now.day
    
    # Add ordinal suffix
    if 10 <= day % 100 <= 20:
        suffix = 'th'
    else:
        suffix = {1: 'st', 2: 'nd', 3: 'rd'}.get(day % 10, 'th')
    
    return now.strftime(f'%b %d{suffix}')


def format_summary_message(alerts_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Format a summary header message for critical alerts
    
    Args:
        alerts_data: Dictionary containing critical alerts from the API
        
    Returns:
        List of Slack block objects for summary
    """
    blocks = []
    
    # Summary header
    total_count = alerts_data.get('total_count', 0)
    breakdown = alerts_data.get('breakdown', {})
    
    blocks.append({
        "type": "header",
        "text": {
            "type": "plain_text",
            "text": "🚨 Daily Critical Security Alerts Summary",
            "emoji": True
        }
    })
    
    summary_text = f"*Total Critical Alerts:* `{total_count}`\n\n"
    summary_text += f"*Breakdown:*\n"
    summary_text += f"• 🗑️ Vendors Removed: `{breakdown.get('vendors_removed', 0)}`\n"
    summary_text += f"• 🔑 API Audit Logs: `{breakdown.get('api_audit_logs', 0)}`\n"
    summary_text += f"• ⚠️  Low Security Scores: `{breakdown.get('low_scores', 0)}` (⚠️ *HIGH PRIORITY*)\n"
    summary_text += f"• 🚨 Critical Incidents: `{breakdown.get('critical_incidents', 0)}`\n"
    summary_text += f"• 🔓 Credential Leaks: `{breakdown.get('credential_leaks', 0)}`\n\n"
    summary_text += f"_Showing prioritized mix of top alerts below_\n"
    summary_text += f"_Report generated: {datetime.now().strftime('%B %d, %Y at %I:%M %p')} UTC_"
    
    blocks.append({
        "type": "section",
        "text": {
            "type": "mrkdwn",
            "text": summary_text
        }
    })
    
    blocks.append({"type": "divider"})
    
    return blocks


def format_single_alert_message(alert: Dict[str, Any], alert_number: int) -> List[Dict[str, Any]]:
    """
    Format a single critical alert into Slack blocks with red bar
    
    Args:
        alert: Dictionary containing single alert data
        alert_number: Number of this alert in the sequence
        
    Returns:
        List of Slack block objects for single alert
    """
    blocks = []
    scan_type = alert.get('scan_type', 'Unknown')
    
    # CREDENTIAL LEAKS - Custom Format
    # AUDIT LOGS - Custom Format
    if scan_type == 'Audit Log':
        alert_id = alert.get('id', 'Unknown')
        category = alert.get('category', 'API Audit')
        vendor_name = sanitize_text(alert.get('vendor', 'Unknown'))
        user_name = sanitize_text(alert.get('audit_user', 'Unknown'))  # Name is in vulnerability field
        role = alert.get('audit_role', 'Unknown') # Role is in description
        timestamp = alert.get('timestamp', 'Unknown') # Timestamp is in severity field
        blocks.append({
            "type": "section",
            "fields": [
                # {"type": "mrkdwn", "text": f"*ID*\n{alert_id}"},
                {"type": "mrkdwn", "text": f"*Vendor*\n{truncate_text(vendor_name, 150)}"}
            ]
        })
        blocks.append({
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Name*\n{truncate_text(user_name, 150)}"},
                {"type": "mrkdwn", "text": f"*Timestamp*\n{timestamp} UTC"}
            ]
        })
            
        
    
    # API AUDIT LOGS - Custom Format (from request_audit_log table)
    elif scan_type == 'API Audit Log':
        alert_id = alert.get('id', 'Unknown')
        key_name = sanitize_text(alert.get('key_name', 'Unknown'))  # Key name is in vendor_name
        method = sanitize_text(alert.get('method', 'unknown'))  # Method is in domain field
        ip = sanitize_text(alert.get('ip', 'N/A'))  # IP is in vulnerability field
        timestamp = alert.get('timestamp', 'Unknown') # Timestamp is in severity field
        
        # Parse description for vendor action details
        desc = alert.get('description', '')
        action = desc.split('Action: ')[1].split(' |')[0] if 'Action: ' in desc else 'API Action'
        vendor_domain = desc.split('/vendiant/domain/')[1].split(' ')[0].split('-')[0].strip() if '/vendiant/domain/' in desc else 'Unknown'        
        endpoint = alert.get('endpoint', 'Unknown')
        response = desc.split('Response: ')[1] if 'Response: ' in desc else '200'
        domain = alert.get('domain', 'Unknown')

        blocks.append({
            "type": "section",
            "fields": [
                # {"type": "mrkdwn", "text": f"*ID*\n{alert_id}"},
                {"type": "mrkdwn", "text": f"*API Key*\n{truncate_text(key_name, 150)}"}
            ]
        })
        blocks.append({
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Method*\n{method}"},
                {"type": "mrkdwn", "text": f"*Vendor*\n{truncate_text(domain, 150)}"}
            ]
        })
        blocks.append({
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Endpoint*\n{truncate_text(endpoint, 150)}"},
                {"type": "mrkdwn", "text": f"*IP Address*\n{ip}"}
            ]
        })
        blocks.append({
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Response Code*\n{response}"},
                {"type": "mrkdwn", "text": f"*Timestamp*\n{timestamp} UTC"}
            ]
        })
    
    # CREDENTIAL LEAKS - Custom Format
    elif scan_type == 'Credential Leak':
        email = sanitize_text(alert.get('email', 'Unknown'))
        username = sanitize_text(alert.get('username', ''))
        domain = sanitize_text(alert.get('domain', ''))
        source_name = sanitize_text(alert.get('source_name', ''))
        breach_type = sanitize_text(alert.get('breach_type', ''))
        confidence = sanitize_text(alert.get('confidence', ''))
        record_type = sanitize_text(alert.get('record_type', ''))
        source_channel = sanitize_text(alert.get('source_channel', ''))
        severity = sanitize_text(alert.get('severity', 'Unknown'))
        description = sanitize_text(alert.get('description', 'No description'))
        recommendations = sanitize_text(alert.get('recommendations', ''))
        timestamp = alert.get('timestamp', 'Unknown')
        ingested_date = sanitize_text(alert.get('ingested_date', ''))
        web_address = sanitize_text(alert.get('web_address', ''))
        raw_pwd = alert.get("password_leaked", 0)
        password_leaked_text = "Yes" if raw_pwd == 1 or str(raw_pwd).strip() in ("1", "True", "true") else "No"

        # Row 1: Email (full width - primary identifier)
        blocks.append({
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Email*\n{truncate_text(email, 250)}"}
            ]
        })

        # Row 2: Username | Domain (show both if available)
        row2_fields = []
        row2_fields.append({"type": "mrkdwn", "text": f"*Username*\n{truncate_text(username, 150) or '—'}"})
        row2_fields.append({"type": "mrkdwn", "text": f"*Domain*\n{truncate_text(domain, 150) or '—'}"})
        blocks.append({"type": "section", "fields": row2_fields})

        # Row 3: Source Name | Breach Type
        row3_fields = []
        row3_fields.append({"type": "mrkdwn", "text": f"*Source / Incident*\n{truncate_text(source_name, 150) or '—'}"})
        row3_fields.append({"type": "mrkdwn", "text": f"*Breach Type*\n{truncate_text(breach_type, 150) or '—'}"})
        blocks.append({"type": "section", "fields": row3_fields})

        # Row 4: Confidence | Source Channel
        row4_fields = []
        row4_fields.append({"type": "mrkdwn", "text": f"*Confidence*\n{truncate_text(confidence, 150) or '—'}"})
        row4_fields.append({"type": "mrkdwn", "text": f"*Source Channel*\n{truncate_text(source_channel, 150) or '—'}"})
        blocks.append({"type": "section", "fields": row4_fields})

        # Row 5: Exposure Date | Ingested Date
        row5_fields = [{"type": "mrkdwn", "text": f"*Exposure Date*\n{timestamp}"}]
        if ingested_date:
            row5_fields.append({"type": "mrkdwn", "text": f"*Ingested Date*\n{ingested_date}"})
        blocks.append({"type": "section", "fields": row5_fields})

        # Row 6: Password Leaked
        blocks.append({
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Password Leaked*\n{password_leaked_text}"}
            ]
        })

        # Description (full width)
        if description and description != 'No description':
            blocks.append({
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*Description*\n{truncate_text(description, 500)}"}
            })

        # Recommendations (full width, only if available)
        if recommendations:
            blocks.append({
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*Recommendations*\n{truncate_text(recommendations, 500)}"}
            })

        # Web Address (full width, only if available, as clickable link)
        if web_address:
            blocks.append({
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*Web Address*\n<{web_address}|{truncate_text(web_address, 200)}>"}
            })
    
    # DEFAULT FORMAT - For Low Scores, Security Incidents, and Vulnerabilities
    else:
        alert_id = alert.get('id', 'Unknown')
        vendor_name = sanitize_text(alert.get('vendor_name', 'Unknown'))
        domain = sanitize_text(alert.get('domain', 'Unknown'))
        subdomain = sanitize_text(alert.get('subdomain', domain))
        vulnerability = sanitize_text(alert.get('vulnerability', 'Unknown Issue'))
        description = sanitize_text(alert.get('description', 'No description available'))
        detected_at = alert.get('detected_at', alert.get('timestamp', ''))
        
        domain_link = f"<https://{subdomain}|{subdomain}>" if subdomain and '.' in subdomain else subdomain
        
        # Customize header and labels based on scan type
        if scan_type == 'Security Incident':
            header_text = f"🚨 Security Incident Detected - {vendor_name}"
            details_label = "Incident Title"
            row2_field2_label = "Detected At"
            row2_field2_value = detected_at if detected_at else 'Unknown'
        elif scan_type == 'Overall Security Score':
            header_text = f"⚠️ Low Security Score Alert - {vendor_name}"
            details_label = "Score Details"
            row2_field2_label = "Issue Type"
            row2_field2_value = truncate_text(scan_type, 150)
        else:
            header_text = f"🚨 Critical Security Alert - {vendor_name}"
            details_label = "Details"
            row2_field2_label = "Issue Type"
            row2_field2_value = truncate_text(scan_type, 150)
        
        blocks.append({
            "type": "section",
            "fields": [
                # {"type": "mrkdwn", "text": f"*ID*\n{alert_id}"},
                {"type": "mrkdwn", "text": f"*Vendor*\n{truncate_text(vendor_name, 150)}"}
            ]
        })
        blocks.append({
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Domain*\n{truncate_text(domain_link, 150)}"},
                {"type": "mrkdwn", "text": f"*{row2_field2_label}*\n{row2_field2_value}"}
            ]
        })
        blocks.append({
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Severity*\nCRITICAL"}
            ]
        })
        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"*{details_label}*\n{truncate_text(vulnerability, 500)}"}
        })
        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"*Description*\n{truncate_text(description, 1000)}"}
        })
        
        # Source link for news/incident alerts (if available)
        source_url = alert.get('source_url') or alert.get('source')
        if source_url:
            blocks.append({
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*Source:* <{source_url}|View Article>"}
            })
    
    # Footer for all types
    current_date = get_formatted_date()
    blocks.append({
        "type": "context",
        "elements": [{"type": "mrkdwn", "text": f"Vendiant Security Platform  {current_date}"}]
    })
    
    return blocks




def send_critical_alerts_notification(alerts_data: Dict[str, Any]) -> bool:
    """
    Send critical alerts to Slack - each alert as a separate message with its own red bar
    Only sends alerts that haven't been sent before (checks database)
    
    Args:
        alerts_data: Dictionary containing critical alerts from the API
        
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        alerts = alerts_data.get('critical_alerts', [])
        total_count = alerts_data.get('total_count', 0)
        
        if total_count == 0:
            logger.info("No alerts found at all - skipping Slack notification")
            # Don't send any message when there are no alerts
            return True
        
        # Alerts are already filtered upstream in fetch_critical_alerts()
        # No need to check for duplicates here

        if len(alerts) == 0:
            logger.info("No new alerts to send - skipping Slack notification")
            # Don't send any message when there are no alerts
            return True

        # Update alerts_data for summary
        alerts_data_filtered = alerts_data.copy()
        alerts_data_filtered['critical_alerts'] = alerts
        alerts_data_filtered['total_count'] = len(alerts)

        # Recalculate breakdown
        breakdown = {
            'vendors_removed': len([a for a in alerts if a.get('scan_type') == 'Audit Log']),
            'api_audit_logs': len([a for a in alerts if a.get('scan_type') == 'API Audit Log']),
            'low_scores': len([a for a in alerts if a.get('scan_type') == 'Overall Security Score']),
            'critical_incidents': len([a for a in alerts if a.get('scan_type') == 'Security Incident']),
            'credential_leaks': len([a for a in alerts if a.get('scan_type') == 'Credential Leak'])
        }
        alerts_data_filtered['breakdown'] = breakdown

        # Send summary header first
        summary_blocks = format_summary_message(alerts_data_filtered)
        send_slack_notification(summary_blocks, "Daily Critical Security Alerts Summary", alert_type="alerts_summary")

        # Prioritize alerts (same logic as format_critical_alerts_message)
        low_score_alerts = [a for a in alerts if a.get('scan_type') == 'Overall Security Score']
        incident_alerts = [a for a in alerts if a.get('scan_type') == 'Security Incident']
        api_audit_alerts = [a for a in alerts if a.get('scan_type') == 'API Audit Log']
        audit_alerts = [a for a in alerts if a.get('scan_type') == 'Audit Log']
        credential_leak_alerts = [a for a in alerts if a.get('scan_type') == 'Credential Leak']

        # Build prioritized list - audit logs FIRST (vendor removals), then API audit logs, then other alerts
        prioritized_alerts = []
        prioritized_alerts.extend(audit_alerts)       # ALL audit logs (vendor removals) - HIGHEST PRIORITY
        prioritized_alerts.extend(api_audit_alerts)   # ALL API audit logs
        prioritized_alerts.extend(credential_leak_alerts)  # ALL credential leaks
        prioritized_alerts.extend(low_score_alerts)   # ALL low security scores
        prioritized_alerts.extend(incident_alerts)    # ALL incidents

        # Add any remaining alerts that weren't categorized
        remaining = [a for a in alerts if a not in prioritized_alerts]
        prioritized_alerts.extend(remaining)

        # Send each alert as a separate message with its own red bar
        success_count = 0
        alerts_to_send = prioritized_alerts  # Send ALL alerts (no limit)
        
        logger.info(f"Sending ALL {len(alerts_to_send)} alerts")
        
        for i, alert in enumerate(alerts_to_send, 1):
            alert_blocks = format_single_alert_message(alert, i)
            alert_type = f"critical_alert_{alert.get('scan_type', 'unknown').lower().replace(' ', '_')}"
            # Generate preview text for Slack notifications
            vendor_name = alert.get('vendor_name', alert.get('vendor', 'Unknown Vendor'))
            scan_type = alert.get('scan_type', 'Alert')
            preview_text = f"🚨 {scan_type}: {vendor_name}"
            soc_mention = (
                SLACK_SOC_CREDENTIAL_LEAK_MENTION_ID
                if alert.get("scan_type") == "Credential Leak"
                else None
            )
            if send_slack_notification(
                alert_blocks,
                preview_text,
                color="#dc2626",
                alert_type=alert_type,
                mention_slack_id=soc_mention,
            ):
                success_count += 1
                # Mark this alert as sent in the database
                table_name = alert.get('table_name')
                record_id = alert.get('record_id')
                if table_name and record_id:
                    try:
                        # Import the function here to avoid circular imports
                        from .slack_scheduler import mark_alert_sent
                        mark_alert_sent(table_name, record_id)
                    except Exception as e:
                        logger.error(f"Failed to mark alert sent for {table_name}:{record_id}: {e}")
            else:
                logger.error(f"Failed to send alert for {alert.get('vendor_name', 'Unknown')}")
        
        logger.info(f"Successfully sent {success_count}/{len(alerts_to_send)} individual alerts")
        return success_count > 0
        
    except Exception as e:
        logger.error(f"Error sending critical alerts notification: {e}")
        return False


def send_vendor_analytics_notification(analytics_data: Dict[str, Any]) -> bool:
    """
    Send vendor analytics to Slack
    
    Args:
        analytics_data: Dictionary containing vendor performance data from the API
        
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        blocks = format_vendor_analytics_message(analytics_data)
        return send_slack_notification(blocks, "Daily Vendor Analytics Report", alert_type="vendor_analytics")
    except Exception as e:
        logger.error(f"Error sending vendor analytics notification: {e}")
        return False


# ===== EVENT-BASED NOTIFICATIONS =====

def send_critical_vulnerability_alert(vendor_name: str, domain: str, vulnerability_data: Dict[str, Any]) -> bool:
    """
    Send immediate Slack notification for critical vulnerability discovery

    Args:
        vendor_name: Name of the vendor
        domain: Domain affected
        vulnerability_data: Vulnerability details including title, description, severity, etc.

    Returns:
        bool: True if successful, False otherwise
    """
    try:
        subdomain = vulnerability_data.get('subdomain', domain)
        title = vulnerability_data.get('title', 'Unknown Vulnerability')
        description = vulnerability_data.get('description', 'No description available')
        severity = vulnerability_data.get('severity', 'Medium')
        category = vulnerability_data.get('category', 'Unknown')
        vuln_id = vulnerability_data.get('id')

        # Only send for critical severity
        if severity.upper() != 'CRITICAL':
            logger.debug(f"Skipping non-critical vulnerability alert: {title} (severity: {severity})")
            return True

        logger.info(f"Sending critical vulnerability alert for {vendor_name}: {title}")

        # Format the alert using existing single alert format
        alert = {
            'vendor_name': vendor_name,
            'domain': domain,
            'subdomain': subdomain,
            'vulnerability': title,
            'description': description,
            'scan_type': category,
            'severity': severity,
            'detected_at': vulnerability_data.get('detected_at', ''),
            'id': vuln_id
        }

        blocks = format_single_alert_message(alert, 1)
        preview_text = f"🚨 Critical Vulnerability: {vendor_name} - {title}"
        return send_slack_notification(blocks, preview_text, color="#dc2626", alert_type="critical_vulnerability")

    except Exception as e:
        logger.error(f"Error sending critical vulnerability alert: {e}")
        return False


def send_critical_incident_alert(vendor_name: str, domain: str, incident_data: Dict[str, Any]) -> bool:
    """
    Send immediate Slack notification for critical incident discovery

    Args:
        vendor_name: Name of the vendor
        domain: Domain affected
        incident_data: Incident details including title, description, severity, etc.

    Returns:
        bool: True if successful, False otherwise
    """
    try:
        from datetime import datetime, timedelta
        import logging

        title = incident_data.get('title', 'Unknown Incident')
        description = incident_data.get('description', 'No description available')
        severity = incident_data.get('severity', 'Medium')
        incident_id = incident_data.get('id')

        # Only send for critical severity
        if severity.upper() != 'CRITICAL':
            logger.debug(f"Skipping non-critical incident alert: {title} (severity: {severity})")
            return True

        # Check if event date is within the last 7 days
        event_date_str = incident_data.get('date', '')
        if event_date_str:
            try:
                # Parse the event date (format: YYYY-MM-DD)
                event_date = datetime.strptime(event_date_str, '%Y-%m-%d').date()
                today = datetime.now().date()
                seven_days_ago = today - timedelta(days=7)

                # Only send alert if event date is within the last 7 days
                if event_date < seven_days_ago:
                    logger.info(f"Skipping old incident alert: {title} (event date: {event_date_str}, more than 7 days old)")
                    return True

            except ValueError as date_error:
                logger.warning(f"Could not parse event date '{event_date_str}' for incident {title}: {date_error}")
                # Continue with alert if date parsing fails

        logger.info(f"Sending critical incident alert for {vendor_name}: {title}")

        # Format the alert using existing single alert format
        alert = {
            'vendor_name': vendor_name,
            'domain': domain,
            'subdomain': domain,
            'vulnerability': title,
            'description': description,
            'scan_type': 'Security Incident',
            'severity': severity,
            'detected_at': incident_data.get('date', incident_data.get('created_at', '')),
            'id': incident_id,
            'source': incident_data.get('source', incident_data.get('source_url')),
            'source_url': incident_data.get('source', incident_data.get('source_url'))
        }

        blocks = format_single_alert_message(alert, 1)
        preview_text = f"🚨 Security Incident: {vendor_name} - {title}"
        return send_slack_notification(blocks, preview_text, color="#dc2626", alert_type="critical_incident")

    except Exception as e:
        logger.error(f"Error sending critical incident alert: {e}")
        return False


def send_audit_log_alert(audit_data: Dict[str, Any]) -> bool:
    """
    Send immediate Slack notification for critical audit log events (vendor deletions)

    Args:
        audit_data: Audit log details including user info, action, etc.

    Returns:
        bool: True if successful, False otherwise
    """
    try:
        action = audit_data.get('action', 'Unknown')
        user_name = audit_data.get('user_name', 'Unknown')
        user_role = audit_data.get('user_role', 'User')
        details = audit_data.get('details', {})

        # Only send for DELETE actions (vendor removals)
        if action.upper() != 'DELETE':
            logger.debug(f"Skipping non-critical audit log: {action}")
            return True

        logger.info(f"Sending audit log alert for vendor removal by {user_name}")

        # Extract vendor info from details
        vendor_name = 'Unknown Vendor'
        domain = 'Unknown'
        if isinstance(details, dict):
            vendor_name = details.get('vendor_name', 'Unknown Vendor')
            domain = details.get('domain', 'Unknown')

        # Format the alert using existing single alert format for audit logs
        alert = {
            'id': audit_data.get('id', 'unknown'),
            'timestamp': str(audit_data.get('created_at', 'Unknown')),
            'vendor': vendor_name,
            'domain': domain,
            'scan_type': 'Audit Log',
            'category': 'Vendor Removal',
            'audit_action': action,
            'audit_role': user_role,
            'audit_user': user_name
        }

        blocks = format_single_alert_message(alert, 1)
        preview_text = f"🗑️ Vendor Deleted: {vendor_name} by {user_name}"
        return send_slack_notification(blocks, preview_text, color="#dc2626", alert_type="audit_log")

    except Exception as e:
        logger.error(f"Error sending audit log alert: {e}")
        return False


def send_api_audit_log_alert(api_audit_data: Dict[str, Any]) -> bool:
    """
    Send immediate Slack notification for API audit log events

    Args:
        api_audit_data: API audit log details including key_name, method, endpoint, etc.

    Returns:
        bool: True if successful, False otherwise
    """
    try:
        key_name = api_audit_data.get('key_name', 'Unknown')
        method = api_audit_data.get('http_method', 'Unknown')
        endpoint = api_audit_data.get('endpoint_path', 'Unknown')
        response_code = api_audit_data.get('response_code', 'Unknown')
        client_ip = api_audit_data.get('client_ip', 'N/A')

        logger.info(f"Sending API audit log alert for {method} {endpoint} by {key_name}")

        # Extract domain from request data if available
        request_data = api_audit_data.get('request_data', {})
        domain = None
        if isinstance(request_data, dict) and 'domain' in request_data:
            domain = request_data.get('domain')

        # Format the alert using existing single alert format for API audit logs
        alert = {
            'id': api_audit_data.get('id', 'unknown'),
            'key_name': key_name,
            'method': method,
            'endpoint': endpoint,
            'domain': domain,
            'ip': client_ip,
            'description': f"Action: {method} Request | Endpoint: {endpoint} | Response: {response_code}",
            'scan_type': 'API Audit Log',
            'timestamp': str(api_audit_data.get('timestamp', 'Unknown')),
            'category': 'API Audit'
        }

        blocks = format_single_alert_message(alert, 1)
        preview_text = f"🔑 API Audit Log: {key_name} - {method} {endpoint}"
        return send_slack_notification(blocks, preview_text, color="#dc2626", alert_type="api_audit_log")

    except Exception as e:
        logger.error(f"Error sending API audit log alert: {e}")
        return False


def send_breach_alert(breach_data: Dict[str, Any]) -> bool:
    """
    Send immediate Slack notification for credential breach detection

    Args:
        breach_data: Breach record details including email, severity, etc.

    Returns:
        bool: True if successful, False otherwise
    """
    try:
        email = breach_data.get('email', 'Unknown')
        severity = breach_data.get('severity', 'Unknown')
        description = breach_data.get('description', 'No description')
        password_leaked = breach_data.get('password_leaked', 0)
        breach_id = breach_data.get('id', 'unknown')

        logger.info(f"Sending breach alert for {email}")

        # Extract domain from email
        name = email.split('@')[1] if '@' in email else ''
        password_leaked_text = "Yes" if password_leaked == 1 else "No"

        # Format the alert using existing single alert format for credential leaks
        alert = {
            'id': breach_id,
            'email': email,
            'password_leaked': password_leaked,
            'name': name,
            'severity': severity,
            'vulnerability': "Credential Leak Detected",
            'description': description,
            'scan_type': 'Credential Leak',
            'detected_at': breach_data.get('created_at', ''),
            'category': 'Credential Leak'
        }

        blocks = format_single_alert_message(alert, 1)
        preview_text = f"🔓 Credential Leak Detected: {email}"
        return send_slack_notification(
            blocks,
            preview_text,
            color="#dc2626",
            alert_type="credential_leak",
            mention_slack_id=SLACK_SOC_CREDENTIAL_LEAK_MENTION_ID or None,
        )

    except Exception as e:
        logger.error(f"Error sending breach alert: {e}")
        return False


def _build_breach_monitor_client_leaks_dashboard_url(
    date_from: date,
    date_to: date,
) -> str:
    """Deep link to the Breach Monitor client-leaks view with an ingested-date range."""
    params = urlencode(
        {
            "section": "breach-monitor",
            "breach_monitor_view": "clients",
            "date_from": date_from.isoformat(),
            "date_to": date_to.isoformat(),
            "date_field": "ingested",
        }
    )
    return f"{DASHBOARD_FRONTEND_URL}/?{params}"


def _ingested_at_to_date(value: Any) -> Optional[date]:
    if value is None:
        return None
    if isinstance(value, datetime):
        dt = value
    elif isinstance(value, date):
        return value
    else:
        text = str(value).strip()
        if not text:
            return None
        try:
            dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError:
            return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).date()


def format_breach_monitor_client_leak_digest_message(
    alert_count: int,
    dashboard_url: str,
    *,
    date_from: Optional[date] = None,
    date_to: Optional[date] = None,
) -> Tuple[List[Dict[str, Any]], str]:
    """Slack blocks for the daily client credential leak count digest."""
    noun = "leak" if alert_count == 1 else "leaks"
    period_from = (date_from or datetime.now(timezone.utc).date()).isoformat()
    period_to = (date_to or date_from or datetime.now(timezone.utc).date()).isoformat()

    blocks: List[Dict[str, Any]] = [
        {
            "type": "section",
            "fields": [
                {
                    "type": "mrkdwn",
                    "text": "*Alert Type*\nClient Credential Leak — Daily Summary",
                }
            ],
        },
        {
            "type": "section",
            "fields": [
                {
                    "type": "mrkdwn",
                    "text": f"*New Leaks Since Last Notification*\n{alert_count} {noun}",
                },
                {"type": "mrkdwn", "text": "*Scan Type*\nCredential Leak"},
            ],
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Ingested From*\n{period_from}"},
                {"type": "mrkdwn", "text": f"*Ingested To*\n{period_to}"},
            ],
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": (
                    "*Description*\n"
                    f"{alert_count} new client credential {noun} "
                    "were detected since the last daily Slack notification. "
                    "Open the dashboard to review the affected records."
                ),
            },
        },
        {
            "type": "actions",
            "elements": [
                {
                    "type": "button",
                    "text": {
                        "type": "plain_text",
                        "text": "View client leaks in dashboard",
                        "emoji": True,
                    },
                    "style": "primary",
                    "url": dashboard_url,
                }
            ],
        },
        {
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": f"Vendiant Security Platform  {get_formatted_date()}",
                }
            ],
        },
    ]
    preview = (
        f"🔓 Client Credential Leak Detected: "
        f"{alert_count} new {noun} since last notification"
    )
    return blocks, preview


def send_breach_monitor_daily_client_leak_digest() -> bool:
    """
    Once-daily digest for client credential leaks stored in Breach Monitor.

    Counts active client leaks not yet reported via Slack, @-mentions the configured
    client owners with the count only, and links to the dashboard client-leaks view
    filtered to the ingested-date range of those alerts. Suppressed ignore-list rows
    are marked processed without contributing to the count or triggering a message.
    """
    if not SLACK_WEBHOOK_URL:
        logger.info("SLACK_WEBHOOK_URL not set; skipping client leak daily digest")
        return False

    try:
        from db_service import BreachMonitorRecordsService, BreachMonitorIgnoreListService
    except ImportError:
        from Dashboard.db_service import BreachMonitorRecordsService, BreachMonitorIgnoreListService

    svc = BreachMonitorRecordsService()
    pending = svc.fetch_pending_client_leak_slack_rows()
    if not pending:
        logger.info("Client leak daily digest: no pending client leaks")
        return True

    ignore_svc: Optional[Any]
    try:
        ignore_svc = BreachMonitorIgnoreListService()
    except Exception as exc:
        logger.warning("Could not load BreachMonitorIgnoreListService; digest ignore filtering skipped: %s", exc)
        ignore_svc = None

    notify_rows: List[Dict[str, Any]] = []
    suppressed_uids: List[str] = []
    for row in pending:
        uid = str(row.get("breach_monitor_uid") or "").strip()
        if not uid:
            continue
        email = str(row.get("email") or "")
        incident = str(row.get("incident_name") or "")
        password = str(row.get("password_plain") or "")
        if ignore_svc is not None and email:
            try:
                if ignore_svc.should_suppress(email, incident, password):
                    suppressed_uids.append(uid)
                    continue
            except Exception as exc:
                logger.warning("Ignore-list check failed for client leak digest row; including in count: %s", exc)
        notify_rows.append(row)

    all_uids = [str(row.get("breach_monitor_uid") or "").strip() for row in pending if row.get("breach_monitor_uid")]

    if not notify_rows:
        if suppressed_uids:
            svc.mark_client_leak_slack_alerts_sent(all_uids)
            logger.info(
                "Client leak daily digest: %s pending row(s) suppressed by ignore list; no Slack message",
                len(suppressed_uids),
            )
        return True

    ingested_dates = [
        d for d in (_ingested_at_to_date(row.get("ingested_at")) for row in notify_rows) if d is not None
    ]
    today = datetime.now(timezone.utc).date()
    date_from = min(ingested_dates) if ingested_dates else today
    date_to = max(ingested_dates) if ingested_dates else today
    dashboard_url = _build_breach_monitor_client_leaks_dashboard_url(date_from, date_to)
    blocks, preview = format_breach_monitor_client_leak_digest_message(
        len(notify_rows),
        dashboard_url,
        date_from=date_from,
        date_to=date_to,
    )

    if not send_slack_notification(
        blocks,
        preview,
        color="#dc2626",
        alert_type="credential_leak_client_digest",
        mention_slack_ids=SLACK_CLIENT_CREDENTIAL_LEAK_MENTION_IDS or None,
    ):
        logger.error("Client leak daily digest: Slack notification failed")
        return False

    if not svc.mark_client_leak_slack_alerts_sent(all_uids):
        logger.error("Client leak daily digest: failed to mark rows as sent after Slack post")
        return False

    logger.info(
        "Client leak daily digest sent: %s new leak(s), %s suppressed, dashboard=%s",
        len(notify_rows),
        len(suppressed_uids),
        dashboard_url,
    )
    return True


def send_breach_monitor_scheduled_sync_new_leaks_alert(
    new_count: int,
    leak_alerts: List[Dict[str, Any]],
) -> bool:
    """
    Slack notifications for new Breach Monitor leaks from webhook ingest or manual refresh.

    Employee leaks are sent immediately (one message per leak). Client/customer leaks
    are deferred to :func:`send_breach_monitor_daily_client_leak_digest` so Slack only gets a
    once-daily count since the last digest post.

    ``leak_alerts`` items are dicts from
    ``BreachMonitorRecordsService.breach_monitor_api_result_to_credential_leak_alert``.

    Alerts are filtered against ``breach_monitor_ignore_list`` before sending:
    - If the email has an entry with empty incident_names → all alerts for that email are suppressed.
    - If the email has an entry with specific incident_names → only those incidents are suppressed.
    """
    if new_count <= 0:
        return True
    if not leak_alerts:
        logger.warning(
            "Breach Monitor sync reported %s new leak(s) but no alert payloads; skipping Slack",
            new_count,
        )
        return False
    if not SLACK_WEBHOOK_URL:
        logger.info("SLACK_WEBHOOK_URL not set; skipping Breach Monitor new-leak Slack notification")
        return False

    employee_alerts = [
        alert
        for alert in leak_alerts
        if str(alert.get("leak_category") or "").strip().lower() == "employee"
    ]
    client_count = len(leak_alerts) - len(employee_alerts)
    if client_count:
        logger.info(
            "Breach Monitor sync: %s new client leak(s) stored for daily Slack digest (not sent immediately)",
            client_count,
        )
    if not employee_alerts:
        return True

    try:
        from db_service import BreachMonitorIgnoreListService
        ignore_svc: Optional[Any] = BreachMonitorIgnoreListService()
    except Exception as _e:
        logger.warning("Could not load BreachMonitorIgnoreListService; ignore-list filtering skipped: %s", _e)
        ignore_svc = None

    ok_any = False
    suppressed = 0
    try:
        for alert in employee_alerts:
            raw_email: str = str(alert.get("email") or "")
            incident: str = str(alert.get("source_name") or alert.get("incident_name") or "")
            password: str = str(alert.get("password_plain") or "")

            if ignore_svc is not None and raw_email:
                try:
                    if ignore_svc.should_suppress(raw_email, incident, password):
                        suppressed += 1
                        logger.info(
                            "Breach Monitor Slack alert suppressed by ignore list: email_domain=%s incident=%s",
                            raw_email.split("@")[-1] if "@" in raw_email else "unknown",
                            incident or "(all)",
                        )
                        continue
                except Exception as _se:
                    logger.warning("Ignore-list check failed for alert; sending anyway: %s", _se)

            blocks = format_single_alert_message(alert, 1)
            email = sanitize_text(raw_email or "Unknown")
            preview_text = f"🔓 Employee Credential Leak Detected: {email}"
            alert_color = "#7f1d1d"
            mention_slack_id = SLACK_SOC_CREDENTIAL_LEAK_MENTION_ID or None
            mention_slack_ids = None
            if send_slack_notification(
                blocks,
                preview_text,
                color=alert_color,
                alert_type="credential_leak",
                mention_slack_id=mention_slack_id,
                mention_slack_ids=mention_slack_ids,
            ):
                ok_any = True

        if suppressed:
            logger.info(
                "Breach Monitor Slack sync: %s employee alert(s) suppressed by ignore list out of %s employee leak(s)",
                suppressed,
                len(employee_alerts),
            )
        return ok_any
    except Exception as e:
        logger.error(f"Error sending Breach Monitor scheduled-sync Slack alert: {e}")
        return False


def send_low_score_alert(vendor_name: str, domain: str, score_data: Dict[str, Any]) -> bool:
    """
    Send immediate Slack notification for low security score alerts

    Args:
        vendor_name: Name of the vendor
        domain: Domain affected
        score_data: Score details including current score, threshold, etc.

    Returns:
        bool: True if successful, False otherwise
    """
    try:
        current_score = score_data.get('current_score', 0)
        threshold = score_data.get('threshold', 750)

        # Only send if score is below threshold
        if current_score >= threshold:
            logger.debug(f"Skipping low score alert: {current_score} >= {threshold}")
            return True

        logger.info(f"Sending low score alert for {vendor_name}: {current_score}/950")

        # Format the alert using existing single alert format
        alert = {
            'vendor_name': vendor_name,
            'domain': domain,
            'subdomain': domain,
            'vulnerability': f'Low Security Score ({current_score}/950)',
            'description': f'Domain has an overall security score of {current_score}/950, which is below the critical threshold of {threshold}.',
            'scan_type': 'Overall Security Score',
            'severity': 'CRITICAL',
            'detected_at': '',
            'category': 'Security Score'
        }

        blocks = format_single_alert_message(alert, 1)
        preview_text = f"⚠️ Low Security Score: {vendor_name} ({current_score}/950)"
        return send_slack_notification(blocks, preview_text, color="#dc2626", alert_type="low_score_alert")

    except Exception as e:
        logger.error(f"Error sending low score alert: {e}")
        return False


def send_api_key_alert(action: str, api_key_name: str, user_email: str, timestamp: str) -> bool:
    """
    Send immediate Slack notification for API key actions (CREATE, DELETE, ACTIVATED, REVOKED)

    Args:
        action: The action performed (CREATE, DELETE, ACTIVATED, REVOKED)
        api_key_name: Name of the API key
        user_email: Email of the user who performed the action
        timestamp: When the action occurred

    Returns:
        bool: True if successful, False otherwise
    """
    try:
        logger.info(f"Sending API key alert: {action} - {api_key_name} by {user_email}")

        # Create a custom format for API key notifications
        blocks = []

        # Header with action - map CREATE/DELETE to CREATED/DELETED
        action_emoji = {
            'CREATE': '➕',
            'DELETE': '🗑️',
            'ACTIVATED': '✅',
            'REVOKED': '🚫'
        }.get(action.upper(), '🔑')

        # Map action display text
        action_display = {
            'CREATE': 'Created',
            'DELETE': 'Deleted',
            'ACTIVATED': 'Activated',
            'REVOKED': 'Revoked'
        }.get(action.upper(), action.title())

        blocks.append({
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"{action_emoji} API Key {action_display}"
            }
        })

        # Details section
        blocks.append({
            "type": "section",
            "fields": [
                {
                    "type": "mrkdwn",
                    "text": f"*API Key Name*\n{api_key_name}"
                },
                {
                    "type": "mrkdwn",
                    "text": f"*Action*\n{action_display}"
                }
            ]
        })

        blocks.append({
            "type": "section",
            "fields": [
                {
                    "type": "mrkdwn",
                    "text": f"*Performed By*\n{user_email}"
                },
                {
                    "type": "mrkdwn",
                    "text": f"*Timestamp*\n{timestamp} UTC"
                }
            ]
        })

        # Footer
        blocks.append({
            "type": "context",
            "elements": [{
                "type": "mrkdwn",
                "text": "Vendiant Security Platform - API Key Management"
            }]
        })

        preview_text = f"{action_emoji} API Key {action_display}: {api_key_name}"
        return send_slack_notification(blocks, preview_text, color="#3b82f6", alert_type=f"api_key_{action.lower()}")

    except Exception as e:
        logger.error(f"Error sending API key alert: {e}")
        return False

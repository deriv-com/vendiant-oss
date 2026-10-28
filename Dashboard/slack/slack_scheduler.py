import logging
import requests
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from datetime import datetime
from zoneinfo import ZoneInfo
import atexit

# Import moved to function to avoid circular import

# Use existing logging configuration (don't reconfigure to avoid conflicts)
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Add console handler if not already present
if not logger.handlers:
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(
        logging.Formatter('[%(asctime)s] [SLACK BOT] %(levelname)s - %(message)s', 
                         datefmt='%Y-%m-%d %H:%M:%S')
    )
    logger.addHandler(console_handler)

# Scheduler instance
scheduler = None

# Client leak digest runs at 11:00 Asia/Dubai (UTC+4, no DST).
DUBAI_TZ = ZoneInfo("Asia/Dubai")


def check_alert_sent_recently(table_name: str, record_id: int, hours: int = 24) -> bool:
    """
    Check if an alert for this record was sent to Slack recently

    Args:
        table_name: Name of the table (vulnerabilities, news, audit_logs, etc.)
        record_id: ID of the record
        hours: Hours to look back

    Returns:
        bool: True if alert was sent recently, False otherwise
    """
    try:
        try:
            from Dashboard.db_config import DatabaseConnection
        except ImportError:
            from db_config import DatabaseConnection

        with DatabaseConnection() as db:
            if table_name == 'vendors':
                # For vendors, check low_score_alert_sent_at
                query = """
                SELECT low_score_alert_sent_at
                FROM vendors
                WHERE id = %s AND low_score_alert_sent_at >= NOW() - INTERVAL '%s hours'
                """
            else:
                # For other tables, check slack_alert_sent_at
                query = f"""
                SELECT slack_alert_sent_at
                FROM {table_name}
                WHERE id = %s AND slack_alert_sent_at >= NOW() - INTERVAL '%s hours'
                """

            result = db.execute_query(query, (record_id, hours))
            return len(result) > 0

    except Exception as e:
        logger.error(f"Error checking if alert sent recently for {table_name}:{record_id}: {e}")
        return False


def mark_alert_sent(table_name: str, record_id: int):
    """
    Mark that an alert was sent for this record

    Args:
        table_name: Name of the table
        record_id: ID of the record
    """
    try:
        try:
            from Dashboard.db_config import DatabaseConnection
        except ImportError:
            from db_config import DatabaseConnection

        with DatabaseConnection() as db:
            if table_name == 'vendors':
                # For vendors, update low_score_alert_sent_at
                query = """
                UPDATE vendors
                SET low_score_alert_sent_at = NOW()
                WHERE id = %s
                """
            else:
                # For other tables, update slack_alert_sent_at
                query = f"""
                UPDATE {table_name}
                SET slack_alert_sent_at = NOW()
                WHERE id = %s
                """

            db.execute_insert(query, (record_id,))

    except Exception as e:
        logger.error(f"Error marking alert sent for {table_name}:{record_id}: {e}")


def fetch_critical_alerts():
    """
    Fetch critical alerts using direct database queries and send to Slack
    EXCLUDES: Encryption and Network related alerts
    """
    try:
        print("\n[SLACK BOT] Fetching critical alerts using direct database queries...")
        logger.info("Fetching critical alerts for Slack notification...")
        
        # Import required services
        from db_service import (
            get_vendor_by_domain,
            get_vulnerabilities_for_domain,
            VendorService
        )
        from audit_service import audit_service
        try:
            from Dashboard.db_config import DatabaseConnection
        except ImportError:
            from db_config import DatabaseConnection
        
        critical_alerts = []
        vendor_service = VendorService()
        
        # Get all vendors
        vendors = vendor_service.get_all_vendors()
        print(f"[SLACK BOT] Processing {len(vendors)} vendors")
        logger.info(f"Processing {len(vendors)} vendors for critical alerts")
        
        for vendor in vendors:
            domain = vendor.get('domain', '')
            vendor_name = vendor.get('name', 'Unknown Vendor')
            vendor_id = vendor.get('id')
            
            if not domain:
                continue
            
            # Check overall domain score
            vendor_data = get_vendor_by_domain(domain)
            overall_score = None
            if vendor_data:
                overall_score = vendor_data.get('securityScore') or vendor_data.get('scores', {}).get('current')
            
            # Add low-scoring domains as critical alerts
            if overall_score is not None and overall_score < 750:
                # Check if we already sent an alert for this vendor recently
                if not check_alert_sent_recently('vendors', vendor_id, hours=24):
                    alert = {
                        'id': f"{vendor_id}_low_score_{domain}",
                        'vendor_name': vendor_name,
                        'vendor_id': vendor_id,
                        'domain': domain,
                        'subdomain': domain,
                        'severity': 'CRITICAL',
                        'vulnerability': f'Low Security Score ({overall_score}/950)',
                        'description': f'Domain has an overall security score of {overall_score}/950, which is below the critical threshold of 600.',
                        'scan_type': 'Overall Security Score',
                        'detected_at': '',
                        'category': 'Security Score',
                        'table_name': 'vendors',
                        'record_id': vendor_id
                    }
                    critical_alerts.append(alert)
            
            # Get vulnerabilities - EXCLUDE Network and Encryption categories
            vulnerabilities = get_vulnerabilities_for_domain(domain)
            critical_vulns = [
                v for v in vulnerabilities 
                if v.get('severity', '').upper() == 'CRITICAL' 
                and v.get('category', '').upper() not in ['NETWORK', 'ENCRYPTION']
            ]
            
            for vuln in critical_vulns:
                vuln_id = vuln.get('id')
                # Check if we already sent an alert for this vulnerability recently
                if vuln_id and not check_alert_sent_recently('vulnerabilities', vuln_id, hours=24):
                    alert = {
                        'id': f"{vendor_id}_{vuln.get('title', 'unknown')}_{vuln.get('subdomain', domain)}",
                        'vendor_name': vendor_name,
                        'vendor_id': vendor_id,
                        'domain': domain,
                        'subdomain': vuln.get('subdomain', domain),
                        'severity': 'CRITICAL',
                        'vulnerability': vuln.get('title', vuln.get('description', 'Unknown Vulnerability')),
                        'description': vuln.get('description', ''),
                        'scan_type': vuln.get('category', 'Unknown'),
                        'detected_at': vuln.get('detected_at', ''),
                        'category': vuln.get('category', 'Unknown'),
                        'table_name': 'vulnerabilities',
                        'record_id': vuln_id
                    }
                    critical_alerts.append(alert)
        
        # Get critical news and incidents from the last 7 days
        try:
            # Direct database query for the last 7 days (inclusive of today)
            recent_news_query = """
            SELECT n.id, n.domain, n.event_date, n.title, n.description, 
                   n.severity, n.source_url, n.event_type, n.created_at,
                   v.vendor_name
            FROM news n
            LEFT JOIN vendors v ON n.domain = v.domain
            WHERE n.event_date >= CURRENT_DATE - INTERVAL '7 days'
            ORDER BY n.event_date DESC, n.created_at DESC
            """
            
            with DatabaseConnection() as db:
                recent_news_results = db.execute_query(recent_news_query)
            
            # Convert to same format as get_all_news returns
            all_news_items = []
            if recent_news_results:
                all_news_items = [{
                    'id': row['id'],
                    'domain': row['domain'],
                    'vendor_name': row['vendor_name'],
                    'date': row['event_date'].isoformat() if row['event_date'] else '',
                    'event_date': row['event_date'].isoformat() if row['event_date'] else '',  # Store event_date explicitly
                    'title': row['title'],
                    'description': row['description'],
                    'severity': row['severity'],
                    'source': row['source_url'],
                    'type': row['event_type'],
                    'created_at': row['created_at'].isoformat() if row['created_at'] else ''
                } for row in recent_news_results]
            
            critical_news = [
                item for item in all_news_items 
                if item.get('severity', '').upper() == 'CRITICAL' 
                and item.get('type', '').lower() == 'incident'
            ]
             
            for news_item in critical_news:
                news_id = news_item.get('id')
                # Check if we already sent an alert for this news item recently
                if news_id and not check_alert_sent_recently('news', news_id, hours=24):
                    vendor_for_news = next((v for v in vendors if v.get('domain') == news_item.get('domain')), None)
                    vendor_name_for_news = vendor_for_news.get('name', 'Unknown Vendor') if vendor_for_news else 'Unknown Vendor'
                    vendor_id_for_news = vendor_for_news.get('id', 0) if vendor_for_news else 0

                    alert = {
                        'id': f"incident_{news_item.get('id', 'unknown')}_{news_item.get('domain', 'unknown')}",
                        'vendor_name': vendor_name_for_news,
                        'vendor_id': vendor_id_for_news,
                        'domain': news_item.get('domain', 'Unknown'),
                        'subdomain': news_item.get('domain', 'Unknown'),
                        'severity': 'CRITICAL',
                        'vulnerability': news_item.get('title', 'Critical Security Incident'),
                        'description': news_item.get('description', 'No description available'),
                        'scan_type': 'Security Incident',
                        'detected_at': news_item.get('event_date', news_item.get('date', news_item.get('created_at', ''))),  # Use event_date from news table
                        'category': 'Security Incident',
                        'table_name': 'news',
                        'record_id': news_id,
                        'source_url': news_item.get('source_url')
                    }
                    critical_alerts.append(alert)
        except Exception as news_error:
            logger.error(f"Error fetching critical news: {news_error}")
        
        # Get recent critical audit logs (last 5 days) - API logs only
        try:
            # Direct database query for audit logs from last 7 days
            audit_query = """
            SELECT id, user_id, user_name, user_email, user_role, action, details, created_at FROM audit_logs 
            WHERE created_at >= NOW() - INTERVAL '7 days' 
            AND action = 'DELETE' 
            ORDER BY created_at DESC
            LIMIT 50
            """
            
            with DatabaseConnection() as db:
                audit_results = db.execute_query(audit_query)
                
                print(f"[SLACK BOT] Found {len(audit_results) if audit_results else 0} audit logs from last 7 days")
                logger.info(f"Found {len(audit_results) if audit_results else 0} audit logs from last 7 days")
                
                if audit_results:
                    # Filter for critical actions
                    critical_actions = ['DELETE']
                    critical_audit_logs = [
                        log for log in audit_results 
                        if any(action in log.get('action', '').upper() for action in critical_actions)
                    ]
                    
                    print(f"[SLACK BOT] Found {len(critical_audit_logs)} critical audit logs -> DELETE")
                    logger.info(f"Found {len(critical_audit_logs)} critical audit logs -> DELETE")
                else:
                    critical_audit_logs = []
            
            for log in critical_audit_logs[:10]:
                log_id = log.get('id', 'unknown')
                user_email = log.get('user_email', 'Unknown')
                user_name = log.get('user_name', 'Unknown')
                user_role = log.get('user_role', 'User')
                resource_type = log.get('resource_type', 'N/A')
                resource_id = log.get('resource_id', 'N/A')
                ip_address = log.get('ip_address', 'N/A')
                user_agent = log.get('user_agent', 'Unknown')
                details = log.get('details', {})
                timestamp = log.get('created_at', 'Unknown')
                action = log.get('action', 'Unknown')
                
                # Parse details for more information
                if isinstance(details, dict):
                    vendor = details.get('vendor_name', 'Unknown Vendor')
                    domain = details.get('domain', 'Unknown')
                else:
                    vendor = 'Unknown Vendor'
                    domain = 'Unknown'
                
                # Check if it's a vendor deletion/removal
                if 'DELETE' in action.upper():
                    # Check if we already sent an alert for this audit log recently
                    if not check_alert_sent_recently('audit_logs', log_id, hours=24):
                        # Vendor removal format - since we're only fetching DELETE actions, they're all vendor removals
                        # Use stable ID based on database ID
                        alert = {
                            'id': f"audit_log_{log_id}",
                            'timestamp': str(timestamp),
                            'vendor': vendor,
                            'domain': domain,
                            'scan_type': 'Audit Log',
                            'category': 'Vendor Removal',
                            'audit_action': action,
                            'audit_role': user_role,
                            'audit_user': user_name,
                            'table_name': 'audit_logs',
                            'record_id': log_id
                        }
                        critical_alerts.append(alert)
        except Exception as audit_error:
            logger.error(f"Error fetching audit logs: {audit_error}")
        
        # Get API audit logs from request_audit_log table (all API operations)
        try:
            api_audit_query = """
            SELECT id, key_name, client_ip, request_data, timestamp, response_code, endpoint_path, http_method
            FROM request_audit_log 
            WHERE timestamp >= NOW() - INTERVAL '7 days'
            ORDER BY timestamp DESC 
            LIMIT 50
            """
            
            with DatabaseConnection() as db:
                api_audit_results = db.execute_query(api_audit_query)
                
                print(f"[SLACK BOT] Found {len(api_audit_results) if api_audit_results else 0} API audit logs from last 7 days")
                logger.info(f"Found {len(api_audit_results) if api_audit_results else 0} API audit logs from last 7 days")
                
                if api_audit_results:
                    for log in api_audit_results[:10]:
                        log_id = log.get('id', 'unknown')
                        # Check if we already sent an alert for this API audit log recently
                        if log_id != 'unknown' and not check_alert_sent_recently('request_audit_log', int(log_id), hours=24):
                            key_name = log.get('key_name', 'Unknown')
                            client_ip = log.get('client_ip', 'N/A')
                            timestamp = log.get('timestamp', 'Unknown')
                            response_code = log.get('response_code', 'Unknown')
                            endpoint_path = log.get('endpoint_path', 'N/A')
                            http_method = log.get('http_method','Unknown')
                            request_data = log.get('request_data', {})

                            # Extract request info from request data
                            request_info = 'API Request'
                            domain = None
                            if isinstance(request_data, dict) and request_data:
                                # Try to get meaningful info from request data
                                if 'domain' in request_data:
                                    domain = request_data.get('domain')

                            # Determine action type based on method
                            action_type = f"{http_method} Request"

                            # Use stable ID based on database ID (not timestamp)
                            alert = {
                                'id': f"api_audit_{log_id}",
                                'key_name': key_name,  # Key name goes in vendor_name
                                'method': http_method,
                                'endpoint': endpoint_path, # Method goes in domain field
                                'domain': domain,
                                'ip': client_ip,  # IP goes in vulnerability field
                                'description': f"Action: {action_type} | {request_info} | Endpoint: {endpoint_path} | Response: {response_code}",
                                'scan_type': 'API Audit Log',
                                'timestamp': str(timestamp),
                                'category': 'API Audit',
                                'table_name': 'request_audit_log',
                                'record_id': int(log_id)
                            }
                            critical_alerts.append(alert)
        except Exception as api_audit_error:
            logger.error(f"Error fetching API audit logs: {api_audit_error}")
        
        # Failed scans removed as requested
        # Get recent breaches using direct database query
        try:
            # Get breach records from last 7 days (no severity filter)
            # Exclude credential leaks (password_leaked = 1) to avoid duplication
            # Note: password_leaked is INTEGER (0=False, 1=True)
            breach_query = """
            SELECT id, email, severity, description, created_at, password_leaked
            FROM breach_records 
            WHERE created_at >= NOW() - INTERVAL '7 days'
            ORDER BY created_at DESC
            LIMIT 50
            """
            
            with DatabaseConnection() as db:
                breach_results = db.execute_query(breach_query)
                
                print(f"[SLACK BOT] Found {len(breach_results) if breach_results else 0} breach records from last 7 days")
                if breach_results:
                    print(f"[SLACK BOT] Sample breach record: {breach_results[0]}")
                logger.info(f"Found {len(breach_results) if breach_results else 0} breach records from last 7 days")
                
                if breach_results:
                    
                    for breach in breach_results:
                        breach_id = breach.get('id', 'unknown')
                        # Check if we already sent an alert for this breach recently
                        if breach_id != 'unknown' and not check_alert_sent_recently('breach_records', int(breach_id), hours=24):
                            # Extract domain from email
                            email = breach.get('email', '')
                            name = email.split('@')[1] if '@' in email else ''
                            severity = breach.get('severity', 'Unknown')
                            description = breach.get('description', 'No description')
                            # Find vendor for this domain
                            # Use stable ID based on database ID (or email if no ID)
                            alert_id = f"credential_leak_{breach_id}" if breach_id != 'unknown' else f"credential_leak_{email}_{breach.get('created_at', '')}"
                            alert = {
                                'id': alert_id,
                                'email': email,
                                'password_leaked': breach.get('password_leaked', 0),
                                'name': name,
                                'severity': severity,
                                'vulnerability': f"Credential Leak Detected",
                                'description': description,
                                'scan_type': 'Credential Leak',
                                'detected_at': breach.get('created_at', ''),
                                'category': 'Credential Leak',
                                'table_name': 'breach_records',
                                'record_id': int(breach_id)
                            }
                            critical_alerts.append(alert)
        except Exception as breach_error:
            logger.error(f"Error fetching breaches: {breach_error}")
        
        # Sort by detection time
        critical_alerts.sort(key=lambda x: x.get('detected_at', ''), reverse=True)
        
        # Count different types
        vuln_alerts = len([a for a in critical_alerts if a.get('scan_type') not in ['Overall Security Score', 'Security Incident', 'Audit Log', 'API Audit Log','Credential Leak']])
        score_alerts = len([a for a in critical_alerts if a.get('scan_type') == 'Overall Security Score'])
        incident_alerts = len([a for a in critical_alerts if a.get('scan_type') == 'Security Incident'])
        audit_alerts = len([a for a in critical_alerts if a.get('scan_type') == 'Audit Log'])
        api_audit_alerts = len([a for a in critical_alerts if a.get('scan_type') == 'API Audit Log'])
        # Note: audit_alerts are vendor deletions, so vendors_removed = audit_alerts
        failed_scan_alerts = len([a for a in critical_alerts if a.get('scan_type') == 'Failed Scan'])
        credential_leak_alerts = len([a for a in critical_alerts if a.get('scan_type') == 'Credential Leak'])
        
        alerts_data = {
            'success': True,
            'critical_alerts': critical_alerts,
            'total_count': len(critical_alerts),
            'breakdown': {
                'vulnerabilities': vuln_alerts,
                'low_scores': score_alerts,
                'critical_incidents': incident_alerts,
                'vendors_removed': audit_alerts,  # Audit logs are vendor deletions
                'api_audit_logs': api_audit_alerts,
                'failed_scans': failed_scan_alerts,
                'credential_leaks': credential_leak_alerts
            }
        }
        
        total_count = len(critical_alerts)
        print(f"[SLACK BOT] Found {total_count} critical alerts ")
        print(f"[SLACK BOT] Breakdown: {vuln_alerts} vulnerabilities, {score_alerts} low scores, {incident_alerts} incidents, {audit_alerts} vendors removed, {api_audit_alerts} API audit logs, {credential_leak_alerts} credential leaks")
        logger.info(f"Found {total_count} critical alerts ")
        logger.info(f"Breakdown: {vuln_alerts} vulnerabilities, {score_alerts} low scores, {incident_alerts} incidents, {audit_alerts} vendors removed, {api_audit_alerts} API audit logs, {credential_leak_alerts} credential leaks")
        
        # Send to Slack
        print(f"[SLACK BOT] Sending {total_count} alerts to Slack...")
        from .slack_service import send_critical_alerts_notification
        success = send_critical_alerts_notification(alerts_data)
        if success:
            print("[SLACK BOT] Successfully sent critical alerts to Slack!")
            logger.info("Successfully sent critical alerts to Slack")
        else:
            print("[SLACK BOT] Failed to send critical alerts to Slack!")
            logger.error("Failed to send critical alerts to Slack")
        
    except Exception as e:
        print(f"[SLACK BOT] Error: {e}")
        logger.error(f"Error in fetch_critical_alerts: {e}")


def fetch_vendor_analytics():
    """
    Fetch vendor analytics from the API endpoint and send to Slack
    """
    try:
        print("\n[SLACK BOT] Fetching vendor analytics...")
        logger.info("Fetching vendor analytics for Slack notification...")
        
        # Call the vendor performance endpoint (port 5005)
        response = requests.get('http://localhost:5005/api/analytics/vendor-performance', timeout=30)
        print(f"[SLACK BOT] API Response Status: {response.status_code}")
        logger.info(f"API Response Status: {response.status_code}")
        
        if response.status_code == 200:
            analytics_data = response.json()
            print(f"[SLACK BOT] Fetched vendor analytics data")
            logger.info(f"Fetched vendor analytics data")
            
            # Send to Slack
            print(f"[SLACK BOT] Sending analytics to Slack...")
            from .slack_service import send_vendor_analytics_notification
            success = send_vendor_analytics_notification(analytics_data)
            if success:
                print("[SLACK BOT] Successfully sent vendor analytics to Slack!")
                logger.info("Successfully sent vendor analytics to Slack")
            else:
                print("[SLACK BOT] Failed to send vendor analytics to Slack")
                logger.error("Failed to send vendor analytics to Slack")
        else:
            print(f"[SLACK BOT] Failed to fetch analytics. Status: {response.status_code}")
            logger.error(f"Failed to fetch vendor analytics. Status: {response.status_code}")
            
    except requests.exceptions.ConnectionError as e:
        print(f"[SLACK BOT] Connection Error: Is the app running on port 5005?")
        logger.error(f"Connection error in fetch_vendor_analytics: {e}")
    except Exception as e:
        print(f"[SLACK BOT] Error: {e}")
        logger.error(f"Error in fetch_vendor_analytics: {e}")


def send_critical_alerts_notification():
    """
    Send only critical alerts (API logs, audit logs)
    """
    print("\n" + "=" * 70)
    print(f"[SLACK BOT] Starting critical alerts notification")
    print(f"[SLACK BOT] Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 70)
    logger.info("=" * 60)
    logger.info(f"Starting critical alerts notification at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    logger.info("=" * 60)
    
    # Send critical alerts only
    fetch_critical_alerts()
    
    print("\n" + "=" * 70)
    print("[SLACK BOT] Critical alerts notification completed!")
    print("=" * 70 + "\n")
    logger.info("=" * 60)
    logger.info("Critical alerts notification completed")
    logger.info("=" * 60)


def send_weekly_vendor_analytics():
    """
    Send weekly vendor analytics report
    """
    print("\n" + "=" * 70)
    print(f"[SLACK BOT] Starting weekly vendor analytics report")
    print(f"[SLACK BOT] Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 70)
    logger.info("=" * 60)
    logger.info(f"Starting weekly vendor analytics at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    logger.info("=" * 60)
    
    # Send vendor analytics only
    fetch_vendor_analytics()
    
    print("\n" + "=" * 70)
    print("[SLACK BOT] Weekly vendor analytics completed!")
    print("=" * 70 + "\n")
    logger.info("=" * 60)
    logger.info("Weekly vendor analytics completed")
    logger.info("=" * 60)


def send_daily_slack_notifications():
    """
    Combined function to send both critical alerts and vendor analytics (for backward compatibility)
    """
    print("\n" + "=" * 70)
    print(f"[SLACK BOT] Starting combined Slack notifications")
    print(f"[SLACK BOT] Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 70)
    logger.info("=" * 60)
    logger.info(f"Starting combined notifications at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    logger.info("=" * 60)
    
    # Send critical alerts
    fetch_critical_alerts()
    
    # Send vendor analytics
    fetch_vendor_analytics()
    
    print("\n" + "=" * 70)
    print("[SLACK BOT] Combined notifications completed!")
    print("=" * 70 + "\n")
    logger.info("=" * 60)
    logger.info("Combined notifications completed")
    logger.info("=" * 60)


def send_daily_client_leak_digest():
    """Send the once-daily Breach Monitor client credential leak count digest to Slack."""
    print("\n" + "=" * 70)
    print(f"[SLACK BOT] Starting daily client leak digest")
    print(f"[SLACK BOT] Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 70)
    logger.info("Starting daily client leak digest at %s", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

    from .slack_service import send_breach_monitor_daily_client_leak_digest

    success = send_breach_monitor_daily_client_leak_digest()
    if success:
        print("[SLACK BOT] Daily client leak digest completed")
        logger.info("Daily client leak digest completed")
    else:
        print("[SLACK BOT] Daily client leak digest failed")
        logger.error("Daily client leak digest failed")

    print("=" * 70 + "\n")


def initialize_slack_scheduler():
    """
    Initialize the Slack notification scheduler
    - Weekly vendor analytics: Tuesdays at 11:00 AM (server local time)
    - Daily client credential leak digest: Every day at 11:00 AM Asia/Dubai
    """
    global scheduler
    
    print("\n[DEBUG] initialize_slack_scheduler() called")
    print(f"[DEBUG] Current scheduler value: {scheduler}")
    
    try:
        scheduler = BackgroundScheduler()
        print(f"[DEBUG] BackgroundScheduler created: {scheduler}")
        
        # Weekly vendor analytics report - Tuesdays at 11:00 AM
        scheduler.add_job(
            func=send_weekly_vendor_analytics,
            trigger=CronTrigger(day_of_week='tue', hour=11, minute=0),
            id='weekly_vendor_analytics',
            name='Weekly vendor analytics (Tuesdays 11 AM)',
            replace_existing=True
        )

        scheduler.add_job(
            func=send_daily_client_leak_digest,
            trigger=CronTrigger(hour=11, minute=0, timezone=DUBAI_TZ),
            id='daily_client_leak_digest',
            name='Daily client credential leak digest (11 AM Asia/Dubai)',
            replace_existing=True
        )

        
        scheduler.start()
        logger.info(f"[DEBUG] Scheduler started. Running: {scheduler.running}")
        logger.info(f"[DEBUG] Scheduler jobs: {scheduler.get_jobs()}")
        logger.info("\n" + "=" * 70)
        logger.info("Slack notification scheduler initialized successfully")
        logger.info("Weekly vendor analytics: Tuesdays at 11:00 AM")
        logger.info("Client credential leak digest: Daily at 11:00 AM Asia/Dubai (UTC+4)")
        logger.info(f"[DEBUG] Final scheduler state - Running: {scheduler.running}, ID: {id(scheduler)}")
        logger.info("=" * 70 + "\n")

        
        # Shut down the scheduler when the app exits
        atexit.register(lambda: scheduler.shutdown() if scheduler else None)
        
    except Exception as e:
        print(f"\nERROR: Failed to initialize Slack scheduler!")
        print(f"   Error: {e}")
        print(f"   Please check the logs for more details.\n")
        logger.error(f"Error initializing Slack scheduler: {e}")
        import traceback
        traceback.print_exc()


def shutdown_slack_scheduler():
    """
    Shutdown the Slack notification scheduler
    """
    global scheduler
    if scheduler:
        scheduler.shutdown()
        logger.info("Slack notification scheduler shut down")


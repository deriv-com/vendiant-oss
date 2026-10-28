#!/usr/bin/env python3
"""
Scan Resume Utilities

Reports where the full-scan loop will pick up next.

This used to derive the position from the `scores` table -- taking the most
recent row labelled 'full_scan_all' and walking to the "next" vendor. That was
unsound for three reasons:

  * `scores` is written by several code paths, and scan_format was inherited
    from whichever row was written last, so a row could claim to come from a
    full scan that never ran. In practice a report *read* moved the cursor.
  * "Next vendor" was computed over vendors ordered by id, while the scanner
    walked them ordered by vendor_name. The two never agreed.
  * The scan ran from the checkpoint to the end of its list with no wrap-around,
    so vendors before the checkpoint were skipped every pass.

Scan order is now simply "stalest first" over vendors.last_full_scan_at, a
column written only when a full scan completes every step. Resuming is implicit:
whatever an interrupted run did not reach is still the oldest. This module now
just reports that queue for the dashboard.
"""
import logging


def get_resume_scan_info_sync():
    """Describe the next work the full-scan loop will do.

    Response keys are kept stable for the dashboard, which reads can_resume,
    resume_from_domain, resume_from_vendor and message.
    """
    try:
        from db_service import DatabaseConnection

        with DatabaseConnection() as db:
            pending = db.execute_single_query(
                """
                SELECT
                    COUNT(*) FILTER (WHERE last_full_scan_at IS NULL)  AS never_scanned,
                    COUNT(*)                                            AS total
                FROM vendors
                WHERE domain IS NOT NULL AND domain <> ''
                """
            ) or {}

            next_vendor = db.execute_single_query(
                """
                SELECT domain, vendor_name, last_full_scan_at
                FROM vendors
                WHERE domain IS NOT NULL AND domain <> ''
                ORDER BY last_full_scan_at ASC NULLS FIRST, id ASC
                LIMIT 1
                """
            )

            if not next_vendor:
                return {
                    'status': 'success',
                    'can_resume': False,
                    'checkpoint_vendor': '',
                    'message': 'No vendors available to scan',
                }

            never_scanned = pending.get('never_scanned') or 0
            total = pending.get('total') or 0
            last_scan = next_vendor.get('last_full_scan_at')

            if last_scan is None:
                message = (
                    f"Next up: {next_vendor['vendor_name']} ({next_vendor['domain']}) "
                    f"- never scanned. {never_scanned} of {total} vendors have no completed scan yet."
                )
            else:
                message = (
                    f"Next up: {next_vendor['vendor_name']} ({next_vendor['domain']}) "
                    f"- stalest, last completed {last_scan.isoformat()}."
                )

            return {
                'status': 'success',
                'can_resume': True,
                'checkpoint_vendor': next_vendor['domain'],
                'resume_from_domain': next_vendor['domain'],
                'resume_from_vendor': next_vendor['vendor_name'],
                'last_scan_time': last_scan.isoformat() if last_scan else None,
                'never_scanned_count': never_scanned,
                'total_vendors': total,
                'message': message,
            }

    except Exception as e:
        logging.error(f"Error getting resume scan info: {str(e)}")
        return {
            'status': 'error',
            'can_resume': False,
            'checkpoint_vendor': '',
            'message': f'Error getting resume info: {str(e)}',
        }

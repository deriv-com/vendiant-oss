import os
import time
import threading
import logging
from datetime import datetime
from typing import Callable, Dict, Any

from scheduler_config import background_schedulers_enabled

try:
    from Dashboard.background_job_store import generate_job_id
except ImportError:
    from background_job_store import generate_job_id


def register_auto_full_scan_on_startup(
    app,
    background_jobs: Dict[str, Dict[str, Any]],
    run_background_full_scan_all_domains: Callable[[str, bool, str], None]
) -> None:
    """
    Register a startup handler that launches a background loop to continuously
    run full scans for all vendors. Controlled via AUTO_FULL_SCAN_ON_START env.
    """
    # Local counter removed — job IDs are generated globally unique for multi-pod.

    def _start_background_full_scan_internal(include_subdomains: bool = True, checkpoint_vendor: str = '') -> str:
        """
        Programmatically start a background full scan for all domains.
        Returns the created job_id.
        """
        job_id = generate_job_id('full')
        log_message = f'Background full scan starting... (auto scheduler) (subdomains: {"included" if include_subdomains else "main domains only"})'
        if checkpoint_vendor:
            log_message += f' (checkpoint: starting from {checkpoint_vendor})'

        background_jobs[job_id] = {
            'job_id': job_id,
            'status': 'starting',
            'progress': 0,
            'start_time': datetime.now(),
            'current_domain': None,
            'stage': 'initializing',
            'domains': [],
            'total_domains': 0,
            'completed': [],
            'failed': [],
            'logs': [log_message],
            'include_subdomains': include_subdomains,
            'checkpoint_vendor': checkpoint_vendor or None,
            'vendor_filters': {},
            'scan_type': 'full'
        }

        scan_thread = threading.Thread(
            target=run_background_full_scan_all_domains,
            args=(job_id, include_subdomains, checkpoint_vendor)
        )
        scan_thread.daemon = True
        scan_thread.start()

        # Update status to running
        background_jobs[job_id]['status'] = 'running'
        background_jobs[job_id]['logs'].append('Background scan thread started (auto)')
        logging.info(f"Auto scheduler started background full scan job: {job_id}")
        return job_id

    def auto_full_scan_scheduler():
        """
        Continuously runs full scans for all vendors in a loop with smart resume.
        """
        logging.info("Auto full scan scheduler loop started")
        blocked_since = None
        last_blocked_log = 0.0
        while True:
            try:
                # Clear orphans first. A job whose pod was killed can never mark
                # itself terminal, so without this the block below is permanent.
                try:
                    background_jobs.reap_stale_jobs()
                except Exception as reap_exc:
                    logging.error("Auto scheduler: stale job reap failed: %s", reap_exc)

                # Only a full-fleet scan may block this loop. API-triggered
                # single scans run independently and must not gate it.
                active = background_jobs.active_jobs(scan_types=['full'])
                if active:
                    now = time.time()
                    if blocked_since is None:
                        blocked_since = now
                    # Never block silently: log on first detection, then hourly.
                    if now - last_blocked_log > 3600 or last_blocked_log == 0.0:
                        last_blocked_log = now
                        blocker = active[0]
                        logging.info(
                            "Auto scheduler waiting: full scan %s already active "
                            "(status=%s, domain=%s, pod=%s, last heartbeat=%s). "
                            "Blocked for %.1f minutes.",
                            blocker.get('job_id'),
                            blocker.get('status'),
                            blocker.get('current_domain'),
                            blocker.get('started_by_pod'),
                            blocker.get('updated_at'),
                            (now - blocked_since) / 60.0,
                        )
                    time.sleep(30)
                    continue
                blocked_since = None
                last_blocked_log = 0.0

                # No checkpoint. run_background_full_scan_all_domains orders
                # vendors stalest-first (vendors.last_full_scan_at), so resuming
                # is implicit: whatever an interrupted run failed to reach is
                # still the oldest and gets picked up first.
                #
                # The old scan_resume_utils cursor was derived from the `scores`
                # table and could be moved by any code path that wrote a score
                # row -- including a report read -- so it pointed at whichever
                # vendor was last *viewed* rather than last scanned.
                logging.info("Auto scheduler: starting full scan (stalest-first ordering)")
                job_id = _start_background_full_scan_internal(include_subdomains=True)

                # Wait for completion of this job.
                # The reaper must run in here too, not only in the outer loop:
                # if the scan thread dies without setting a terminal status
                # while this process survives, the job never leaves 'running'
                # and this loop would otherwise wait on it forever -- the exact
                # failure the reaper exists to prevent, just relocated.
                while True:
                    job = background_jobs.get(job_id)
                    if not job or job.get('status') in ['completed', 'failed', 'cancelled']:
                        break
                    try:
                        if job_id in background_jobs.reap_stale_jobs():
                            logging.error(
                                "Auto scheduler: reaped its own job %s -- the scan thread "
                                "stopped heartbeating. Moving on to a new scan.", job_id
                            )
                            break
                    except Exception as reap_exc:
                        logging.error("Auto scheduler: in-flight reap check failed: %s", reap_exc)
                    time.sleep(30)
                # Small pause before starting next loop
                time.sleep(60)
            except Exception as e:
                logging.error(f"Auto full scan scheduler error: {e}")
                time.sleep(60)

    def _startup_handler():
        try:
            if not background_schedulers_enabled():
                logging.info(
                    "ENABLE_BACKGROUND_SCHEDULERS disabled — auto vendor full-scan loop not started"
                )
                return

            try:
                background_jobs.purge_completed_jobs()
            except Exception as purge_exc:
                logging.warning("Background scan job purge skipped: %s", purge_exc)

            # Reap before the loop starts: a pod that died mid-scan leaves a job
            # stuck in 'running', and this pod would otherwise inherit that block.
            #
            # Two passes, because they catch different things:
            #  - cross-pod: this scheduler is a singleton, so any full scan
            #    owned by another pod is orphaned by definition. Recovers from
            #    a rollout immediately, where time-based reaping would make the
            #    fleet wait out the full staleness window first.
            #  - time-based: catches anything stale that this same pod owns.
            try:
                for label, reaped in (
                    ("left by a previous pod", background_jobs.reap_jobs_from_other_pods()),
                    ("stale", background_jobs.reap_stale_jobs()),
                ):
                    if reaped:
                        logging.warning(
                            "Startup reaped %d %s scan job(s): %s",
                            len(reaped), label, ", ".join(reaped)
                        )
            except Exception as reap_exc:
                logging.error("Background scan job reap skipped: %s", reap_exc)

            enabled = os.getenv('AUTO_FULL_SCAN_ON_START', '1')
            if str(enabled).lower() in ('1', 'true', 'yes', 'on'):
                t = threading.Thread(target=auto_full_scan_scheduler)
                t.daemon = True
                t.start()
                logging.info("AUTO_FULL_SCAN_ON_START enabled - scheduler thread launched")
            else:
                logging.info("AUTO_FULL_SCAN_ON_START disabled - scheduler not started")
        except Exception as e:
            logging.error(f"Failed to start auto full scan scheduler: {e}")

    # Register with FastAPI (handler lives on APIRouter, not the app instance)
    app.router.add_event_handler("startup", _startup_handler)



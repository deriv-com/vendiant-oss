"""
Threaded Scheduler Manager
Manages news scheduler and Slack bot scheduler in separate threads
"""
import threading
import logging
import time
import atexit
from typing import Optional

from scheduler_config import background_schedulers_enabled

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ThreadedSchedulerManager:
    """
    Manages multiple schedulers in separate threads
    """
    
    def __init__(self):
        self.news_thread: Optional[threading.Thread] = None
        self.slack_thread: Optional[threading.Thread] = None
        self.shutdown_event = threading.Event()
        self.running = False
        
    def start_news_scheduler_thread(self):
        """Start news scheduler in a separate thread"""
        if self.news_thread and self.news_thread.is_alive():
            logger.warning("News scheduler thread is already running")
            return
            
        logger.info("Starting news scheduler thread...")
        self.news_thread = threading.Thread(
            target=self._run_news_scheduler,
            name="NewsSchedulerThread",
            daemon=True
        )
        self.news_thread.start()
        logger.info("News scheduler thread started successfully")
        
    def start_slack_scheduler_thread(self):
        """Start Slack bot scheduler in a separate thread"""
        if self.slack_thread and self.slack_thread.is_alive():
            logger.warning("Slack scheduler thread is already running")
            return
            
        logger.info("Starting Slack scheduler thread...")
        self.slack_thread = threading.Thread(
            target=self._run_slack_scheduler,
            name="SlackSchedulerThread", 
            daemon=True
        )
        self.slack_thread.start()
        logger.info("Slack scheduler thread started successfully")

    def _run_news_scheduler(self):
        """Run news scheduler in its own thread"""
        try:
            logger.info("[NEWS THREAD] Initializing news scheduler...")
            from routes.news_routes import initialize_news_scheduler
            
            # Initialize the news scheduler
            initialize_news_scheduler()
            logger.info("[NEWS THREAD] News scheduler initialized and running")
            
            # Keep the thread alive
            while not self.shutdown_event.is_set():
                time.sleep(1)
                
        except Exception as e:
            logger.error(f"[NEWS THREAD] Error in news scheduler thread: {e}")
            import traceback
            traceback.print_exc()
        finally:
            logger.info("[NEWS THREAD] News scheduler thread shutting down")
            
    def _run_slack_scheduler(self):
        """Run Slack bot scheduler in its own thread"""
        try:
            logger.info("[SLACK THREAD] Initializing Slack scheduler...")
            from slack.slack_scheduler import initialize_slack_scheduler
            
            # Initialize the Slack scheduler
            initialize_slack_scheduler()
            logger.info("[SLACK THREAD] Slack scheduler initialized and running")
            
            # Keep the thread alive
            while not self.shutdown_event.is_set():
                time.sleep(1)
                
        except Exception as e:
            logger.error(f"[SLACK THREAD] Error in Slack scheduler thread: {e}")
            import traceback
            traceback.print_exc()
        finally:
            logger.info("[SLACK THREAD] Slack scheduler thread shutting down")
            
    def start_all_schedulers(self):
        """Start both schedulers in separate threads"""
        logger.info("=" * 70)
        logger.info("Starting Threaded Scheduler Manager")
        logger.info("=" * 70)

        if not background_schedulers_enabled():
            logger.info(
                "ENABLE_BACKGROUND_SCHEDULERS is disabled — skipping news and Slack "
                "schedulers (dashboard manual actions only)"
            )
            return

        self.running = True
        
        # Start news scheduler thread
        self.start_news_scheduler_thread()
        
        # Small delay to avoid race conditions
        time.sleep(0.5)
        
        # Start Slack scheduler thread
        self.start_slack_scheduler_thread()

        logger.info("=" * 70)
        logger.info("All schedulers started in separate threads")
        logger.info("News Scheduler: Running every 2 hours")
        logger.info("Slack Analytics: Tuesdays at 11:00 AM")
        logger.info("Slack Alerts: Event Based")
        logger.info("=" * 70)
        
    def shutdown_all_schedulers(self):
        """Shutdown all scheduler threads gracefully"""
        if not self.running:
            return
            
        logger.info("=" * 70)
        logger.info("Shutting down all scheduler threads...")
        logger.info("=" * 70)
        
        # Signal shutdown to all threads
        self.shutdown_event.set()
        self.running = False
        
        # Wait for threads to finish (with timeout)
        if self.news_thread and self.news_thread.is_alive():
            logger.info("Waiting for news scheduler thread to finish...")
            self.news_thread.join(timeout=5)
            if self.news_thread.is_alive():
                logger.warning("News scheduler thread did not finish gracefully")
                
        if self.slack_thread and self.slack_thread.is_alive():
            logger.info("Waiting for Slack scheduler thread to finish...")
            self.slack_thread.join(timeout=5)
            if self.slack_thread.is_alive():
                logger.warning("Slack scheduler thread did not finish gracefully")

        # Also shutdown the actual schedulers
        try:
            from routes.news_routes import shutdown_scheduler as shutdown_news_scheduler
            shutdown_news_scheduler()
        except Exception as e:
            logger.warning(f"Error shutting down news scheduler: {e}")
            
        try:
            from slack.slack_scheduler import shutdown_slack_scheduler
            shutdown_slack_scheduler()
        except Exception as e:
            logger.warning(f"Error shutting down Slack scheduler: {e}")

        logger.info("All scheduler threads shut down")
        
    def get_status(self):
        """Get status of all scheduler threads"""
        return {
            'news_scheduler': {
                'thread_alive': self.news_thread.is_alive() if self.news_thread else False,
                'thread_name': self.news_thread.name if self.news_thread else None
            },
            'slack_scheduler': {
                'thread_alive': self.slack_thread.is_alive() if self.slack_thread else False,
                'thread_name': self.slack_thread.name if self.slack_thread else None
            },
            'manager_running': self.running,
            'shutdown_event_set': self.shutdown_event.is_set()
        }

# Global instance
scheduler_manager = ThreadedSchedulerManager()

def initialize_threaded_schedulers():
    """Initialize all schedulers in separate threads"""
    scheduler_manager.start_all_schedulers()

def shutdown_threaded_schedulers():
    """Shutdown all threaded schedulers"""
    scheduler_manager.shutdown_all_schedulers()

def get_scheduler_status():
    """Get status of all schedulers"""
    return scheduler_manager.get_status()

# Register shutdown function to run on app exit
atexit.register(shutdown_threaded_schedulers)

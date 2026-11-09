import os
import sys
import logging
import threading
from pathlib import Path

import psycopg2
from psycopg2 import pool as psycopg2_pool
from psycopg2.extras import RealDictCursor, execute_values
from dotenv import load_dotenv

# Project root (repo root): Dashboard/db_config.py -> parent.parent
_ROOT = Path(__file__).resolve().parent.parent
load_dotenv(_ROOT / ".env")

#Setup logging
# Add custom integrations path for logger
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'custom_integrations'))
from logger_config import setup_logger

# Configure logging using custom logger
logger = setup_logger()

# Database configuration — values from root .env (DB_*), same names as docker-compose
def _env_int(key: str, default: str) -> int:
    raw = os.getenv(key, default)
    try:
        return int(raw)
    except (TypeError, ValueError):
        return int(default)


DB_CONFIG = {
    'host': os.getenv('DB_HOST'),
    'port': os.getenv('DB_PORT'),
    'database': os.getenv('DB_NAME'),
    'user': os.getenv('DB_USER'),
    'password': os.getenv('DB_PASSWORD'),
    'connect_timeout': 10,
    'keepalives_idle': 600,
    'keepalives_interval': 30,
    'keepalives_count': 3
}

# Breach-monitor data can live in a dedicated database (DB_NAME_BREACHES).
# It defaults to DB_NAME so a single-database deployment works with no
# extra configuration.
BREACH_MONITOR_DB_CONFIG = {
    'host': os.getenv('DB_HOST'),
    'port': os.getenv('DB_PORT'),
    'database': os.getenv('DB_NAME_BREACHES', os.getenv('DB_NAME')),
    'user': os.getenv('DB_USER'),
    'password': os.getenv('DB_PASSWORD'),
    'connect_timeout': 10,
    'keepalives_idle': 600,
    'keepalives_interval': 30,
    'keepalives_count': 3
}

# Bounded per-process connection pools. Every replica of this service opens
# its own pool, so size DB_POOL_MAX_CONN with
# `replicas * pools_per_process * DB_POOL_MAX_CONN` staying comfortably under
# the PostgreSQL server's max_connections. This bounds the connection burst
# that a spike of webhook requests can create.
DB_POOL_MIN_CONN = _env_int('DB_POOL_MIN_CONN', '1')
DB_POOL_MAX_CONN = _env_int('DB_POOL_MAX_CONN', '5')
# Seconds a caller waits for a free pooled connection before giving up.
DB_POOL_ACQUIRE_TIMEOUT = _env_int('DB_POOL_ACQUIRE_TIMEOUT', '15')

_pool_lock = threading.Lock()
_pools: dict = {}


class BlockingThreadedConnectionPool(psycopg2_pool.ThreadedConnectionPool):
    """ThreadedConnectionPool whose ``getconn`` waits for a free slot.

    The stock pool raises ``PoolError("connection pool exhausted")`` the moment
    all ``maxconn`` connections are checked out, so a burst of concurrent
    requests (e.g. a breach-monitor webhook batch) fails some of them outright even
    though a connection frees up milliseconds later. A semaphore sized to
    ``maxconn`` makes callers queue for up to ``acquire_timeout`` seconds instead.
    """

    def __init__(self, minconn, maxconn, *args, acquire_timeout=DB_POOL_ACQUIRE_TIMEOUT, **kwargs):
        self._slots = threading.BoundedSemaphore(maxconn)
        self._acquire_timeout = acquire_timeout
        super().__init__(minconn, maxconn, *args, **kwargs)

    def getconn(self, key=None):
        if not self._slots.acquire(timeout=self._acquire_timeout):
            raise psycopg2_pool.PoolError(
                f"connection pool exhausted (waited {self._acquire_timeout}s)"
            )
        try:
            return super().getconn(key)
        except Exception:
            self._slots.release()
            raise

    def putconn(self, conn=None, key=None, close=False):
        # Only release a slot for a connection this pool handed out, and release
        # it even if the return itself fails, so a slot can never leak.
        owned = conn is not None and id(conn) in self._rused
        try:
            super().putconn(conn, key, close)
        finally:
            if owned:
                self._slots.release()


def _get_pool(config: dict, pool_key: str) -> psycopg2_pool.ThreadedConnectionPool:
    """Lazily create (once) and return the connection pool for ``pool_key``."""
    pool_obj = _pools.get(pool_key)
    if pool_obj is not None:
        return pool_obj
    with _pool_lock:
        pool_obj = _pools.get(pool_key)
        if pool_obj is None:
            pool_obj = BlockingThreadedConnectionPool(
                DB_POOL_MIN_CONN,
                DB_POOL_MAX_CONN,
                **config,
            )
            _pools[pool_key] = pool_obj
            logger.info(
                "Initialized DB connection pool '%s' (min=%s, max=%s, acquire_timeout=%ss)",
                pool_key, DB_POOL_MIN_CONN, DB_POOL_MAX_CONN, DB_POOL_ACQUIRE_TIMEOUT,
            )
    return pool_obj

class DatabaseConnection:
    """Database connection manager for PostgreSQL, backed by a bounded pool."""

    # Overridden by BreachMonitorDatabaseConnection to target a different pool/DB.
    _POOL_KEY = "dashboard"
    _DB_CONFIG = DB_CONFIG

    def __init__(self):
        self.connection = None
        self.cursor = None
        self._broken = False

    def _pool(self) -> psycopg2_pool.ThreadedConnectionPool:
        return _get_pool(self._DB_CONFIG, self._POOL_KEY)

    def connect(self):
        """Acquire a pooled connection to PostgreSQL."""
        try:
            self.connection = self._pool().getconn()
            self._broken = False
            self.cursor = self.connection.cursor(cursor_factory=RealDictCursor)
            return True
        except psycopg2.Error as e:
            logger.error(f"Error acquiring PostgreSQL connection from pool: {e}")
            return False

    def disconnect(self):
        """Return the connection to the pool (or discard it if it errored)."""
        if self.cursor:
            try:
                self.cursor.close()
            except psycopg2.Error:
                pass
        if self.connection:
            try:
                self._pool().putconn(self.connection, close=self._broken)
            except psycopg2.Error as e:
                logger.error(f"Error returning connection to pool: {e}")
        self.connection = None
        self.cursor = None
    
    def execute_query(self, query, params=None):
        """Execute a SELECT query and return results"""
        try:
            if not self.connection or self.connection.closed:
                if not self.connect():
                    logger.error("Failed to establish database connection")
                    return None
            
            self.cursor.execute(query, params)
            return self.cursor.fetchall()
        except psycopg2.OperationalError as e:
            logger.error(f"Database connection error: {e}")
            # Connection is dead; discard it (don't return it to the pool) and retry once.
            self._broken = True
            try:
                self.disconnect()
                if self.connect():
                    self.cursor.execute(query, params)
                    return self.cursor.fetchall()
            except Exception as reconnect_error:
                logger.error(f"Reconnection failed: {reconnect_error}")
                self._broken = True
            return None
        except psycopg2.Error as e:
            logger.error(f"Error executing query: {e}")
            return None
    
    def execute_single_query(self, query, params=None):
        """Execute a SELECT query and return single result"""
        try:
            if not self.connection or self.connection.closed:
                if not self.connect():
                    return None
            
            self.cursor.execute(query, params)
            return self.cursor.fetchone()
        except psycopg2.OperationalError as e:
            logger.error(f"Error executing single query: {e}")
            self._broken = True
            return None
        except psycopg2.Error as e:
            logger.error(f"Error executing single query: {e}")
            return None
    
    def execute_insert(self, query, params=None):
        """Execute an INSERT/UPDATE/DELETE query and commit"""
        try:
            if not self.connection or self.connection.closed:
                if not self.connect():
                    return False
            
            self.cursor.execute(query, params)
            self.connection.commit()
            return True
        except psycopg2.OperationalError as e:
            logger.error(f"Error executing insert/update: {e}")
            self._broken = True
            return False
        except psycopg2.Error as e:
            logger.error(f"Error executing insert/update: {e}")
            if self.connection:
                self.connection.rollback()
            return False
    
    def execute_many(self, query, params_list):
        """Execute multiple queries with parameter lists (batch insert)"""
        try:
            if not self.connection or self.connection.closed:
                if not self.connect():
                    return False
            
            self.cursor.executemany(query, params_list)
            self.connection.commit()
            return True
        except psycopg2.OperationalError as e:
            logger.error(f"Error executing batch insert: {e}")
            self._broken = True
            return False
        except psycopg2.Error as e:
            logger.error(f"Error executing batch insert: {e}")
            if self.connection:
                self.connection.rollback()
            return False
    
    def execute_returning(self, query, params=None):
        """Execute a write query with RETURNING and commit, returning a single row"""
        try:
            if not self.connection or self.connection.closed:
                if not self.connect():
                    return None
            
            self.cursor.execute(query, params)
            result = self.cursor.fetchone()
            self.connection.commit()
            return result
        except psycopg2.OperationalError as e:
            logger.error(f"Error executing returning query: {e}")
            self._broken = True
            return None
        except psycopg2.Error as e:
            logger.error(f"Error executing returning query: {e}")
            if self.connection:
                self.connection.rollback()
            return None
    
    def execute_values_returning(self, query, params_list):
        """Execute a VALUES-based batch insert with RETURNING and commit"""
        try:
            if not self.connection or self.connection.closed:
                if not self.connect():
                    return None
            
            execute_values(self.cursor, query, params_list)
            results = self.cursor.fetchall()
            self.connection.commit()
            return results
        except psycopg2.OperationalError as e:
            logger.error(f"Error executing values returning query: {e}")
            self._broken = True
            return None
        except psycopg2.Error as e:
            logger.error(f"Error executing values returning query: {e}")
            if self.connection:
                self.connection.rollback()
            return None
    
    def __enter__(self):
        """Context manager entry"""
        self.connect()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.disconnect()

class BreachMonitorDatabaseConnection(DatabaseConnection):
    """Database connection manager that targets the breach-monitor database.

    All behaviour is identical to DatabaseConnection; the only difference is
    that it connects using BREACH_MONITOR_DB_CONFIG, which points at the database
    named by the DB_NAME_BREACHES environment variable (defaults to DB_NAME
    when the variable is unset so single-database local environments keep
    working without extra configuration).
    """

    _POOL_KEY = "breach-monitor"
    _DB_CONFIG = BREACH_MONITOR_DB_CONFIG


def test_connection():
    """Test database connection"""
    with DatabaseConnection() as db:
        if db.connection:
            result = db.execute_single_query("SELECT version();")
            if result:
                logger.info(f"Database connection successful. PostgreSQL version: {result['version']}")
                return True
        return False 
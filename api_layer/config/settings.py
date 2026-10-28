import os
from datetime import timedelta
from urllib.parse import quote_plus

import psycopg2
from dotenv import load_dotenv

load_dotenv()


def _build_database_url(
    user: str | None,
    password: str | None,
    host: str | None,
    port: str | None,
    name: str | None,
) -> str:
    """Build a PostgreSQL URI with URL-encoded credentials (usernames or passwords may contain @ or other reserved characters)."""
    safe_user = quote_plus(user or "")
    safe_password = quote_plus(password or "")
    safe_host = host or "localhost"
    safe_port = port or "5432"
    safe_name = name or ""
    if password:
        return f"postgresql://{safe_user}:{safe_password}@{safe_host}:{safe_port}/{safe_name}"
    return f"postgresql://{safe_user}@{safe_host}:{safe_port}/{safe_name}"


def get_db_connection_params() -> dict:
    """Connection kwargs for psycopg2; avoids URI parsing issues with reserved characters in credentials."""
    port_raw = os.getenv("DB_PORT") or "5432"
    try:
        port = int(port_raw)
    except (TypeError, ValueError):
        port = 5432
    return {
        "host": os.getenv("DB_HOST"),
        "port": port,
        "database": os.getenv("DB_NAME"),
        "user": os.getenv("DB_USER"),
        "password": os.getenv("DB_PASSWORD") or None,
        "connect_timeout": 10,
    }


def get_db_connection():
    """Open a PostgreSQL connection using DB_* env vars when available."""
    params = get_db_connection_params()
    if params["host"] and params["database"] and params["user"]:
        return psycopg2.connect(**params)
    config = get_config()
    return psycopg2.connect(config.DATABASE_URL)


class APIConfig:
    """Configuration settings for the Vendiant API Layer"""
    
    # Database Configuration - Build URL from individual components
    DB_HOST = os.getenv('DB_HOST')
    DB_PORT = os.getenv('DB_PORT')
    DB_NAME = os.getenv('DB_NAME')
    DB_USER = os.getenv('DB_USER')
    DB_PASSWORD = os.getenv('DB_PASSWORD')
    
    # Construct DATABASE_URL from components or use provided URL
    DATABASE_URL = os.getenv('DATABASE_URL') or _build_database_url(
        DB_USER, DB_PASSWORD, DB_HOST, DB_PORT, DB_NAME
    )
    
    # API Configuration
    API_VERSION = 'v1'
    API_PREFIX = f'/api/{API_VERSION}'
    
    # Backend Integration
    BACKEND_API_URL = os.getenv('BACKEND_API_URL', 'http://localhost:5005')
    
    # Authentication Configuration
    API_KEY_PREFIX = 'vnd_'
    API_KEY_LENGTH = 32  # 32-character key after prefix
    HASH_ALGORITHM = 'argon2'  # Using Argon2 for secure password hashing
    
    # Rate Limiting Configuration (Scope-based)
    READ_ONLY_RATE_LIMIT = 50  # requests per minute for read_only scope
    ADMIN_RATE_LIMIT = 50     # requests per minute for admin scope
    RATE_LIMIT_WINDOW = timedelta(minutes=1)  # 1 minute window
    
    # API Key Expiry Configuration
    READ_ONLY_KEY_EXPIRY_DAYS = 50  # Read-only keys expire in 30 days
    ADMIN_KEY_EXPIRY_DAYS = 50      # Admin keys expire in 90 days
    
    # Legacy configuration (deprecated)
    DEFAULT_RATE_LIMIT = 50    # fallback to read_only limit
    BURST_LIMIT = 10           # reduced burst limit
    
    # Security Configuration
    REQUIRE_HTTPS = os.getenv('REQUIRE_HTTPS', 'false').lower() == 'true'
    ALLOWED_ORIGINS = os.getenv('ALLOWED_ORIGINS', '*').split(',')
    
    # Audit Configuration
    ENABLE_AUDIT_LOGGING = True
    AUDIT_LOG_RETENTION_DAYS = 90
    
    # Cache Configuration
    CACHE_TTL = 300  # 5 minutes
    ENABLE_CACHING = True
    
    # Pagination Configuration
    DEFAULT_PAGE_SIZE = 50
    MAX_PAGE_SIZE = 1000
    
    # API Key Expiration
    DEFAULT_API_KEY_EXPIRY_DAYS = 30
    
    # Slack Health Check
    SLACK_HEALTH_CHECK_WEBHOOK_URL = os.getenv('SLACK_HEALTH_CHECK_WEBHOOK_URL', '')

    # Logging Configuration
    LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')
    LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    
    # CORS Configuration - explicit origins only (never use "*"); main.py sets allow_credentials=False
    CORS_ORIGINS = [
        o.strip()
        for o in os.getenv(
            "CORS_ORIGINS",
            "http://localhost:3005,http://localhost:8081",
        ).split(",")
        if o.strip()
    ]
    CORS_METHODS = ["GET", "POST", "DELETE", "OPTIONS"]
    CORS_HEADERS = ["Content-Type", "X-API-Key", "Authorization"]

# Environment-specific configurations
class DevelopmentConfig(APIConfig):
    DEBUG = True
    REQUIRE_HTTPS = False

class ProductionConfig(APIConfig):
    DEBUG = False
    REQUIRE_HTTPS = True

class TestingConfig(APIConfig):
    DEBUG = True
    TESTING = True
    DATABASE_URL = os.getenv('TEST_DATABASE_URL', 'postgresql://localhost:5432/vendiant_test')

# Configuration mapping
config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}

def get_config():
    """Get configuration based on environment"""
    # Check multiple environment variables for better detection
    env = os.getenv('PYTHONENV') or os.getenv('FLASK_ENV') or os.getenv('ENVIRONMENT', 'default')
    return config.get(env, config['default']) 
from fastapi import FastAPI, HTTPException, Depends, Request, Response, status
from fastapi.exception_handlers import http_exception_handler as _default_http_handler
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, field_validator, ConfigDict
from starlette.background import BackgroundTask
from typing import Optional, Dict, Any, List
import json
import logging
import os
import re
import html
import ipaddress
from datetime import datetime
import uvicorn
from dotenv import load_dotenv
from urllib.parse import quote

# Load environment variables from .env.local first, then .env

load_dotenv('.env')

# Import our modules
from config.settings import get_config
from middleware.fastapi_auth import fastapi_auth
from auth.api_key_manager import resolve_scopes, is_webhook_only_scopes
from middleware.slack_health_notifier import notify_error
from utils.backend_client import make_backend_request, get_all_vendors, get_backend_client, trigger_background_scan_for_domain, get_scan_status_for_domain, BackendAPIError
from routes.breach_monitor_webhook import router as breach_monitor_webhook_router

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

_api_config = get_config()


def _normalize_cors_origins(origins):
    if isinstance(origins, str):
        origins = origins.split(",")
    return [o.strip() for o in origins if o.strip()]


CORS_ALLOWED_ORIGINS = _normalize_cors_origins(_api_config.CORS_ORIGINS)

_runtime_env = os.getenv("PYTHONENV") or os.getenv("FLASK_ENV") or os.getenv("ENVIRONMENT", "default")
if _runtime_env == "production":
    if not all(
        origin.startswith("https://")
        for origin in CORS_ALLOWED_ORIGINS
        if not origin.startswith("http://localhost")
    ):
        raise ValueError("All production CORS origins must use HTTPS")

# Initialize FastAPI app
app = FastAPI(
    title="Vendiant Security API",
    description="External REST API for Vendiant Security Platform - Domain-focused security intelligence",
    version="2.0.0",
    docs_url=None,  # Disabled: expose no public API documentation
    redoc_url=None,  # Disabled: expose no public API documentation
    openapi_url=None  # Disabled: expose no OpenAPI schema
)

# Add CORS middleware: explicit origins only. Keep allow_credentials=False unless a
# cookie/session flow requires it; API keys in X-API-Key do not require credentials mode.
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ALLOWED_ORIGINS,
    allow_credentials=False,
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "X-API-Key", "Authorization"],
)

_TRUSTED_PROXY_NETWORKS: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = [
    # Loopback — local/same-host proxies
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    # Docker/Podman default bridge ranges
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("10.0.0.0/8"),
    # Additional trusted proxy IPs from env (comma-separated), loaded at startup
]

def _load_extra_trusted_proxies() -> None:
    """Extend _TRUSTED_PROXY_NETWORKS from TRUSTED_PROXY_IPS env var at startup."""
    raw = os.getenv("TRUSTED_PROXY_IPS", "")
    for entry in raw.split(","):
        entry = entry.strip()
        if not entry:
            continue
        try:
            _TRUSTED_PROXY_NETWORKS.append(ipaddress.ip_network(entry, strict=False))
        except ValueError:
            logger.warning("TRUSTED_PROXY_IPS: invalid network ignored: %s", entry)

_load_extra_trusted_proxies()


def _is_trusted_proxy(ip_str: str) -> bool:
    """Return True if the connecting socket IP belongs to a trusted proxy network."""
    try:
        addr = ipaddress.ip_address(ip_str)
        return any(addr in net for net in _TRUSTED_PROXY_NETWORKS)
    except ValueError:
        return False


def _is_routable_client_ip(ip_str: str) -> bool:
    """Return True when ip_str looks like a real external client address."""
    try:
        addr = ipaddress.ip_address(ip_str.strip())
    except ValueError:
        return False
    return addr.is_global


def _parse_xff_entries(xff: str) -> list[str]:
    return [entry.strip() for entry in xff.split(",") if entry.strip()]


def _first_public_ip(entries: list[str]) -> Optional[str]:
    for entry in entries:
        if _is_routable_client_ip(entry):
            return entry
    return None


# Cloudflare edge ranges — https://www.cloudflare.com/ips-v4 / ips-v6
_CLOUDFLARE_CIDRS: tuple[str, ...] = (
    "173.245.48.0/20",
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
    "141.101.64.0/18",
    "108.162.192.0/18",
    "190.93.240.0/20",
    "188.114.96.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
    "162.158.0.0/15",
    "104.16.0.0/13",
    "104.24.0.0/14",
    "172.64.0.0/13",
    "131.0.72.0/22",
    "2400:cb00::/32",
    "2606:4700::/32",
    "2803:f800::/32",
    "2405:b500::/32",
    "2405:8100::/32",
    "2a06:98c0::/29",
    "2c0f:f248::/32",
)

_CLOUDFLARE_NETWORKS: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []


def _load_cloudflare_networks() -> None:
    """Load Cloudflare edge IP ranges; extend via CLOUDFLARE_IP_RANGES env."""
    for cidr in _CLOUDFLARE_CIDRS:
        _CLOUDFLARE_NETWORKS.append(ipaddress.ip_network(cidr, strict=False))

    raw = os.getenv("CLOUDFLARE_IP_RANGES", "")
    for entry in raw.split(","):
        entry = entry.strip()
        if not entry:
            continue
        try:
            _CLOUDFLARE_NETWORKS.append(ipaddress.ip_network(entry, strict=False))
        except ValueError:
            logger.warning("CLOUDFLARE_IP_RANGES: invalid network ignored: %s", entry)


_load_cloudflare_networks()


def _is_cloudflare_ip(ip_str: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip_str.strip())
        return any(addr in net for net in _CLOUDFLARE_NETWORKS)
    except ValueError:
        return False


def _request_via_cloudflare(request: Request, peer_ip: str) -> bool:
    """
    True when a Cloudflare edge IP appears in the connection chain.

    Gates the True-Client-IP / leftmost-XFF fallbacks, which clients can inject.
    (CF-Connecting-IP is checked before this — see
    _resolve_client_ip_from_trusted_proxy.)  Only tamper-proof signals are used:
      - TCP peer (direct Cloudflare → app)
      - X-Real-IP when the trusted proxy overwrites it to the immediate upstream
        ($remote_addr at the proxy — a Cloudflare edge IP when CF is in front)

    X-Forwarded-For is NOT used: ingress / load balancer (and most proxies) append rather
    than replace, so a client can pre-inject a Cloudflare IP at position [0].
    """
    if _is_cloudflare_ip(peer_ip):
        return True

    x_real_ip = (request.headers.get("x-real-ip") or "").strip()
    if x_real_ip and _is_cloudflare_ip(x_real_ip):
        return True

    return False


def _resolve_client_ip_from_trusted_proxy(request: Request, peer_ip: str) -> str:
    """
    Resolve the original client IP when the TCP peer is a trusted reverse proxy.

    Cloudflare Tunnel path (production: client → Cloudflare edge → cloudflared
    pod → nginx-router → app):
      0. CF-Connecting-IP — no Cloudflare edge IP ever appears in this chain
         (cloudflared dials out), so X-Real-IP is the cloudflared pod.  The edge
         overwrites CF-Connecting-IP with the real client on every request, so
         it cannot be forged from outside; only reachable here via a trusted peer.

    Cloudflare path (a Cloudflare edge IP is present in the connection chain):
      1. CF-Connecting-IP / True-Client-IP
      2. Leftmost public X-Forwarded-For entry (Cloudflare prepends the client)

    ingress / load balancer path (no Cloudflare edge IP in chain):
      1. X-Real-IP — gateway overwrites this to $remote_addr; cannot be pre-injected
      2. Rightmost X-Forwarded-For entry — the hop the trusted proxy appended
      3. Socket peer for internal hops with only private addresses
    """
    cf_connecting_ip = (request.headers.get("cf-connecting-ip") or "").strip()
    if cf_connecting_ip and _is_routable_client_ip(cf_connecting_ip):
        return cf_connecting_ip

    if _request_via_cloudflare(request, peer_ip):
        for header_name in ("cf-connecting-ip", "true-client-ip"):
            candidate = (request.headers.get(header_name) or "").strip()
            if candidate and _is_routable_client_ip(candidate):
                return candidate

        entries = _parse_xff_entries(request.headers.get("x-forwarded-for", ""))
        left_public = _first_public_ip(entries)
        if left_public:
            return left_public

    x_real_ip = (request.headers.get("x-real-ip") or "").strip()
    if x_real_ip:
        return x_real_ip

    entries = _parse_xff_entries(request.headers.get("x-forwarded-for", ""))
    if entries:
        return entries[-1]

    return peer_ip


def _has_forwarding_header(request: Request) -> bool:
    return any(
        name in request.headers
        for name in ("x-real-ip", "x-forwarded-for", "cf-connecting-ip", "true-client-ip")
    )


def _claimed_forwarded_ip(request: Request) -> Optional[str]:
    for header_name in ("x-real-ip", "cf-connecting-ip", "true-client-ip"):
        value = (request.headers.get(header_name) or "").strip()
        if value:
            return value

    xff = request.headers.get("x-forwarded-for", "")
    entries = _parse_xff_entries(xff)
    return entries[0] if entries else None


@app.middleware("http")
async def reject_spoofed_ip_headers(request: Request, call_next):
    """
    IP forwarding / spoofing guard.

    ingress pods connect from 10.x addresses and append an internal hop as the
    rightmost X-Forwarded-For entry.  Because proxies append rather than replace
    XFF, the leftmost position is client-controlled and must not be trusted.
    Cloudflare-specific headers (CF-Connecting-IP, True-Client-IP) are only
    trusted when a Cloudflare edge IP is seen on the TCP peer or X-Real-IP
    (set by the gateway to the immediate upstream — not forwarded from the client).

    Resolution when the connection comes from a trusted proxy is handled by
    _resolve_client_ip_from_trusted_proxy().

    If the TCP peer is NOT a trusted proxy, any forwarding header was injected
    by the client directly and is treated as a spoofing attempt.
    """
    real_ip = "unknown"
    if request.scope.get("client"):
        real_ip = request.scope["client"][0]
    elif request.client:
        real_ip = request.client.host

    logger.info("[IP] socket peer: %s", real_ip)

    if not _has_forwarding_header(request):
        request.state.ip_spoofing_attempted = False
        request.state.claimed_ip = None
        request.state.real_client_ip = real_ip
        return await call_next(request)

    if _is_trusted_proxy(real_ip):
        client_ip = _resolve_client_ip_from_trusted_proxy(request, real_ip)
        request.state.ip_spoofing_attempted = False
        request.state.claimed_ip = None
        request.state.real_client_ip = client_ip
        logger.info(
            "[IP] trusted proxy %s → client IP resolved as %s (cf-connecting-ip present=%s)",
            real_ip, client_ip, "cf-connecting-ip" in request.headers,
        )
    else:
        claimed = _claimed_forwarded_ip(request)
        request.state.ip_spoofing_attempted = True
        request.state.claimed_ip = claimed
        request.state.real_client_ip = real_ip
        logger.warning(
            "[IP] spoofing attempt from %s: forwarding header claimed %s",
            real_ip, claimed,
        )

    return await call_next(request)


app.include_router(breach_monitor_webhook_router)

# Middleware is registered after include_router, but Starlette runs all
# @app.middleware handlers on every request regardless of router order.
# webhook_only_api_key_guard therefore still applies to the webhook routes above.


@app.middleware("http")
async def webhook_only_api_key_guard(request: Request, call_next):
    """
    Keys with only the ``webhook`` scope may call POST /vendiant/webhooks/* and nothing else.
    """
    api_key = (request.headers.get("X-API-Key") or "").strip()
    if not api_key:
        auth = (request.headers.get("Authorization") or "").strip()
        if auth.lower().startswith("bearer "):
            candidate = auth[7:].strip()
            if candidate.startswith("vnd_"):
                api_key = candidate

    if api_key:
        credential = fastapi_auth.api_key_manager.validate_api_key(api_key)
        if credential and is_webhook_only_scopes(resolve_scopes(credential)):
            path = request.url.path
            if not path.startswith("/vendiant/webhooks/"):
                return JSONResponse(
                    status_code=status.HTTP_403_FORBIDDEN,
                    content={
                        "detail": "This API key is restricted to webhook endpoints only",
                    },
                )

    return await call_next(request)


# Security middleware to add security headers
@app.middleware("http")
async def cache_request_body_middleware(request: Request, call_next):
    """
    Read and cache the request body, then replay it so downstream route
    handlers can still parse it (consuming the ASGI receive stream would
    otherwise leave FastAPI with an empty body).
    """
    body_bytes = await request.body()

    # Replay the body for downstream consumers
    async def replay_receive():
        return {"type": "http.request", "body": body_bytes, "more_body": False}
    request._receive = replay_receive

    try:
        request.state.request_body = json.loads(body_bytes) if body_bytes else None
    except Exception:
        request.state.request_body = None

    return await call_next(request)


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    """Add security headers to all responses"""
    response = await call_next(request)

    # Security headers
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"

    return response

def _client_ip(request: Request) -> str:
    """Return the resolved client IP from reject_spoofed_ip_headers middleware state."""
    return getattr(request.state, "real_client_ip", None) or (
        request.client.host if request.client else "unknown"
    )


_EXPECTED_404_PATHS = (
    "/vendiant/domain/",  # score / report lookups before a vendor is fully onboarded
)

_SLACK_SUPPRESSED_PATH_PREFIXES = (
    "/vendiant/webhooks/",
)

def _is_expected_404(status_code: int, path: str) -> bool:
    """
    Returns True when a 404 is the normal/expected outcome — e.g. a domain
    score or report lookup that fires before a newly-added vendor has been
    indexed.  These should not generate a Slack alert.
    """
    if status_code != 404:
        return False
    return any(path.startswith(prefix) for prefix in _EXPECTED_404_PATHS)


@app.exception_handler(HTTPException)
async def http_exception_slack_handler(request: Request, exc: HTTPException):
    """Return the error response immediately; notify Slack in the background.

    404s on domain-lookup paths are suppressed because they are expected
    while a newly-added vendor is being onboarded (the vendor exists but has
    no scan data yet, or the request races the creation).
    """
    detail = exc.detail
    error_detail_str = json.dumps({"detail": detail})
    body = {"detail": detail}

    path = str(request.url.path)
    if _is_expected_404(exc.status_code, path):
        logger.info(
            "Suppressing Slack notification for expected 404 on %s %s",
            request.method,
            path,
        )
        return JSONResponse(status_code=exc.status_code, content=body)

    if any(path.startswith(prefix) for prefix in _SLACK_SUPPRESSED_PATH_PREFIXES):
        return JSONResponse(status_code=exc.status_code, content=body)

    bg = BackgroundTask(
        notify_error,
        method=request.method,
        path=path,
        status_code=exc.status_code,
        client_ip=getattr(request.state, "real_client_ip", None) or (request.client.host if request.client else "unknown"),
        error_detail=error_detail_str,
        request_body=getattr(request.state, "request_body", None),
        ip_spoofing_attempted=getattr(request.state, "ip_spoofing_attempted", False),
        claimed_ip=getattr(request.state, "claimed_ip", None),
    )
    return JSONResponse(status_code=exc.status_code, content=body, background=bg)


def _json_safe_validation_detail(exc: RequestValidationError) -> list:
    """Build 422 detail list safe for JSONResponse. Pydantic v2 may put exception
    instances (e.g. ValueError from field_validator) in ctx — they are not JSON-serializable."""
    stripped = [
        {k: v for k, v in e.items() if k != "input" and k != "url"}
        for e in exc.errors()
    ]
    return json.loads(json.dumps(stripped, default=str))


@app.exception_handler(RequestValidationError)
async def validation_exception_slack_handler(request: Request, exc: RequestValidationError):
    """Pydantic / query-param validation failures — 422."""
    errors = _json_safe_validation_detail(exc)
    try:
        error_detail_str = json.dumps({"detail": errors})
    except Exception:
        error_detail_str = json.dumps({"detail": str(exc)})
    bg = BackgroundTask(
        notify_error,
        method=request.method,
        path=str(request.url.path),
        status_code=422,
        client_ip=getattr(request.state, "real_client_ip", None) or (request.client.host if request.client else "unknown"),
        error_detail=error_detail_str,
        request_body=getattr(request.state, "request_body", None),
        ip_spoofing_attempted=getattr(request.state, "ip_spoofing_attempted", False),
        claimed_ip=getattr(request.state, "claimed_ip", None),
    )
    return JSONResponse(status_code=422, content={"detail": errors}, background=bg)


@app.exception_handler(Exception)
async def unhandled_exception_slack_handler(request: Request, exc: Exception):
    """Catch-all for unexpected 500s."""
    msg = str(exc)
    error_detail_str = json.dumps({"detail": f"Unhandled error: {msg}"})
    bg = BackgroundTask(
        notify_error,
        method=request.method,
        path=str(request.url.path),
        status_code=500,
        client_ip=getattr(request.state, "real_client_ip", None) or (request.client.host if request.client else "unknown"),
        error_detail=error_detail_str,
        request_body=getattr(request.state, "request_body", None),
        ip_spoofing_attempted=getattr(request.state, "ip_spoofing_attempted", False),
        claimed_ip=getattr(request.state, "claimed_ip", None),
    )
    logger.error("Unhandled exception on %s %s: %s", request.method, request.url.path, msg)
    return JSONResponse(
        status_code=500,
        # Details go to the log and the alert, never to the caller (VND-007).
        content={"detail": "Internal server error"},
        background=bg,
    )


# Initialize services
config = get_config()
backend_client = get_backend_client()

# Pydantic models
class Vendor(BaseModel):
    id: Optional[int] = Field(None, description="Vendor ID")
    domain: Optional[str] = Field(None, description="Vendor domain")
    name: Optional[str] = Field(None, description="Vendor name")

class DomainScore(BaseModel):
    domain: str = Field(..., description="Domain name")
    overall_risk_score: float = Field(..., description="Overall security risk score (0-950)")
    risk_level: str = Field(..., description="Risk level: Critical, High, Medium, Low")
    vendor_name: Optional[str] = Field(None, description="Associated vendor name")
    last_updated: Optional[str] = Field(None, description="Last score update timestamp")
    scan_status: Optional[Dict[str, Any]] = Field(None, description="Current scan status and progress")

class DomainReport(BaseModel):
    domain: str = Field(..., description="Domain name")
    overall_risk_score: float = Field(..., description="Overall security risk score")
    risk_level: str = Field(..., description="Risk level assessment")
    vendor_info: Dict[str, Any] = Field(..., description="Vendor information")
    category_scores: Optional[Dict[str, Any]] = Field(None, description="Category-wise detailed scores")
    scan_summary: Dict[str, int] = Field(..., description="Summary of scan results by severity")
    subdomain_count: int = Field(0, description="Total number of subdomains discovered")
    scan_format: Optional[str] = Field(None, description="Type of scan: full_scan_all, new_vendor, full_scan_single, or individual_scan")
    scan_timestamp: Optional[str] = Field(None, description="Timestamp of the last scan")
    generated_at: str = Field(..., description="Report generation timestamp")
    scan_status: Optional[Dict[str, Any]] = Field(None, description="Current scan status and progress")

class DomainScan(BaseModel):
    status: str = Field(..., description="Scan status: success or error")
    job_id: str = Field(..., description="Background scan job ID")
    message: str = Field(..., description="Status message")
    domain: str = Field(..., description="Domain being scanned")
    include_subdomains: bool = Field(..., description="Whether subdomains are included in scan")

class NewVendor(BaseModel):

    name: str = Field(..., min_length=1, max_length=255, description="Vendor name")
    domain: str = Field(..., min_length=3, max_length=253, description="Vendor domain (required)")
    
    @field_validator('name')
    @classmethod
    def validate_name(cls, v):
        if not v or not v.strip():
            raise ValueError('Vendor name cannot be empty')
        # Sanitize and validate name
        sanitized = html.escape(v.strip())
        # Check for log injection patterns (newlines, carriage returns)
        if re.search(r'[\r\n]', sanitized):
            raise ValueError('Vendor name contains invalid characters (log injection prevention)')
        # Allow only alphanumeric, spaces, hyphens, underscores, and basic punctuation
        if not re.match(r'^[a-zA-Z0-9\s\-_.,&()]+$', sanitized):
            raise ValueError('Vendor name contains invalid characters')
        return sanitized
    
    @field_validator('domain')
    @classmethod
    def validate_domain(cls, v):
        if not v or not v.strip():
            raise ValueError('Domain cannot be empty')
        
        domain = v.strip().lower()
        
        # Basic domain format validation
        domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$'
        if not re.match(domain_pattern, domain):
            raise ValueError('Invalid domain format')
        
        # Check for suspicious patterns
        suspicious_patterns = [
            r'[<>"\']',  # HTML/XSS characters
            r'[;|&`$]',  # Command injection characters
            r'\s',       # Whitespace
            r'\.\./',    # Directory traversal
            r'[{}]',     # Template injection
        ]
        
        for pattern in suspicious_patterns:
            if re.search(pattern, domain):
                raise ValueError('Domain contains invalid characters')
        
        # Length validation (DNS limit is 253 characters)
        if len(domain) > 253:
            raise ValueError('Domain name too long')
        
        return domain

class APIResponse(BaseModel):
    status: str = Field(..., description="Response status: success or error")
    message: Optional[str] = Field(None, description="Response message")
    data: Optional[Any] = Field(None, description="Response data")
    meta: Optional[Dict[str, Any]] = Field(None, description="Response metadata")

# Authentication dependencies
async def verify_api_key(request: Request):
    return await fastapi_auth.verify_api_key(request)

# Per-route scope dependencies
scope_vendors_list   = fastapi_auth.require_scope("vendors:list")
scope_vendors_read   = fastapi_auth.require_scope("vendors:read")
scope_reports_read   = fastapi_auth.require_scope("reports:read")
scope_vendors_add    = fastapi_auth.require_scope("vendors:add")
scope_vendors_delete = fastapi_auth.require_scope("vendors:delete")
scope_scans_run      = fastapi_auth.require_scope("scans:run")

# Legacy aliases (used by routes below — swapped to scoped deps)
require_read_access  = scope_vendors_list
require_admin_access = scope_vendors_add

# Helper function to add rate limit headers to responses
def add_rate_limit_headers(response, credential_id: int):
    """Add rate limit headers to response"""
    try:
        rate_info = fastapi_auth.api_key_manager.get_rate_limit_info(credential_id)
        response.headers["X-RateLimit-Limit"] = str(rate_info['requests_per_minute'])
        response.headers["X-RateLimit-Remaining"] = str(rate_info['remaining'])
        response.headers["X-RateLimit-Reset"] = str(rate_info['reset_time'])
        response.headers["X-RateLimit-Scope"] = rate_info['scope']
    except Exception as e:
        logger.warning(f"Failed to add rate limit headers: {e}")
    return response

# Input validation and sanitization functions
def validate_domain_parameter(domain: str, client_ip: str = "unknown") -> str:
    """
    Validate and sanitize domain path parameter
    Prevents path traversal, command injection, and other attacks
    """
    if not domain or not isinstance(domain, str):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Domain parameter is required"
        )
    
    # Remove whitespace and convert to lowercase
    domain = domain.strip().lower()
    
    # Length validation
    if len(domain) < 3 or len(domain) > 253:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Domain length must be between 3 and 253 characters"
        )
    
    # Domain format validation (strict RFC compliant)
    domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$'
    if not re.match(domain_pattern, domain):
        # Log invalid domain format attempts
        logger.warning(f"SECURITY: Invalid domain format attempted - Domain: '{domain}', Client IP: {client_ip}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid domain format"
        )
    
    # Check for malicious patterns
    malicious_patterns = [
        r'[<>"\']',     # XSS characters
        r'[;|&`$]',     # Command injection
        r'\.\./',       # Directory traversal
        r'[{}]',        # Template injection
        r'[\r\n]',      # Log injection
        r'[%]',         # URL encoding attempts
        r'[\\]',        # Path separators
        r'/\*.*\*/',    # SQL comment blocks
        r'#',           # SQL/Script comments
        r'@',           # Email-like patterns
        r'\?',          # Query parameters
        r'script',      # Script tags (case insensitive)
        r'javascript:', # JavaScript protocol
        r'[^\x00-\x7F]', # Non-ASCII characters (Unicode attacks)
        r'\x00',        # Null bytes
    ]
    
    for pattern in malicious_patterns:
        # Use case-insensitive matching for script-related patterns
        flags = re.IGNORECASE if 'script' in pattern or 'javascript' in pattern else 0
        if re.search(pattern, domain, flags):
            # Log suspicious domain input for security monitoring
            logger.warning(f"SECURITY: Malicious domain pattern detected - Domain: '{domain}', Pattern: '{pattern}', Client IP: {client_ip}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Domain contains invalid characters"
            )
    
    return domain

def safe_url_encode_domain(domain: str) -> str:
    """
    Safely URL encode domain for use in backend requests
    Prevents URL injection attacks
    """
    # Additional validation before URL encoding
    if not domain or len(domain) > 253:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid domain for URL encoding"
        )
    
    # URL encode the domain to prevent URL injection
    encoded_domain = quote(domain, safe='.-')
    
    # Verify the encoded domain is still reasonable length
    if len(encoded_domain) > 300:  # Allow some overhead for encoding
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Domain too complex for safe URL encoding"
        )
    
    return encoded_domain

def sanitize_string_input(value: str, max_length: int = 255, field_name: str = "input") -> str:
    """
    Sanitize string input to prevent XSS and other injection attacks
    """
    if not value:
        return ""
    
    # HTML escape to prevent XSS
    sanitized = html.escape(value.strip())
    
    # Length validation
    if len(sanitized) > max_length:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"{field_name} exceeds maximum length of {max_length} characters"
        )
    
    return sanitized

def validate_ip_address(ip_str: str) -> str:
    """
    Validate IP address format and reject private/loopback ranges to prevent log poisoning.
    """
    try:
        ip_obj = ipaddress.ip_address(ip_str.strip())
        if ip_obj.is_private or ip_obj.is_loopback:
            return "x-forwarded-ip"
        return str(ip_obj)
    except ValueError:
        return "x-forwarded-ip"

# Helper functions
def get_client_ip(request: Request) -> str:
    """Extract client IP address from middleware-resolved request state."""
    return _client_ip(request)



def determine_risk_level(score: float) -> str:
    """Determine risk level from score"""
    if score >= 800:
        return "Low"
    elif score >= 600:
        return "Medium"
    elif score >= 400:
        return "High"
    else:
        return "Critical"

# Root endpoint
# @app.get("/", response_model=APIResponse)
# async def root():
#     """API root endpoint with basic information"""
#     return APIResponse(
#         status="success",
#         message="Vendiant Security API v2.0 - Domain-focused security intelligence",
#         data={
#             "api_version": "2.0.0",
#             "documentation": "/vendiant/docs",
#             "endpoints": {
#                 "vendors_list": "/vendiant/vendors",
#                 "domain_score": "/vendiant/domain/{domain}/score",
#                 "domain_report": "/vendiant/domain/{domain}/report",
#                 "add_vendor": "/vendiant/vendor",
#                 "delete_vendor": "/vendiant/domain/{domain}"
#             }
#         }
#     )

# Health check
@app.get("/vendiant/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "service": "vendiant-api", "timestamp": datetime.now().isoformat()}


# 1. GET endpoint to fetch the list of vendors
@app.get("/vendiant/vendors", response_model=List[Vendor])
async def get_vendors(
    request: Request,
    response: Response,
    credential: dict = Depends(scope_vendors_list)
):
    """
    Get list of all vendors
    
    Returns a list of all vendors in the system with their basic information.
    """
    try:
        # Get client IP address and user agent
        client_ip = get_client_ip(request)
        user_agent = sanitize_string_input(request.headers.get("user-agent", "Unknown"), 500, "user-agent")
        
        # Refresh cache to get latest data
        
        # Get all vendors
        vendors = get_all_vendors()
        
        vendor_list = []
        for vendor in vendors:
            vendor_obj = Vendor(
                id=vendor.get('id'),
                domain=vendor.get('domain'),
                name=vendor.get('name')
            )
            vendor_list.append(vendor_obj)
        
        # Log successful request
        fastapi_auth.audit_logger.log_request(
            credential_id=credential['id'],
            key_name=credential.get('name'),
            endpoint_path="/vendiant/vendors",
            http_method="GET",
            client_ip=client_ip,
            user_agent=user_agent,
            success=True,
            response_code=200,
            request_data={"query_params": dict(request.query_params)}
        )
        
        # Add rate limit headers
        add_rate_limit_headers(response, credential['id'])
        
        return vendor_list
        
    except Exception as e:
        logger.error(f"Error getting vendors list: {str(e)}")
        fastapi_auth.audit_logger.log_request(
            credential_id=credential['id'],
            key_name=credential.get('name'),
            endpoint_path="/vendiant/vendors",
            http_method="GET",
            client_ip=client_ip,
            user_agent=user_agent,
            success=False,
            response_code=500
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error while retrieving vendors list"
        )

# 2. GET endpoint to fetch the overall risk score of a domain
@app.get("/vendiant/domain/{domain}/score", response_model=DomainScore)
async def get_domain_score(
    domain: str,
    request: Request,
    response: Response,
    credential: dict = Depends(scope_vendors_read)
):
    """
    Get overall security risk score for a domain
    
    Returns the overall security risk score (0-950) for the specified domain.
    Higher scores indicate better security posture.
    """
    try:
        # Get client IP address and user agent first for security logging
        client_ip = get_client_ip(request)
        user_agent = sanitize_string_input(request.headers.get("user-agent", "Unknown"), 500, "user-agent")
        
        # Validate and sanitize domain parameter
        domain = validate_domain_parameter(domain, client_ip)
        
       
        # Get all vendors and find by domain
        vendors = get_all_vendors()
        vendor = None
        
        if vendors and isinstance(vendors, list):
            # Try exact match first
            for v in vendors:
                if isinstance(v, dict):
                    vendor_domain = v.get('domain', '')
                    if isinstance(vendor_domain, str) and vendor_domain.lower() == domain.lower():
                        vendor = v
                        break
            
            # Try partial match if exact match fails
            if not vendor:
                for v in vendors:
                    if isinstance(v, dict):
                        vendor_domain = v.get('domain', '')
                        if isinstance(vendor_domain, str) and domain.lower() in vendor_domain.lower():
                            vendor = v
                            break
        
        if not vendor:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"No vendor found for domain: {domain}"
            )
        
        security_score = vendor.get('securityScore', 0)
        risk_level = determine_risk_level(security_score)
        
        # Get scan status for the domain
        scan_status = get_scan_status_for_domain(domain)
        
        # Log successful request
        fastapi_auth.audit_logger.log_request(
            credential_id=credential['id'],
            key_name=credential.get('name'),
            endpoint_path=f"/vendiant/domain/{domain}/score",
            http_method="GET",
            client_ip=client_ip,
            user_agent=user_agent,
            success=True,
            response_code=200,
            request_data={"domain": domain, "query_params": dict(request.query_params)}
        )
        
        # Add rate limit headers
        add_rate_limit_headers(response, credential['id'])
        
        return DomainScore(
            domain=domain,
            overall_risk_score=security_score,
            risk_level=risk_level,
            vendor_name=vendor.get('name'),
            last_updated=vendor.get('lastScan'),
            scan_status=scan_status
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting domain score for {domain}: {str(e)}")
        fastapi_auth.audit_logger.log_request(
            credential_id=credential['id'],
            key_name=credential.get('name'),
            endpoint_path=f"/vendiant/domain/{domain}/score",
            http_method="GET",
            client_ip=client_ip,
            user_agent=user_agent,
            success=False,
            response_code=500
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error while retrieving domain score"
        )

# 2.5. GET endpoint to get vendor name by domain

# 3. GET endpoint for getting the report of the domain
@app.get("/vendiant/domain/{domain}/report", response_model=DomainReport)
async def get_domain_report(
    domain: str,
    request: Request,
    response: Response,
    credential: dict = Depends(scope_reports_read)
):
    """
    Get comprehensive security report for a domain
    
    Returns detailed security analysis including vulnerabilities, network security,
    encryption status, and domain reputation for the specified domain.
    """
    try:
        # Get client IP address and user agent first for security logging
        client_ip = get_client_ip(request)
        user_agent = sanitize_string_input(request.headers.get("user-agent", "Unknown"), 500, "user-agent")
        
        # Validate and sanitize domain parameter
        domain = validate_domain_parameter(domain, client_ip)
        
        # Get all vendors and find by domain
        vendors = get_all_vendors()
        vendor = None
        
        if vendors and isinstance(vendors, list):
            # Try exact match first
            for v in vendors:
                if isinstance(v, dict):
                    vendor_domain = v.get('domain', '')
                    if isinstance(vendor_domain, str) and vendor_domain.lower() == domain.lower():
                        vendor = v
                        break
            
            # Try partial match if exact match fails
            if not vendor:
                for v in vendors:
                    if isinstance(v, dict):
                        vendor_domain = v.get('domain', '')
                        if isinstance(vendor_domain, str) and domain.lower() in vendor_domain.lower():
                            vendor = v
                            break
        
        if not vendor:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"No vendor found for domain: {domain}"
            )
        
        # Get vendor ID for fetching comprehensive report
        vendor_id = vendor.get('id')
        
        # Use backend client to get comprehensive report with all category scores
        report = await backend_client.get_vendor_report(vendor_id)
        
        if not report:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to retrieve comprehensive report for domain: {domain}"
            )
        
        # Extract data from backend client response
        security_score = report.get('overall_risk_score', 0)
        risk_level = report.get('risk_level', determine_risk_level(security_score))
        
        # Get scan status for the domain
        scan_status = get_scan_status_for_domain(domain)
        
        # Log successful request
        fastapi_auth.audit_logger.log_request(
            credential_id=credential['id'],
            key_name=credential.get('name'),
            endpoint_path=f"/vendiant/domain/{domain}/report",
            http_method="GET",
            client_ip=client_ip,
            user_agent=user_agent,
            success=True,
            response_code=200
        )
        
        # Add rate limit headers
        add_rate_limit_headers(response, credential['id'])
        
        return DomainReport(
            domain=domain,
            overall_risk_score=security_score,
            risk_level=risk_level,
            vendor_info={
                'id': vendor.get('id'),
                'name': vendor.get('name'),
                'domain': vendor.get('domain'),
                'grade': vendor.get('grade'),
                'tier': vendor.get('tier'),
                'industry': vendor.get('industry')
            },
            category_scores=report.get('category_scores', {}),
            scan_summary=report.get('scan_summary', {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Info': 0}),
            subdomain_count=report.get('subdomain_count', 0),
            scan_format=report.get('scan_format'),
            scan_timestamp=report.get('scan_timestamp'),
            generated_at=datetime.now().isoformat(),
            scan_status=scan_status
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting domain report for {domain}: {str(e)}")
        fastapi_auth.audit_logger.log_request(
            credential_id=credential['id'],
            key_name=credential.get('name'),
            endpoint_path=f"/vendiant/domain/{domain}/report",
            http_method="GET",
            client_ip=client_ip,
            user_agent=user_agent,
            success=False,
            response_code=500
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error while generating domain report"
        )

# 4. POST endpoint to add a new vendor
@app.post("/vendiant/vendor", response_model=APIResponse)
async def add_vendor(
    new_vendor: NewVendor,
    request: Request,
    response: Response,
    credential: dict = Depends(scope_vendors_add)
):
    """
    Add a new vendor to the system
    
    Creates a new vendor entry with the provided information.
    Domain is required for the vendor.
    """
    logger.info(f"POST /vendiant/vendor called with credential ID: {credential.get('id')}")
    try:
        # Get client IP address and user agent
        client_ip = get_client_ip(request)
        user_agent = sanitize_string_input(request.headers.get("user-agent", "Unknown"), 500, "user-agent")
        
        # Prepare vendor data for backend
        vendor_data = {
            "name": new_vendor.name,
            "domain": new_vendor.domain
        }
        
        # Create vendor using backend client
        created_vendor = await backend_client.create_vendor(vendor_data)
        
        # Trigger automatic background scan for the new domain (main domain only for faster onboarding)
        scan_job_id = None
        try:
            # Use include_subdomains=False for faster new vendor onboarding
            scan_job_id = trigger_background_scan_for_domain(
                new_vendor.domain,
                include_subdomains=False,
                slack_notify_on_complete=True,
            )
            if scan_job_id:
                logger.info(f"Main domain background scan initiated for new vendor {new_vendor.name} (domain: {new_vendor.domain}), job_id: {scan_job_id}")
            else:
                logger.warning(f"Failed to initiate main domain background scan for new vendor {new_vendor.name} (domain: {new_vendor.domain})")
        except Exception as scan_error:
            logger.error(f"Error initiating main domain background scan for {new_vendor.domain}: {scan_error}")
        
        # Log successful request
        fastapi_auth.audit_logger.log_request(
            credential_id=credential['id'],
            key_name=credential.get('name'),
            endpoint_path="/vendiant/vendor",
            http_method="POST",
            client_ip=client_ip,
            user_agent=user_agent,
            success=True,
            response_code=201,
            request_data={
                "vendor_name": new_vendor.name,
                "domain": new_vendor.domain,
                "background_scan_job_id": scan_job_id,
                "background_scan_initiated": scan_job_id is not None,
                "scan_type": "main_domain_only",
                "include_subdomains": False
            }
        )
        
        # Add rate limit headers
        add_rate_limit_headers(response, credential['id'])
        
        # Prepare response with background scan information
        response_data = created_vendor.copy()
        if scan_job_id:
            response_data["background_scan"] = {
                "initiated": True,
                "job_id": scan_job_id,
                "message": "Main domain security scan initiated (subdomains excluded for faster onboarding)",
                "scan_type": "main_domain_only"
            }
            response_message = f"Vendor '{new_vendor.name}' with domain '{new_vendor.domain}' added successfully and main domain scan initiated (job: {scan_job_id})"
        else:
            response_data["background_scan"] = {
                "initiated": False,
                "job_id": None,
                "message": "Main domain background scan could not be initiated",
                "scan_type": "main_domain_only"
            }
            response_message = f"Vendor '{new_vendor.name}' with domain '{new_vendor.domain}' added successfully (main domain scan failed to start)"
        
        return APIResponse(
            status="success",
            message=response_message,
            data=response_data
        )
        
    except HTTPException:
        raise
    except BackendAPIError as e:
        # Forward the backend's own status code and message verbatim
        logger.warning(f"Backend rejected vendor '{new_vendor.name}' ({new_vendor.domain}): [{e.status_code}] {e.detail}")
        fastapi_auth.audit_logger.log_request(
            credential_id=credential['id'],
            key_name=credential.get('name'),
            endpoint_path="/vendiant/vendor",
            http_method="POST",
            client_ip=client_ip,
            user_agent=user_agent,
            success=False,
            response_code=e.status_code
        )
        raise HTTPException(status_code=e.status_code, detail=e.detail)
    except Exception as e:
        logger.error(f"Error adding vendor {new_vendor.name} ({new_vendor.domain}): {str(e)}")
        fastapi_auth.audit_logger.log_request(
            credential_id=credential['id'],
            key_name=credential.get('name'),
            endpoint_path="/vendiant/vendor",
            http_method="POST",
            client_ip=client_ip,
            user_agent=user_agent,
            success=False,
            response_code=500
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to add vendor '{new_vendor.name}' ({new_vendor.domain})"
        )

# 5. DELETE endpoint to delete a vendor by domain
@app.delete("/vendiant/domain/{domain}", response_model=APIResponse)
async def delete_vendor_by_domain(
    domain: str,
    request: Request,
    response: Response,
    credential: dict = Depends(scope_vendors_delete)
):
    """
    Delete a vendor from the system by domain
    
    Removes the vendor associated with the specified domain and all associated data.
    """
    try:
        # Get client IP address and user agent first for security logging
        client_ip = get_client_ip(request)
        user_agent = sanitize_string_input(request.headers.get("user-agent", "Unknown"), 500, "user-agent")
        
        # Validate and sanitize domain parameter
        domain = validate_domain_parameter(domain, client_ip)
        
        # Find vendor by domain first
        vendors = get_all_vendors()
        vendor = None
        vendor_id = None
        
        if vendors and isinstance(vendors, list):
            for v in vendors:
                if isinstance(v, dict):
                    vendor_domain = v.get('domain', '')
                    if isinstance(vendor_domain, str) and vendor_domain.lower() == domain.lower():
                        vendor = v
                        vendor_id = v.get('id')
                        break
        
        if not vendor or not vendor_id:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"No vendor found for domain: {domain}"
            )
        
        # Delete vendor using backend client
        deleted = await backend_client.delete_vendor(vendor_id)
        
        if not deleted:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Vendor with domain '{domain}' not found"
            )
        
        # Log successful request
        fastapi_auth.audit_logger.log_request(
            credential_id=credential['id'],
            key_name=credential.get('name'),
            endpoint_path=f"/vendiant/domain/{domain}",
            http_method="DELETE",
            client_ip=client_ip,
            user_agent=user_agent,
            success=True,
            response_code=200
        )
        
        # Add rate limit headers
        add_rate_limit_headers(response, credential['id'])
        
        return APIResponse(
            status="success",
            message=f"Vendor '{vendor.get('name')}' with domain '{domain}' deleted successfully",
            data={
                "id": vendor_id,
                "name": vendor.get('name'),
                "domain": domain
            }
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting vendor for domain {domain}: {str(e)}")
        fastapi_auth.audit_logger.log_request(
            credential_id=credential['id'],
            key_name=credential.get('name'),
            endpoint_path=f"/vendiant/domain/{domain}",
            http_method="DELETE",
            client_ip=client_ip,
            user_agent=user_agent,
            success=False,
            response_code=500
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error while deleting vendor"
        )

@app.post("/vendiant/domain/{domain}/fullscan", response_model=DomainScan)
async def start_domain_fullscan(
    domain: str,
    request: Request,
    response: Response,
    credential: dict = Depends(scope_scans_run)
):
    """
    Start a comprehensive full scan for a domain including subdomain discovery and all security checks.
    This triggers the same comprehensive scan that runs when adding a vendor through the frontend.
    Subdomain discovery is always included in the scan.
    """
    # Validate and sanitize domain
    try:
        validated_domain = validate_domain_parameter(domain, get_client_ip(request))
    except ValueError as e:
        fastapi_auth.audit_logger.log_request(
            credential_id=credential.get('id', 0),
            endpoint_path=f"/vendiant/domain/{domain}/fullscan",
            http_method="POST",
            client_ip=get_client_ip(request),
            user_agent=request.headers.get("user-agent", "unknown"),
            success=False,
            response_code=400
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid domain parameter: {str(e)}"
        )
    
    # Get client info for audit logging
    client_ip = get_client_ip(request)
    user_agent = request.headers.get("user-agent", "unknown")
    
    try:
        # First check if a scan is already running
        scan_status = get_scan_status_for_domain(validated_domain)
        
        if scan_status.get('scan_active', False):
            # Scan is already running, return current status
            scan_result = {
                'status': 'success',
                'job_id': scan_status.get('job_id'),
                'message': f'Scan is already in progress for {validated_domain}. {scan_status.get("scan_stage_message", "")}',
            }
        else:
            # No active scan, start a new one
            job_id = trigger_background_scan_for_domain(
                domain=validated_domain,
                include_subdomains=True
            )
            
            if job_id:
                scan_result = {
                    'status': 'success',
                    'job_id': job_id,
                    'message': f'Full scan initiated for {validated_domain}. Scan is now running in the background and includes subdomain discovery and all security checks.',
                }
            else:
                scan_result = {
                    'status': 'error',
                    'job_id': None,
                    'message': f'Failed to initiate background scan for {validated_domain}',
                }
        
        # Log successful scan initiation
        fastapi_auth.audit_logger.log_request(
            credential_id=credential.get('id', 0),
            key_name=credential.get('name'),
            endpoint_path=f"/vendiant/domain/{validated_domain}/fullscan",
            http_method="POST",
            client_ip=client_ip,
            user_agent=user_agent,
            success=True,
            response_code=200
        )
        
        # Add rate limiting headers
        add_rate_limit_headers(response, credential.get('credential_id', 0))
        
        return DomainScan(
            status=scan_result.get('status', 'error'),
            job_id=scan_result.get('job_id', ''),
            message=scan_result.get('message', ''),
            domain=validated_domain,
            include_subdomains=True
        )
        
    except Exception as e:
        logger.error(f"Error starting full scan for {validated_domain}: {str(e)}")
        
        # Log failed scan initiation
        fastapi_auth.audit_logger.log_request(
            credential_id=credential.get('id', 0),
            key_name=credential.get('name'),
            endpoint_path=f"/vendiant/domain/{validated_domain}/fullscan",
            http_method="POST",
            client_ip=client_ip,
            user_agent=user_agent,
            success=False,
            response_code=500
        )
        
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to start full scan for {validated_domain}"
        )

if __name__ == "__main__":
    port = int(os.getenv("PORT", 5006))
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=port,
        reload=True,
        log_level="info"
    ) 
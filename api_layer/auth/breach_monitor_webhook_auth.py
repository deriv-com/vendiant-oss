"""
Authentication for Breach Monitor outbound webhooks.

Only fine-grained API keys created in the dashboard with the sole ``webhook`` scope
are accepted (``X-API-Key`` or ``Authorization: Bearer vnd_...``).
"""

from __future__ import annotations

import hashlib
import logging
import threading
import time
from typing import Any, Dict, Mapping, Optional, Tuple

from fastapi import Request, status
from fastapi.responses import JSONResponse

from auth.api_key_manager import (
    APIKeyManager,
    WEBHOOK_SCOPE,
    is_webhook_only_scopes,
    resolve_scopes,
)

logger = logging.getLogger(__name__)

BREACH_MONITOR_WEBHOOK_MAX_BODY_BYTES = 5 * 1024 * 1024  # 5 MiB

_api_key_manager: Optional[APIKeyManager] = None

# Short-lived cache of webhook API-key validation results.
#
# validate_api_key() does a fresh psycopg2 connection + an Argon2id verify
# (time_cost=3, memory_cost=64MB — intentionally expensive) on every call.
# Breach Monitor delivers webhook callbacks in high-volume bursts using the same
# key repeatedly, so without a cache each request pays that full cost. Since
# route handling for this endpoint already runs off the event loop (see
# routes/breach_monitor_webhook.py), this cache mainly cuts DB load and Argon2 CPU
# time under burst traffic rather than event-loop blocking.
#
# Keyed by SHA-256 of the raw key (not the raw key itself) so a copy of the
# key never lingers in process memory longer than necessary.
_WEBHOOK_KEY_CACHE_TTL_SECONDS = 60
_webhook_key_cache: Dict[str, Tuple[bool, float]] = {}
_webhook_key_cache_lock = threading.Lock()


def _cache_digest(api_key: str) -> str:
    return hashlib.sha256(api_key.encode("utf-8")).hexdigest()


def _cache_get(digest: str) -> Optional[bool]:
    now = time.monotonic()
    with _webhook_key_cache_lock:
        cached = _webhook_key_cache.get(digest)
        if cached is None:
            return None
        is_valid, expires_at = cached
        if expires_at <= now:
            del _webhook_key_cache[digest]
            return None
        return is_valid


def _cache_set(digest: str, is_valid: bool) -> None:
    with _webhook_key_cache_lock:
        # Guard against unbounded growth if many distinct/garbage keys are tried.
        if len(_webhook_key_cache) > 1000:
            now = time.monotonic()
            expired = [k for k, (_, exp) in _webhook_key_cache.items() if exp <= now]
            for k in expired:
                del _webhook_key_cache[k]
        _webhook_key_cache[digest] = (is_valid, time.monotonic() + _WEBHOOK_KEY_CACHE_TTL_SECONDS)


def webhook_json_response(
    status_code: int,
    *,
    status_label: str,
    message: Optional[str] = None,
    headers: Optional[Mapping[str, str]] = None,
    **extra: Any,
) -> JSONResponse:
    """Build a Breach Monitor webhook JSON body that always includes ``code`` (HTTP status)."""
    content: Dict[str, Any] = {"status": status_label, "code": status_code}
    if message is not None:
        content["message"] = message
    content.update(extra)
    return JSONResponse(
        status_code=status_code,
        content=content,
        headers=dict(headers) if headers else None,
    )


def _manager() -> APIKeyManager:
    global _api_key_manager
    if _api_key_manager is None:
        _api_key_manager = APIKeyManager()
    return _api_key_manager


def _unauthorized_response() -> JSONResponse:
    return webhook_json_response(
        status.HTTP_401_UNAUTHORIZED,
        status_label="error",
        message="Unauthorized",
        headers={"WWW-Authenticate": "Bearer"},
    )


def _validate_webhook_api_key(api_key: str) -> bool:
    digest = _cache_digest(api_key)
    cached = _cache_get(digest)
    if cached is not None:
        return cached

    credential = _manager().validate_api_key(api_key)
    if not credential:
        _cache_set(digest, False)
        return False

    scopes = resolve_scopes(credential)
    if not is_webhook_only_scopes(scopes):
        logger.warning(
            "API key %s rejected for webhook: requires only '%s' scope, has %s",
            credential.get("id"),
            WEBHOOK_SCOPE,
            scopes,
        )
        _cache_set(digest, False)
        return False

    _cache_set(digest, True)
    return True


def _extract_api_key_from_request(request: Request) -> Optional[str]:
    header_key = (request.headers.get("X-API-Key") or "").strip()
    if header_key:
        return header_key

    auth_header = (request.headers.get("Authorization") or "").strip()
    if auth_header.lower().startswith("bearer "):
        token = auth_header[7:].strip()
        if token.startswith("vnd_"):
            return token
    return None


def verify_breach_monitor_webhook_request(request: Request, body: bytes) -> JSONResponse | None:
    """
    Validate webhook auth and body size.

    Returns a JSONResponse on failure, or None when the request may proceed.
    """
    if len(body) > BREACH_MONITOR_WEBHOOK_MAX_BODY_BYTES:
        return webhook_json_response(
            status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            status_label="error",
            message="Request body too large",
        )

    api_key = _extract_api_key_from_request(request)
    if api_key and _validate_webhook_api_key(api_key):
        return None

    if api_key:
        logger.warning(
            "Breach Monitor webhook: invalid or non-webhook API key from %s",
            request.client.host if request.client else "unknown",
        )
    else:
        logger.warning(
            "Breach Monitor webhook auth failed (missing API key) from %s",
            request.client.host if request.client else "unknown",
        )

    return _unauthorized_response()

"""
Public Breach Monitor webhook endpoint (internet-facing via nginx /vendiant/).
"""

from __future__ import annotations

import asyncio
import json
import logging

from fastapi import APIRouter, Request, status
from fastapi.responses import JSONResponse

from auth.breach_monitor_webhook_auth import verify_breach_monitor_webhook_request, webhook_json_response
from utils.backend_client import BackendAPIError, get_backend_client

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/vendiant/webhooks", tags=["webhooks"])


@router.post("/breach-monitor")
async def breach_monitor_webhook(request: Request) -> JSONResponse:
    """
    Receive breach platform alert callbacks.

    Returns HTTP 200 when the alert payload is accepted and persisted; any other
    status signals Breach Monitor to retry delivery.

    Authentication: dashboard API key with **only** the ``webhook`` scope
    (create under Settings → API Keys → Breach Monitor webhook only):
    ``X-API-Key: vnd_...`` or ``Authorization: Bearer vnd_...``
    """
    body = await request.body()
    # verify_breach_monitor_webhook_request does a synchronous DB round-trip + Argon2id
    # verify (see auth/breach_monitor_webhook_auth.py). Run it off the event loop so a
    # burst of webhook deliveries can't serialize behind each other and stall
    # every other in-flight request on this single-worker process.
    auth_error = await asyncio.to_thread(verify_breach_monitor_webhook_request, request, body)
    if auth_error is not None:
        return auth_error

    if not body:
        return webhook_json_response(
            status.HTTP_400_BAD_REQUEST,
            status_label="error",
            message="Empty request body",
        )

    try:
        payload = json.loads(body)
    except json.JSONDecodeError:
        return webhook_json_response(
            status.HTTP_400_BAD_REQUEST,
            status_label="error",
            message="Invalid JSON body",
        )

    client = get_backend_client()
    try:
        summary = await client.process_breach_monitor_webhook(payload)
        if not isinstance(summary, dict):
            summary = {}
        status_label = str(summary.get("status", "ok"))
        result_fields = {k: v for k, v in summary.items() if k not in ("status", "code")}
        return webhook_json_response(
            status.HTTP_200_OK,
            status_label=status_label,
            **result_fields,
        )
    except BackendAPIError as exc:
        logger.error(
            "Breach Monitor webhook backend processing failed: [%s] %s",
            exc.status_code,
            exc.detail,
        )
        if exc.status_code >= 500 or exc.status_code == 503:
            from middleware.slack_health_notifier import notify_error

            notify_error(
                "POST",
                "/vendiant/webhooks/breach-monitor",
                exc.status_code,
                client_ip=getattr(request.state, "real_client_ip", None) or (request.client.host if request.client else "unknown"),
                error_detail=str(exc.detail)[:600],
            )
        if 400 <= exc.status_code < 500 and exc.status_code != 503:
            return webhook_json_response(
                exc.status_code,
                status_label="error",
                message=exc.detail,
            )
        return webhook_json_response(
            status.HTTP_500_INTERNAL_SERVER_ERROR,
            status_label="error",
            message="Failed to process webhook",
        )
    except Exception as exc:
        logger.error("Breach Monitor webhook unexpected error: %s", exc)
        from middleware.slack_health_notifier import notify_error

        notify_error(
            "POST",
            "/vendiant/webhooks/breach-monitor",
            status.HTTP_500_INTERNAL_SERVER_ERROR,
            client_ip=getattr(request.state, "real_client_ip", None) or (request.client.host if request.client else "unknown"),
            error_detail=str(exc)[:600],
        )
        return webhook_json_response(
            status.HTTP_500_INTERNAL_SERVER_ERROR,
            status_label="error",
            message="Failed to process webhook",
        )

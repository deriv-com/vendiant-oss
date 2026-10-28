"""
Internal Breach Monitor webhook ingestion (called from the public API layer).
"""

import asyncio
import logging
from typing import Any, Dict

from fastapi import APIRouter, BackgroundTasks, Body, status
from fastapi.responses import JSONResponse

try:
    from Dashboard.breach_monitor_webhook import process_breach_monitor_webhook_payload
except ImportError:
    from breach_monitor_webhook import process_breach_monitor_webhook_payload

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/internal/breach-monitor", tags=["internal-breach-monitor"])


def _internal_webhook_response(
    status_code: int,
    *,
    status_label: str,
    message: str | None = None,
    **extra: Any,
) -> JSONResponse:
    content: Dict[str, Any] = {"status": status_label, "code": status_code}
    if message is not None:
        content["message"] = message
    content.update(extra)
    return JSONResponse(status_code=status_code, content=content)


@router.post("/webhook")
async def ingest_breach_monitor_webhook(
    background_tasks: BackgroundTasks,
    body: Dict[str, Any] = Body(...),
) -> JSONResponse:
    """
    Persist Breach Monitor callback data and fire Slack alerts for new UIDs.
    Not exposed publicly; the API layer proxies authenticated requests here.

    Processing (sync DB upsert) runs in a worker thread via ``asyncio.to_thread``
    so a burst of concurrent webhook deliveries doesn't serialize behind each
    other on the single asyncio event loop; Slack notification is deferred to a
    background task so it happens after the response is already sent.
    """
    try:
        summary = await asyncio.to_thread(
            process_breach_monitor_webhook_payload, body, background_tasks
        )
        return _internal_webhook_response(
            status.HTTP_200_OK,
            status_label="ok",
            **summary,
        )
    except ValueError as exc:
        logger.warning("Breach Monitor webhook rejected: %s", exc)
        return _internal_webhook_response(
            status.HTTP_400_BAD_REQUEST,
            status_label="error",
            message=str(exc),
        )
    except Exception as exc:
        logger.exception("Breach Monitor webhook ingestion failed")
        try:
            from scan_health_notifier import notify_breach_monitor_operation_failure
        except ImportError:
            from Dashboard.scan_health_notifier import notify_breach_monitor_operation_failure

        notify_breach_monitor_operation_failure("Webhook ingestion", str(exc))
        return _internal_webhook_response(
            status.HTTP_500_INTERNAL_SERVER_ERROR,
            status_label="error",
            message="Failed to process Breach Monitor webhook",
        )

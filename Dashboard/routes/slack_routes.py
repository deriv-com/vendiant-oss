import logging
from typing import Any, Dict, Optional
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, field_validator
from slack.slack_service import send_api_audit_log_alert

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/internal/slack", tags=["internal-slack"])


class ApiAuditAlertPayload(BaseModel):
    id: Any = None
    credential_id: Any = None
    key_name: str = "Unknown"
    action: str = "API Request"
    client_ip: str = "N/A"
    user_agent: Optional[str] = None
    request_data: Optional[Dict] = None
    response_code: int = 200
    success: bool = True
    endpoint_path: str = ""
    http_method: str = ""
    timestamp: Optional[str] = None

    @field_validator("request_data", mode="before")
    @classmethod
    def _coerce_request_data(cls, v: Any) -> Dict:
        return v if isinstance(v, dict) else {}


@router.post("/api-audit-alert")
async def api_audit_alert(payload: ApiAuditAlertPayload):
    """Internal endpoint: called by the API layer to send a Slack notification for API audit log events."""
    success = send_api_audit_log_alert(payload.model_dump())
    if not success:
        raise HTTPException(status_code=500, detail="Slack notification failed")
    return {"ok": True}

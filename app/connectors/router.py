from __future__ import annotations

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from app.connectors.registry import (
    connector_execute_plan,
    connector_preflight,
    connector_readiness,
    list_connector_capabilities,
)
from app.core.security import require_admin_or_monitor_token

router = APIRouter(
    prefix="/api/v1/connectors",
    tags=["connectors"],
    dependencies=[Depends(require_admin_or_monitor_token)],
)


class ConnectorPreflightRequest(BaseModel):
    action: str = Field(..., min_length=1)
    target: str = Field(..., min_length=1)
    change_ticket: str | None = None


class ConnectorExecuteRequest(ConnectorPreflightRequest):
    dry_run: bool = True


@router.get("")
def read_connectors():
    return {"items": list_connector_capabilities()}


@router.get("/{provider}/readiness")
def read_connector_readiness(provider: str):
    return connector_readiness(provider)


@router.post("/{provider}/preflight")
def run_connector_preflight(provider: str, payload: ConnectorPreflightRequest):
    return connector_preflight(
        provider,
        action=payload.action,
        target=payload.target,
        change_ticket=payload.change_ticket,
    )


@router.post("/{provider}/execute")
def run_connector_execute(provider: str, payload: ConnectorExecuteRequest):
    return connector_execute_plan(
        provider,
        action=payload.action,
        target=payload.target,
        dry_run=payload.dry_run,
        change_ticket=payload.change_ticket,
    )

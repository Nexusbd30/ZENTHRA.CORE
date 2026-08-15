from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from app.core.security import require_admin_or_monitor_token
from app.runtime.orchestrator import PLAYBOOK_QUEUE

router = APIRouter(
    prefix="/api/v1/runtime",
    tags=["runtime"],
    dependencies=[Depends(require_admin_or_monitor_token)],
)


class EnqueueRequest(BaseModel):
    payload: dict[str, Any] = Field(default_factory=dict)
    idempotency_key: str | None = None


@router.get("/status")
def runtime_status():
    return {
        "schema": "vaelqorix.runtime.distributed.v1",
        "workers": ["playbook-execution"],
        "queue": PLAYBOOK_QUEUE.stats(),
        "capabilities": [
            "idempotency_key",
            "backpressure",
            "dead_letter_queue",
            "retry_ready",
            "scheduler_ready",
            "streaming_events_ready",
        ],
    }


@router.post("/playbooks/enqueue")
def enqueue_playbook(payload: EnqueueRequest):
    return PLAYBOOK_QUEUE.enqueue(payload.payload, idempotency_key=payload.idempotency_key)

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from app.core.security import require_admin_or_control_token
from app.runtime.orchestrator import PLAYBOOK_QUEUE

router = APIRouter(
    prefix="/api/v1/runtime",
    tags=["runtime"],
    dependencies=[Depends(require_admin_or_control_token)],
)


class EnqueueRequest(BaseModel):
    payload: dict[str, Any] = Field(default_factory=dict)
    idempotency_key: str | None = None


@router.get("/status")
def runtime_status():
    return {
        "schema": "vaelqorix.runtime.distributed.v1",
        "workers": [],
        "consumer_status": "not_configured",
        "queue": PLAYBOOK_QUEUE.stats(),
        "capabilities": [
            "persistent_storage",
            "idempotency_key",
            "backpressure",
            "lease_fencing",
            "bounded_retries",
            "dead_letter_queue",
            "terminal_record_retention",
        ],
    }


@router.post("/playbooks/enqueue")
def enqueue_playbook(payload: EnqueueRequest):
    return PLAYBOOK_QUEUE.enqueue(payload.payload, idempotency_key=payload.idempotency_key)

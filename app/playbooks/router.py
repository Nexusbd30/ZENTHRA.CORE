from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from app.core.security import require_admin_or_monitor_token
from app.playbooks.registry import list_playbooks, playbook_summary
from app.playbooks.runtime import preview_playbook

router = APIRouter(
    prefix="/api/v1/playbooks",
    tags=["playbooks"],
    dependencies=[Depends(require_admin_or_monitor_token)],
)


class PlaybookPreviewRequest(BaseModel):
    context: dict[str, Any] = Field(default_factory=dict)
    dry_run: bool = True
    approved: bool = False


@router.get("")
def read_playbooks():
    return {"items": [playbook_summary(playbook) for playbook in list_playbooks()]}


@router.post("/{playbook_id}/preview")
def preview(playbook_id: str, payload: PlaybookPreviewRequest):
    return preview_playbook(
        playbook_id=playbook_id,
        context=payload.context,
        dry_run=payload.dry_run,
        approved=payload.approved,
    )

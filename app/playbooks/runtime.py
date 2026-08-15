from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from app.playbooks.engine import build_execution_plan
from app.playbooks.registry import get_playbook, playbook_summary


def preview_playbook(
    *,
    playbook_id: str,
    context: dict[str, Any],
    dry_run: bool = True,
    approved: bool = False,
) -> dict[str, Any]:
    playbook = get_playbook(playbook_id)
    if playbook is None:
        return {"status": "not_found", "playbook_id": playbook_id}
    return {
        "status": "ok",
        "execution_id": uuid4().hex,
        "created_at": datetime.now(UTC).isoformat(),
        "playbook": playbook_summary(playbook),
        "plan": build_execution_plan(
            playbook,
            context=context,
            dry_run=dry_run,
            approved=approved,
        ),
    }

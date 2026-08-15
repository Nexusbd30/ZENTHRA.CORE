from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from app.playbooks.contracts import Playbook, playbook_from_dict

PLAYBOOK_ROOT = Path("playbooks")


def load_playbook(path: Path) -> Playbook:
    data = json.loads(path.read_text(encoding="utf-8"))
    return playbook_from_dict(data)


def list_playbooks(root: Path = PLAYBOOK_ROOT) -> list[Playbook]:
    if not root.exists():
        return []
    return [load_playbook(path) for path in sorted(root.rglob("*.json"))]


def get_playbook(playbook_id: str, root: Path = PLAYBOOK_ROOT) -> Playbook | None:
    for playbook in list_playbooks(root):
        if playbook.playbook_id == playbook_id:
            return playbook
    return None


def playbook_summary(playbook: Playbook) -> dict[str, Any]:
    return {
        "playbook_id": playbook.playbook_id,
        "version": playbook.version,
        "name": playbook.name,
        "description": playbook.description,
        "triggers": playbook.triggers,
        "step_count": len(playbook.steps),
        "labels": playbook.labels,
    }

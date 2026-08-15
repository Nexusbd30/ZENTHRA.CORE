from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4


@dataclass
class RuntimeQueue:
    name: str
    max_size: int = 1000
    items: deque[dict[str, Any]] = field(default_factory=deque)
    dead_letters: list[dict[str, Any]] = field(default_factory=list)

    def enqueue(self, payload: dict[str, Any], *, idempotency_key: str | None = None) -> dict[str, Any]:
        if len(self.items) >= self.max_size:
            event = {"payload": payload, "reason": "backpressure", "timestamp": datetime.now(UTC).isoformat()}
            self.dead_letters.append(event)
            return {"status": "backpressure", "dead_letter": event}
        item = {
            "job_id": uuid4().hex,
            "idempotency_key": idempotency_key or uuid4().hex,
            "payload": payload,
            "status": "queued",
            "queued_at": datetime.now(UTC).isoformat(),
            "attempts": 0,
        }
        self.items.append(item)
        return {"status": "queued", "job": item}

    def stats(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "queued": len(self.items),
            "dead_letters": len(self.dead_letters),
            "max_size": self.max_size,
        }


PLAYBOOK_QUEUE = RuntimeQueue("playbook-execution")

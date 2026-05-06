from __future__ import annotations

import time
from datetime import UTC, datetime

from app.actions.base import BaseAction
from app.actions.endpoint import EndpointAction
from app.actions.identity import IdentityAction
from app.actions.network import NetworkAction

ACTION_EXECUTORS: dict[str, BaseAction] = {
    "network_isolate": NetworkAction(),
    "identity_lockdown": IdentityAction(),
    "endpoint_isolate": EndpointAction(),
}


class ActionTransaction:
    def __init__(self, executor: BaseAction):
        self.executor = executor
        self.performed: list[dict] = []

    def record(self, rollback_payload: dict):
        self.performed.append(rollback_payload)

    def rollback(self) -> list[dict]:
        rollback_events: list[dict] = []
        for payload in reversed(self.performed):
            result = self.executor.rollback_step(payload)
            rollback_events.append(
                {
                    "payload": payload,
                    "status": result.status,
                    "detail": result.detail,
                    "evidence": result.evidence,
                }
            )
        return rollback_events


def execute_plan(plan: dict, *, controls: dict | None = None) -> dict:
    controls = controls or {}
    action_type = plan.get("action_type", "observe")
    dry_run = bool(controls.get("dry_run", False))

    if action_type not in ACTION_EXECUTORS:
        return {
            "status": "success",
            "duration_ms": 0,
            "executed_steps": [
                {
                    "step": "noop",
                    "status": "ok",
                    "timestamp": datetime.now(UTC).isoformat(),
                    "detail": f"action {action_type} handled as non-disruptive",
                }
            ],
            "rollback_available": False,
            "rollback_events": [],
        }

    if dry_run:
        return {
            "status": "success",
            "mode": "dry_run",
            "duration_ms": 0,
            "executed_steps": [
                {
                    "step": step.get("step"),
                    "status": "planned",
                    "detail": "dry-run: step validated but not executed",
                    "evidence": {
                        "action_type": action_type,
                        "payload": step.get("payload", {}),
                    },
                    "timestamp": datetime.now(UTC).isoformat(),
                }
                for step in plan.get("steps", [])
            ],
            "rollback_available": False,
            "rollback_events": [],
        }

    executor = ACTION_EXECUTORS[action_type]
    tx = ActionTransaction(executor)
    start = time.perf_counter()
    simulate_failure_after = int(controls.get("simulate_failure_after_steps", 0) or 0)

    executed: list[dict] = []
    try:
        for idx, step in enumerate(plan.get("steps", []), start=1):
            result = executor.execute_step(step, controls)
            tx.record(result.rollback_payload or {})

            executed.append(
                {
                    "step": step.get("step"),
                    "status": result.status,
                    "detail": result.detail,
                    "evidence": result.evidence,
                    "timestamp": datetime.now(UTC).isoformat(),
                }
            )

            if simulate_failure_after and idx >= simulate_failure_after:
                raise RuntimeError("Simulated failure requested by controls")

        duration_ms = int((time.perf_counter() - start) * 1000)
        return {
            "status": "success",
            "duration_ms": duration_ms,
            "executed_steps": executed,
            "rollback_available": True,
            "rollback_events": [],
        }
    except Exception as exc:  # noqa: BLE001
        rollback_events = tx.rollback()
        duration_ms = int((time.perf_counter() - start) * 1000)
        return {
            "status": "failed",
            "duration_ms": duration_ms,
            "executed_steps": executed,
            "rollback_available": True,
            "rollback_events": rollback_events,
            "error": str(exc),
        }

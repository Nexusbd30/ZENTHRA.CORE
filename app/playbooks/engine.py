from __future__ import annotations

from typing import Any

from app.playbooks.contracts import Playbook, PlaybookStep


def _get(context: dict[str, Any], path: str) -> Any:
    current: Any = context
    for part in path.split("."):
        if not isinstance(current, dict):
            return None
        current = current.get(part)
    return current


def _condition_matches(when: dict[str, Any], context: dict[str, Any]) -> bool:
    if not when:
        return True
    raw_equals = when.get("equals")
    equals = raw_equals if isinstance(raw_equals, dict) else {}
    for key, expected in equals.items():
        if _get(context, str(key)) != expected:
            return False
    raw_contains = when.get("contains")
    contains = raw_contains if isinstance(raw_contains, dict) else {}
    for key, expected in contains.items():
        value = _get(context, str(key))
        if isinstance(value, list):
            if expected not in value:
                return False
        elif str(expected) not in str(value or ""):
            return False
    raw_min_values = when.get("min")
    min_values = raw_min_values if isinstance(raw_min_values, dict) else {}
    for key, expected in min_values.items():
        try:
            if float(_get(context, str(key)) or 0.0) < float(expected):
                return False
        except (TypeError, ValueError):
            return False
    return True


def build_execution_plan(
    playbook: Playbook,
    *,
    context: dict[str, Any],
    dry_run: bool = True,
    approved: bool = False,
) -> dict[str, Any]:
    planned: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    approval_required = False
    for step in playbook.steps:
        if not _condition_matches(step.when, context):
            skipped.append({"step_id": step.step_id, "reason": "condition_not_met"})
            continue
        if step.requires_approval and not approved:
            approval_required = True
        planned.append(_step_plan(step, dry_run=dry_run, approved=approved))
    return {
        "schema": "vaelqorix.playbooks.execution_plan.v1",
        "playbook_id": playbook.playbook_id,
        "version": playbook.version,
        "dry_run": dry_run,
        "approval_required": approval_required,
        "steps": planned,
        "skipped": skipped,
        "rollback_strategy": "reverse_order_for_reversible_steps",
    }


def _step_plan(step: PlaybookStep, *, dry_run: bool, approved: bool) -> dict[str, Any]:
    gated = step.requires_approval and not approved
    return {
        "step_id": step.step_id,
        "connector": step.connector,
        "action": step.action,
        "parameters": step.parameters,
        "status": "approval_required" if gated else ("planned" if dry_run else "ready"),
        "retries": step.retries,
        "requires_approval": step.requires_approval,
        "rollback": step.rollback,
        "on_success": step.on_success,
        "on_failure": step.on_failure,
    }

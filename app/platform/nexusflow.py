from __future__ import annotations

from typing import Any

from app.ares.planner import DISRUPTIVE_ACTIONS, build_plan


class NexusFlowWorkflowEngine:
    name = "NexusFlow"
    contract = "nexusops.nexusflow.workflow_engine.v1"

    def build_status(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "contract": self.contract,
            "workflow_modules": [
                "app.ares.planner",
                "app.ares.executor",
                "app.ares.approval",
                "app.services.autonomy_service",
            ],
            "supports_human_approvals": True,
            "supports_rollback": True,
            "disruptive_actions": sorted(DISRUPTIVE_ACTIONS),
            "blacknode_required": True,
        }

    def preview_workflow(self, verdict: dict[str, Any]) -> dict[str, Any]:
        plan = build_plan(verdict)
        return {
            "contract": self.contract,
            "action_type": verdict.get("action_type", "observe"),
            "target": verdict.get("target", "unknown"),
            "plan": plan,
            "requires_blacknode": True,
        }


nexusflow_engine = NexusFlowWorkflowEngine()


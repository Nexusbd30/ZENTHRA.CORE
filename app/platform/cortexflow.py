from __future__ import annotations

from typing import Any

from app.intelligence.status import build_intelligence_status
from app.redqueen.decision_engine import ALLOWED_ACTIONS, DOMAIN_ACTIONS


class CortexFlowAgentRuntime:
    name = "CortexFlow"
    contract = "vaelqorix.cortexflow.agent_runtime.v1"

    def build_status(self) -> dict[str, Any]:
        intelligence = build_intelligence_status()
        return {
            "name": self.name,
            "contract": self.contract,
            "runtime_modules": ["app.redqueen", "app.ares", "app.intelligence"],
            "allowed_actions": sorted(ALLOWED_ACTIONS),
            "domain_actions": {key: sorted(value) for key, value in DOMAIN_ACTIONS.items()},
            "llm": intelligence["llm"],
            "mcp": intelligence["mcp"],
            "blacknode_required": True,
        }


cortexflow_runtime = CortexFlowAgentRuntime()


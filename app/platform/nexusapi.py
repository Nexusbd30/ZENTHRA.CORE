from __future__ import annotations

from typing import Any

from app.ares.executor import ACTION_EXECUTORS
from app.core.mcp_gateway import list_mcp_tools
from app.platform.blacknode import classify_action_risk
from app.secops.providers import list_provider_capability_payloads as list_devsecops_providers


class NexusAPIToolRegistry:
    name = "NexusAPI"
    contract = "nexusops.nexusapi.tool_registry.v1"

    def list_action_tools(self) -> list[dict[str, Any]]:
        return [
            {
                "name": action_type,
                "executor": executor.__class__.__name__,
                "risk_level": classify_action_risk(action_type),
                "requires_blacknode": True,
                "audited": True,
            }
            for action_type, executor in sorted(ACTION_EXECUTORS.items())
        ]

    def list_mcp_tools(self) -> list[dict[str, str]]:
        return list_mcp_tools()

    def build_status(self) -> dict[str, Any]:
        action_tools = self.list_action_tools()
        mcp_tools = self.list_mcp_tools()
        providers = list_devsecops_providers()
        return {
            "name": self.name,
            "contract": self.contract,
            "action_tool_count": len(action_tools),
            "mcp_tool_count": len(mcp_tools),
            "devsecops_provider_count": len(providers),
            "action_tools": action_tools,
            "mcp_tools": mcp_tools,
            "devsecops_providers": providers,
            "blacknode_enforced": True,
        }


nexusapi_registry = NexusAPIToolRegistry()


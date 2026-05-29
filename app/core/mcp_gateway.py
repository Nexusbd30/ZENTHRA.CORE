from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class MCPTool:
    name: str
    category: str
    capability: str
    mode: str = "read"


MCP_TOOL_REGISTRY: tuple[MCPTool, ...] = (
    MCPTool("identity.lookup", "identity", "resolve identity metadata"),
    MCPTool("identity.activity", "identity", "read identity activity timeline"),
    MCPTool("pipeline.lookup", "devsecops", "resolve pipeline metadata"),
    MCPTool("artifact.lookup", "devsecops", "read artifact metadata"),
    MCPTool("secret.rotation.status", "devsecops", "read secret rotation state"),
    MCPTool("vulnerability.lookup", "devsecops", "read vulnerability intelligence"),
    MCPTool("siem.search", "secops", "read correlated SIEM evidence"),
    MCPTool("evidence.fetch", "secops", "read case evidence"),
    MCPTool("case.create", "secops", "create defensive case record", mode="write"),
)


def _list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item).strip().lower() for item in value if item is not None and str(item).strip()]


def list_mcp_tools() -> list[dict[str, str]]:
    return [
        {
            "name": tool.name,
            "category": tool.category,
            "capability": tool.capability,
            "mode": tool.mode,
        }
        for tool in MCP_TOOL_REGISTRY
    ]


def evaluate_mcp_tool_policy(context: dict[str, Any] | None) -> dict[str, Any]:
    context = context if isinstance(context, dict) else {}
    requested_tools = _list(context.get("tools"))
    allowed_tools = set(_list(context.get("allowed_tools")))
    blocked_tools = set(_list(context.get("blocked_tools")))
    registered = {tool.name: tool for tool in MCP_TOOL_REGISTRY}

    unknown_tools = [tool for tool in requested_tools if tool not in registered]
    explicitly_blocked = [tool for tool in requested_tools if tool in blocked_tools]
    not_allowed = [
        tool for tool in requested_tools if allowed_tools and tool not in allowed_tools
    ]
    allowed = not unknown_tools and not explicitly_blocked and not_allowed == []
    code = "ok"
    detail = "MCP tool policy allows declared tools"
    if unknown_tools:
        code = "mcp_tool_unknown"
        detail = "MCP context references tools outside the local registry"
    elif explicitly_blocked:
        code = "mcp_tool_blocked"
        detail = "MCP context references blocked tools"
    elif not_allowed:
        code = "mcp_tool_not_allowed"
        detail = "MCP context references tools outside the allowlist"

    return {
        "schema": "zenthra.mcp_tool_policy.v1",
        "mode": "local_registry",
        "allowed": allowed,
        "code": code,
        "detail": detail,
        "requested_tools": requested_tools,
        "unknown_tools": unknown_tools,
        "blocked_tools": explicitly_blocked,
        "not_allowed_tools": not_allowed,
        "registered_tools": sorted(registered),
    }

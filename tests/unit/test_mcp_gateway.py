from __future__ import annotations

from app.core.mcp_context import normalize_mcp_context
from app.core.mcp_gateway import evaluate_mcp_tool_policy, list_mcp_tools


def test_mcp_tool_policy_allows_registered_tools():
    context = normalize_mcp_context(
        {
            "tools": ["identity.lookup", "pipeline.lookup"],
            "allowed_tools": ["identity.lookup", "pipeline.lookup"],
        }
    )

    result = evaluate_mcp_tool_policy(context)

    assert result["schema"] == "vaelqorix.mcp_tool_policy.v1"
    assert result["allowed"] is True
    assert result["code"] == "ok"


def test_mcp_tool_policy_rejects_unknown_tools():
    result = evaluate_mcp_tool_policy({"tools": ["unknown.execute"]})

    assert result["allowed"] is False
    assert result["code"] == "mcp_tool_unknown"
    assert result["unknown_tools"] == ["unknown.execute"]


def test_mcp_tool_policy_rejects_tools_outside_allowlist():
    result = evaluate_mcp_tool_policy(
        {
            "tools": ["identity.lookup", "siem.search"],
            "allowed_tools": ["identity.lookup"],
        }
    )

    assert result["allowed"] is False
    assert result["code"] == "mcp_tool_not_allowed"
    assert result["not_allowed_tools"] == ["siem.search"]


def test_mcp_tool_registry_exposes_defensive_capabilities():
    tools = {tool["name"]: tool for tool in list_mcp_tools()}

    assert tools["identity.lookup"]["mode"] == "read"
    assert tools["pipeline.lookup"]["category"] == "devsecops"
    assert tools["case.create"]["mode"] == "write"

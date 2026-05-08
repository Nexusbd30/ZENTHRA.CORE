from __future__ import annotations


def evaluate_ares_health(memory: dict) -> dict:
    count = int(memory.get("count", 0) or 0)
    failure_rate = float(memory.get("failure_rate", 0.0) or 0.0)
    consecutive_failures = int(memory.get("consecutive_failures", 0) or 0)

    if count == 0:
        return {
            "status": "unknown",
            "severity": "info",
            "reason": "no execution history for target",
            "recommended_controls": {"dry_run": True},
        }

    if consecutive_failures >= 2 or failure_rate >= 0.5:
        return {
            "status": "critical",
            "severity": "high",
            "reason": "recent ARES executions failed too often",
            "recommended_controls": {
                "dry_run": True,
                "requires_human": True,
                "mcp_context": {
                    "blocked_actions": [
                        "network_isolate",
                        "identity_lockdown",
                        "endpoint_isolate",
                    ],
                    "reason": "ares_memory_failure_guard",
                },
            },
        }

    if failure_rate > 0:
        return {
            "status": "degraded",
            "severity": "medium",
            "reason": "some ARES executions failed recently",
            "recommended_controls": {"requires_human": True},
        }

    return {
        "status": "healthy",
        "severity": "low",
        "reason": "recent ARES executions completed successfully",
        "recommended_controls": {},
    }

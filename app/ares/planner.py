from __future__ import annotations


def build_plan(verdict: dict) -> dict:
    action_type = verdict.get("action_type", "observe")
    target = verdict.get("target", "unknown")

    steps: list[dict] = []
    if action_type == "network_isolate":
        steps = [
            {"step": "resolve_target", "payload": {"target": target}},
            {"step": "isolate_network", "payload": {"target": target}},
            {"step": "confirm_isolation", "payload": {"target": target}},
        ]
    elif action_type == "identity_lockdown":
        steps = [
            {"step": "resolve_identity", "payload": {"target": target}},
            {"step": "disable_credentials", "payload": {"target": target}},
            {"step": "force_mfa", "payload": {"target": target}},
        ]
    elif action_type == "endpoint_isolate":
        steps = [
            {"step": "resolve_endpoint", "payload": {"target": target}},
            {"step": "isolate_endpoint", "payload": {"target": target}},
            {"step": "snapshot_forensics", "payload": {"target": target}},
        ]
    elif action_type == "soar_delegate":
        steps = [
            {"step": "open_ticket", "payload": {"target": target}},
            {"step": "notify_soc", "payload": {"target": target}},
        ]
    else:
        steps = [{"step": "observe_only", "payload": {"target": target}}]

    return {"action_type": action_type, "target": target, "steps": steps}

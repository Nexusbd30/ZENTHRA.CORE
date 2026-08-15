from __future__ import annotations

from typing import Any


def build_entity_graph(events: list[dict[str, Any]], matches: list[dict[str, Any]]) -> dict[str, Any]:
    nodes: dict[str, dict[str, Any]] = {}
    edges: dict[str, dict[str, str]] = {}
    for event in events:
        entity_id = str(event.get("entity_id") or "unknown")
        nodes[entity_id] = {"id": entity_id, "type": str(event.get("entity_type") or "unknown")}
        payload = event.get("normalized_payload")
        payload = payload if isinstance(payload, dict) else {}
        for key in ("src_ip", "dst_ip", "domain", "user", "host"):
            value = str(payload.get(key) or "")
            if not value:
                continue
            nodes[value] = {"id": value, "type": key}
            edges[f"{entity_id}->{value}:{key}"] = {
                "source": entity_id,
                "target": value,
                "relationship": key,
            }
    for match in matches:
        rule_id = str(match.get("rule_id") or "")
        entity_id = str(match.get("entity_id") or "")
        if rule_id and entity_id:
            nodes[rule_id] = {"id": rule_id, "type": "detection_rule"}
            edges[f"{rule_id}->{entity_id}:matched"] = {
                "source": rule_id,
                "target": entity_id,
                "relationship": "matched",
            }
    return {"nodes": list(nodes.values()), "edges": list(edges.values())}

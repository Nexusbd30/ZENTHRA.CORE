from __future__ import annotations

from collections import defaultdict
from typing import Any


def correlate_detections(matches: list[dict[str, Any]]) -> dict[str, Any]:
    by_entity: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for match in matches:
        by_entity[str(match.get("entity_id") or "unknown")].append(match)

    incidents: list[dict[str, Any]] = []
    for entity_id, items in by_entity.items():
        severity = max(int(item.get("severity") or 0) for item in items)
        stages = sorted({str(item.get("kill_chain_stage") or "unknown") for item in items})
        recommended = "observe"
        if severity >= 9 or len(stages) >= 2:
            recommended = "aggressive_containment"
        elif severity >= 8:
            recommended = str(items[0].get("recommended_action") or "soar_delegate")
        incidents.append(
            {
                "entity_id": entity_id,
                "severity": severity,
                "kill_chain_stages": stages,
                "match_count": len(items),
                "recommended_action": recommended,
                "matches": items,
            }
        )
    return {
        "schema": "vaelqorix.detection.correlation.v1",
        "incident_count": len(incidents),
        "incidents": sorted(incidents, key=lambda item: int(item["severity"]), reverse=True),
    }

from __future__ import annotations

from ipaddress import ip_address
from typing import Any

TRACE_SCHEMA = "vaelqorix.redqueen.bridge_trace.v1"
PRIVATE_SOURCE_LABEL = "internal_or_private_source"


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _first_text(*values: Any) -> str:
    for value in values:
        if value is None:
            continue
        text = str(value).strip()
        if text:
            return text
    return ""


def _factor_values(factors: list[str], prefix: str) -> list[str]:
    prefix = prefix.lower()
    values: list[str] = []
    for factor in factors:
        text = str(factor).strip()
        if text.lower().startswith(prefix):
            values.append(text.split(":", 1)[1].strip())
    return list(dict.fromkeys(item for item in values if item))


def _ip_scope(value: str) -> str:
    try:
        parsed = ip_address(value)
    except ValueError:
        return "unknown"
    if parsed.is_private or parsed.is_loopback or parsed.is_link_local:
        return "private"
    if parsed.is_multicast or parsed.is_reserved or parsed.is_unspecified:
        return "non_routable"
    return "public"


def _network_candidates(payload: dict[str, Any], factors: list[str]) -> list[dict[str, Any]]:
    src_ip = _first_text(
        payload.get("src_ip"),
        payload.get("source_ip"),
        payload.get("client_ip"),
        payload.get("remote_ip"),
        *_factor_values(factors, "src_ip:"),
        *_factor_values(factors, "source_ip:"),
    )
    dst_ip = _first_text(payload.get("dst_ip"), payload.get("destination_ip"), payload.get("server_ip"))
    candidates: list[dict[str, Any]] = []
    if src_ip:
        candidates.append(
            {
                "type": "ip",
                "value": src_ip,
                "scope": _ip_scope(src_ip),
                "role": "observed_source",
                "confidence": 0.78,
            }
        )
    if dst_ip:
        candidates.append(
            {
                "type": "ip",
                "value": dst_ip,
                "scope": _ip_scope(dst_ip),
                "role": "observed_destination",
                "confidence": 0.48,
            }
        )
    return candidates


def _identity_candidates(payload: dict[str, Any], factors: list[str]) -> list[dict[str, Any]]:
    identity_context = _dict(payload.get("identity_context"))
    subject = _dict(identity_context.get("subject"))
    session = _dict(identity_context.get("session"))
    candidates: list[dict[str, Any]] = []
    identity_id = _first_text(
        payload.get("identity_id"),
        payload.get("user"),
        subject.get("id"),
        subject.get("upn"),
        *_factor_values(factors, "devsecops_actor:"),
    )
    if identity_id:
        candidates.append(
            {
                "type": "identity",
                "value": identity_id,
                "scope": "internal",
                "role": "suspected_account_bridge",
                "confidence": 0.74,
            }
        )
    session_id = _first_text(session.get("id"), session.get("session_id"), payload.get("session_id"))
    if session_id:
        candidates.append(
            {
                "type": "session",
                "value": session_id,
                "scope": "internal",
                "role": "suspected_session_bridge",
                "confidence": 0.7,
            }
        )
    device_id = _first_text(session.get("device_id"), payload.get("device_id"), payload.get("host_id"))
    if device_id:
        candidates.append(
            {
                "type": "device",
                "value": device_id,
                "scope": "internal",
                "role": "suspected_device_bridge",
                "confidence": 0.66,
            }
        )
    return candidates


def _devsecops_candidates(payload: dict[str, Any], factors: list[str]) -> list[dict[str, Any]]:
    devsecops_context = _dict(payload.get("devsecops_context"))
    pipeline = _dict(devsecops_context.get("pipeline"))
    actor = _dict(devsecops_context.get("actor"))
    candidates: list[dict[str, Any]] = []
    repository = _first_text(
        pipeline.get("repository"),
        payload.get("repository"),
        *_factor_values(factors, "devsecops_repository:"),
    )
    pipeline_id = _first_text(
        pipeline.get("pipeline_id"),
        payload.get("pipeline_id"),
        *_factor_values(factors, "devsecops_pipeline:"),
    )
    runner = _first_text(pipeline.get("runner_id"), payload.get("runner_id"), actor.get("runner_id"))
    if repository:
        candidates.append(
            {
                "type": "repository",
                "value": repository,
                "scope": "business_change",
                "role": "supply_chain_bridge",
                "confidence": 0.72,
            }
        )
    if pipeline_id:
        candidates.append(
            {
                "type": "pipeline",
                "value": pipeline_id,
                "scope": "business_change",
                "role": "delivery_bridge",
                "confidence": 0.76,
            }
        )
    if runner:
        candidates.append(
            {
                "type": "runner",
                "value": runner,
                "scope": "internal",
                "role": "execution_bridge",
                "confidence": 0.68,
            }
        )
    return candidates


def _block_targets(candidates: list[dict[str, Any]]) -> list[dict[str, Any]]:
    blocks: list[dict[str, Any]] = []
    for item in candidates:
        item_type = str(item.get("type") or "")
        value = str(item.get("value") or "")
        scope = str(item.get("scope") or "")
        if not value:
            continue
        if item_type == "ip":
            blocks.append(
                {
                    "type": "network_indicator",
                    "value": value,
                    "scope": "perimeter" if scope == "public" else "internal_segment",
                    "action": "block_inbound_and_watch_egress",
                }
            )
        elif item_type in {"identity", "session"}:
            blocks.append(
                {
                    "type": item_type,
                    "value": value,
                    "scope": "identity_provider",
                    "action": "revoke_or_lock",
                }
            )
        elif item_type in {"device", "runner"}:
            blocks.append(
                {
                    "type": item_type,
                    "value": value,
                    "scope": "endpoint_control",
                    "action": "isolate_pending_review",
                }
            )
        elif item_type in {"repository", "pipeline"}:
            blocks.append(
                {
                    "type": item_type,
                    "value": value,
                    "scope": "devsecops",
                    "action": "freeze_release_path",
                }
            )
    return list({f"{item['type']}:{item['value']}:{item['action']}": item for item in blocks}.values())


def _pivot_chain(target: str, candidates: list[dict[str, Any]], factors: list[str]) -> list[dict[str, str]]:
    chain: list[dict[str, str]] = []
    for item in candidates:
        item_type = str(item.get("type") or "")
        value = str(item.get("value") or "")
        role = str(item.get("role") or "")
        if value and item_type not in {"ip"}:
            chain.append({"from": value, "via": role or item_type, "to": target})
    if any("lateral_movement" in str(factor).lower() for factor in factors):
        chain.append({"from": PRIVATE_SOURCE_LABEL, "via": "lateral_movement_signal", "to": target})
    return chain[:8]


def build_bridge_trace(
    *,
    target: str,
    factors: list[str],
    controls: dict[str, Any] | None = None,
) -> dict[str, Any]:
    controls = controls if isinstance(controls, dict) else {}
    perception = _dict(controls.get("perception"))
    payload = _dict(perception.get("normalized_payload"))
    if not payload:
        payload = perception
    factors = [str(item) for item in factors if str(item).strip()]

    candidates = [
        *_network_candidates(payload, factors),
        *_identity_candidates(payload, factors),
        *_devsecops_candidates(payload, factors),
    ]
    for item in _list(controls.get("origin_candidates")):
        if isinstance(item, dict) and item.get("value"):
            candidates.append(
                {
                    "type": str(item.get("type") or "indicator"),
                    "value": str(item.get("value")),
                    "scope": str(item.get("scope") or "unknown"),
                    "role": str(item.get("role") or "operator_supplied_indicator"),
                    "confidence": float(item.get("confidence") or 0.55),
                }
            )
    candidates = list({f"{item['type']}:{item['value']}:{item.get('role', '')}": item for item in candidates}.values())
    blocks = _block_targets(candidates)
    trace_confidence = min(0.97, 0.32 + (len(candidates) * 0.09) + (len(blocks) * 0.05))
    evidence_sources = ["redqueen_factors", "threat_perception"]
    if controls.get("mcp_context"):
        evidence_sources.append("mcp_context")
    if payload.get("identity_context"):
        evidence_sources.append("identity_context")
    if payload.get("devsecops_context"):
        evidence_sources.append("devsecops_context")

    return {
        "schema": TRACE_SCHEMA,
        "target": target,
        "mode": "defensive_traceability",
        "external_action_policy": "block_and_report_only",
        "trace_confidence": round(trace_confidence, 2),
        "origin_candidates": candidates,
        "suspected_bridge": candidates[0] if candidates else {},
        "pivot_chain": _pivot_chain(target, candidates, factors),
        "block_targets": blocks,
        "evidence_sources": list(dict.fromkeys(evidence_sources)),
        "trace_boundaries": [
            "no_counter_intrusion",
            "no_external_system_access",
            "authorized_assets_only",
            "preserve_chain_of_custody",
        ],
    }

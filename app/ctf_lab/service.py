from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy.orm import Session

from app.ares.hunter_trace import build_hunter_trace
from app.attack_analysis.service import AttackAnalysisService
from app.models.threat_event import ThreatEvent

CTF_LAB_SCHEMA = "vaelqorix.ctf_lab.defensive.v1"

SCENARIOS: dict[str, dict[str, Any]] = {
    "identity_credential_foothold": {
        "id": "identity_credential_foothold",
        "name": "Identity credential foothold",
        "difficulty": "medium",
        "primary_entity": "user:ctf-admin@lab.local",
        "objective": "Detect credential abuse, confirm attack reality, and prepare identity eviction.",
        "expected_classification": {"confirmed_attack", "probable_attack"},
        "events": [
            {
                "source": "identity:entra",
                "event_type": "impossible_travel_login",
                "severity": 8,
                "stage": "initial_access",
                "mitre_tags": ["T1078", "T1110"],
                "risk_score": 78,
                "minutes": 0,
                "signals": ["privileged_identity", "mfa_absent"],
                "summary": "Privileged account login from unusual location with no MFA challenge.",
                "src_ip": "203.0.113.10",
            },
            {
                "source": "identity:entra",
                "event_type": "token_reuse",
                "severity": 8,
                "stage": "credential_access",
                "mitre_tags": ["T1078"],
                "risk_score": 84,
                "minutes": 2,
                "signals": ["refresh_token", "session_anomaly"],
                "summary": "Refresh token reuse observed after impossible travel signal.",
                "src_ip": "203.0.113.10",
            },
            {
                "source": "siem:qradar",
                "event_type": "admin_group_change",
                "severity": 9,
                "stage": "persistence",
                "mitre_tags": ["T1098"],
                "risk_score": 88,
                "minutes": 5,
                "signals": ["persistence", "privilege_escalation"],
                "summary": "Suspicious admin group membership change tied to same identity.",
                "src_ip": "203.0.113.10",
            },
        ],
    },
    "endpoint_lateral_movement": {
        "id": "endpoint_lateral_movement",
        "name": "Endpoint lateral movement",
        "difficulty": "hard",
        "primary_entity": "host:ctf-runner-07",
        "objective": "Detect execution and lateral movement, then build an operator-gated eviction plan.",
        "expected_classification": {"confirmed_attack", "probable_attack"},
        "events": [
            {
                "source": "edr:defender",
                "event_type": "suspicious_command",
                "severity": 8,
                "stage": "execution",
                "mitre_tags": ["T1059"],
                "risk_score": 82,
                "minutes": 0,
                "signals": ["powershell_encoded_command"],
                "summary": "Encoded command launched by unusual parent process.",
                "src_ip": "10.20.7.14",
            },
            {
                "source": "edr:defender",
                "event_type": "remote_service_creation",
                "severity": 9,
                "stage": "lateral_movement",
                "mitre_tags": ["T1021", "T1543"],
                "risk_score": 91,
                "minutes": 3,
                "signals": ["lateral_movement", "new_service"],
                "summary": "Remote service creation indicates pivot attempt.",
                "src_ip": "10.20.7.14",
                "dst_ip": "10.20.7.33",
            },
            {
                "source": "network:netflow",
                "event_type": "large_egress",
                "severity": 7,
                "stage": "exfiltration",
                "mitre_tags": ["T1041"],
                "risk_score": 70,
                "minutes": 8,
                "signals": ["large_egress"],
                "summary": "Outbound transfer spike after lateral movement signal.",
                "src_ip": "10.20.7.14",
                "dst_ip": "198.51.100.25",
            },
        ],
    },
    "benign_noise_triage": {
        "id": "benign_noise_triage",
        "name": "Benign noise triage",
        "difficulty": "easy",
        "primary_entity": "host:ctf-dev-02",
        "objective": "Avoid over-response and classify low-signal telemetry as likely benign.",
        "expected_classification": {"false_positive_likely", "needs_human_review"},
        "events": [
            {
                "source": "edr:defender",
                "event_type": "policy_info",
                "severity": 2,
                "stage": "unknown",
                "mitre_tags": [],
                "risk_score": 10,
                "minutes": 0,
                "signals": ["policy_update"],
                "summary": "Routine policy telemetry with no corroboration.",
                "src_ip": "10.20.1.18",
            }
        ],
    },
}


def list_scenarios() -> dict:
    return {
        "module": "ctf_lab",
        "schema": CTF_LAB_SCHEMA,
        "mode": "defensive_synthetic_lab_only",
        "count": len(SCENARIOS),
        "items": [
            {
                "id": scenario["id"],
                "name": scenario["name"],
                "difficulty": scenario["difficulty"],
                "primary_entity": scenario["primary_entity"],
                "objective": scenario["objective"],
                "event_count": len(scenario["events"]),
            }
            for scenario in SCENARIOS.values()
        ],
        "guardrails": [
            "synthetic_events_only",
            "owned_lab_environment_only",
            "dry_run_default",
            "no_external_targets",
        ],
    }


def get_scenario(scenario_id: str) -> dict | None:
    scenario = SCENARIOS.get(scenario_id)
    if not scenario:
        return None
    return {
        "module": "ctf_lab",
        "schema": CTF_LAB_SCHEMA,
        **scenario,
        "guardrails": [
            "synthetic_events_only",
            "owned_lab_environment_only",
            "dry_run_default",
            "operator_approval_before_disruptive_actions",
        ],
    }


def replay_scenario(db: Session, scenario_id: str, *, run_label: str = "") -> dict | None:
    scenario = SCENARIOS.get(scenario_id)
    if not scenario:
        return None

    run_id = run_label.strip() or f"ctf-{uuid.uuid4().hex[:10]}"
    started_at = datetime.now(UTC).replace(tzinfo=None)
    inserted: list[ThreatEvent] = []
    primary_entity = str(scenario["primary_entity"])

    for index, event in enumerate(scenario["events"], start=1):
        payload = {
            "kill_chain_stage": event["stage"],
            "signals": event["signals"],
            "summary": event["summary"],
            "ctf_lab": {
                "scenario_id": scenario_id,
                "run_id": run_id,
                "synthetic": True,
                "objective": scenario["objective"],
            },
        }
        row = ThreatEvent(
            source=str(event["source"]),
            event_id=f"{run_id}:{scenario_id}:{index}",
            occurred_at=started_at + timedelta(minutes=int(event["minutes"])),
            event_type=str(event["event_type"]),
            severity=int(event["severity"]),
            entity_id=primary_entity,
            entity_type="user" if primary_entity.startswith("user:") else "host",
            mitre_tags=json.dumps(event["mitre_tags"]),
            raw_payload=json.dumps({"ctf_lab": True, **event}),
            normalized_payload=json.dumps(payload),
            risk_score=float(event["risk_score"]),
            src_ip=str(event.get("src_ip") or ""),
            dst_ip=str(event.get("dst_ip") or ""),
        )
        db.add(row)
        inserted.append(row)
    db.commit()

    analysis = AttackAnalysisService.analyze_entity(db, entity_id=primary_entity)
    hunter_trace = build_hunter_trace(
        db,
        target=primary_entity,
        controls={"ctf_mode": True, "source": "ctf_lab", "scenario_id": scenario_id, "run_id": run_id},
    )
    passed = analysis["classification"] in scenario["expected_classification"]
    return {
        "module": "ctf_lab",
        "schema": "vaelqorix.ctf_lab.replay_result.v1",
        "status": "passed" if passed else "needs_review",
        "scenario_id": scenario_id,
        "run_id": run_id,
        "synthetic_events_inserted": len(inserted),
        "target": primary_entity,
        "expected_classification": sorted(scenario["expected_classification"]),
        "actual_classification": analysis["classification"],
        "attack_reality_score": analysis["attack_reality_score"],
        "hunter_presence_state": hunter_trace["presence_state"],
        "scorecard": {
            "detection_passed": passed,
            "event_count": analysis["event_count"],
            "kill_chain_stages": analysis["kill_chain_stages"],
            "requires_human_review": analysis["requires_human_review"],
            "expulsion_readiness": hunter_trace["expulsion_readiness"],
        },
        "analysis": analysis,
        "hunter_trace": hunter_trace,
        "guardrails": [
            "synthetic_events_only",
            "dry_run_default",
            "no_external_targets",
            "operator_gated_eviction",
        ],
    }

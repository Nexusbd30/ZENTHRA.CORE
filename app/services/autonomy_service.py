from __future__ import annotations

import json
from datetime import datetime

from sqlalchemy.orm import Session

from app.ares.advisor import review_plan
from app.ares.approval import verify_approval_payload
from app.ares.executor import execute_plan
from app.ares.internal_firewall import evaluate_internal_firewall
from app.ares.memory import read_ares_memory
from app.ares.monitor import evaluate_ares_health
from app.ares.planner import build_plan
from app.ares.reporter import build_execution_result
from app.ares.validator import validate_verdict
from app.core.audit import audit_autonomy_event
from app.core.mcp_context import mcp_risk_factors, normalize_mcp_context
from app.core.signing import sign_payload
from app.identity.service import summarize_identity_activity
from app.intelligence.rag import rag_factors, rag_payload, retrieve_defensive_context
from app.models.approval_record import ApprovalRecord
from app.models.execution_result import ExecutionResult
from app.models.threat_event import ThreatEvent
from app.models.threat_model import ThreatModel
from app.models.verdict import Verdict
from app.redqueen.decision_engine import generate_verdict
from app.redqueen.drift import analyze_risk_drift
from app.redqueen.memory import recall_threat_context
from app.redqueen.perception import build_threat_perception
from app.redqueen.risk_memory import read_entity_risk_memory, record_risk_memory
from app.redqueen.risk_scorer import score_perception
from app.redqueen.trainer import build_training_report
from app.repositories.approval_repository import ApprovalRepository
from app.repositories.execution_result_repository import ExecutionResultRepository
from app.repositories.threat_repository import ThreatRepository
from app.repositories.verdict_repository import VerdictRepository


class AutonomyService:
    @staticmethod
    def persist_approval(db: Session, approval_data: dict) -> ApprovalRecord:
        approved_at = datetime.fromisoformat(
            str(approval_data.get("approved_at")).replace("Z", "+00:00")
        )
        approval = ApprovalRecord(
            verdict_id=str(approval_data.get("verdict_id", "")),
            target=str(approval_data.get("target", "")),
            action_type=str(approval_data.get("action_type", "")),
            risk_score=float(approval_data.get("risk_score", 0.0)),
            approver=str(approval_data.get("approver", "")),
            reason=str(approval_data.get("reason", "")),
            signature=str(approval_data.get("signature", "")),
            approved_at=approved_at,
        )
        return ApprovalRepository.create(db, approval)

    @staticmethod
    def list_approvals(db: Session, verdict_id: str) -> list[ApprovalRecord]:
        return ApprovalRepository.list_by_verdict(db, verdict_id)

    @staticmethod
    def persist_verdict(db: Session, verdict_data: dict) -> Verdict:
        existing = VerdictRepository.get_by_id(db, str(verdict_data.get("verdict_id", "")))
        if existing:
            return existing

        verdict = Verdict(
            verdict_id=str(verdict_data.get("verdict_id")),
            timestamp=datetime.fromisoformat(str(verdict_data.get("timestamp")).replace("Z", "+00:00")),
            threat_event_id=str(verdict_data.get("threat_event_id", "")),
            status=str(verdict_data.get("status", "pending")),
            severity=str(verdict_data.get("severity", "medium")),
            target=str(verdict_data.get("target", "unknown")),
            action_type=str(verdict_data.get("action_type", "observe")),
            recommended_actions=json.dumps(
                verdict_data.get("recommended_actions", []), ensure_ascii=False
            ),
            primary_action=str(verdict_data.get("primary_action") or verdict_data.get("action_type", "")),
            risk_score=float(verdict_data.get("risk_score", 0.0)),
            confidence=float(verdict_data.get("confidence", 0.0)),
            confidence_score=float(
                verdict_data.get("confidence_score", verdict_data.get("confidence", 0.0))
            ),
            factors=json.dumps(verdict_data.get("factors", []), ensure_ascii=False),
            xai_explanation=json.dumps(
                verdict_data.get("xai_explanation", {}), ensure_ascii=False
            ),
            justification_xai=str(verdict_data.get("justification_xai", "")),
            policy_check=bool(verdict_data.get("policy_check", False)),
            requires_human=bool(verdict_data.get("requires_human", False)),
            requires_human_approval=bool(
                verdict_data.get("requires_human_approval", verdict_data.get("requires_human", False))
            ),
            policy_rule=str(verdict_data.get("policy_rule", "")),
            ttl_seconds=int(verdict_data.get("ttl_seconds", 3600)),
            execution_controls=json.dumps(
                verdict_data.get("execution_controls", {}), ensure_ascii=False
            ),
            signature=str(verdict_data.get("signature", "")),
        )
        return VerdictRepository.create(db, verdict)

    @staticmethod
    def persist_execution_result(db: Session, result_data: dict) -> ExecutionResult:
        model = ExecutionResult(
            verdict_id=str(result_data.get("verdict_id", "")),
            ares_id=str(result_data.get("ares_id", "ares")),
            action_type=str(result_data.get("action_type", "")),
            target_entity=str(result_data.get("target_entity", "")),
            target_system=str(result_data.get("target_system", "")),
            status=str(result_data.get("status", "unknown")),
            duration_ms=int(result_data.get("duration_ms", 0)),
            pre_state=json.dumps(result_data.get("pre_state", {}), ensure_ascii=False),
            post_state=json.dumps(result_data.get("post_state", {}), ensure_ascii=False),
            evidence=json.dumps(result_data.get("evidence", []), ensure_ascii=False),
            rollback_payload=json.dumps(
                result_data.get("rollback_payload", {}), ensure_ascii=False
            ),
            rl_reward=float(result_data.get("rl_reward", 0.0)),
            error_code=str(result_data.get("error_code", "")),
            result_hash=str(result_data.get("result_hash", "")),
            timestamp=datetime.fromisoformat(str(result_data.get("timestamp")).replace("Z", "+00:00")),
        )
        return ExecutionResultRepository.create(db, model)

    @staticmethod
    def get_verdict(db: Session, verdict_id: str) -> Verdict | None:
        return VerdictRepository.get_by_id(db, verdict_id)

    @staticmethod
    def get_execution_results(db: Session, verdict_id: str) -> list[ExecutionResult]:
        return ExecutionResultRepository.list_by_verdict(db, verdict_id)

    @staticmethod
    def get_risk_memory(db: Session, target: str, limit: int = 10) -> dict:
        return read_entity_risk_memory(db, target=target, limit=limit)

    @staticmethod
    def get_risk_drift(
        db: Session,
        target: str,
        current_score: float | None = None,
        limit: int = 10,
    ) -> dict:
        return analyze_risk_drift(
            db,
            target=target,
            current_score=current_score,
            limit=limit,
        )

    @staticmethod
    def get_training_report(db: Session, limit: int = 100) -> dict:
        return build_training_report(db, limit=limit)

    @staticmethod
    def get_ares_memory(db: Session, target: str, limit: int = 20) -> dict:
        return read_ares_memory(db, target=target, limit=limit)

    @staticmethod
    def get_ares_health(db: Session, target: str, limit: int = 20) -> dict:
        memory = read_ares_memory(db, target=target, limit=limit)
        return {
            "target": target,
            "memory": memory,
            "health": evaluate_ares_health(memory),
        }

    @staticmethod
    def issue_verdict(
        db: Session,
        *,
        target: str,
        risk_score: float,
        factors: list[str],
        execution_controls: dict | None = None,
    ) -> dict:
        controls = execution_controls or {}
        mcp_context = normalize_mcp_context(
            controls.get("mcp_context") if isinstance(controls.get("mcp_context"), dict) else {},
            target=target,
        )
        factors = [*factors]
        if mcp_context:
            factors.extend(mcp_risk_factors(mcp_context))
        drift = analyze_risk_drift(db, target=target, current_score=risk_score)
        factors.extend(str(item) for item in drift.get("signals", []) if item)
        if drift.get("severity") in {"high", "critical"}:
            factors.append(f"drift_severity:{drift['severity']}")
        verdict = generate_verdict(
            target=target,
            risk_score=risk_score,
            factors=list(dict.fromkeys(factors)),
            execution_controls={**controls, "mcp_context": mcp_context, "risk_drift": drift},
        )
        AutonomyService.persist_verdict(db, verdict)
        risk_memory = record_risk_memory(db, verdict=verdict)
        audit_autonomy_event(
            db,
            verdict_id=str(verdict.get("verdict_id", "")),
            actor="redqueen",
            action="verdict_issued",
            result={
                "target": target,
                "risk_score": verdict.get("risk_score"),
                "action_type": verdict.get("action_type"),
                "requires_human": verdict.get("requires_human"),
                "risk_memory": risk_memory,
            },
        )
        return verdict

    @staticmethod
    def issue_verdict_from_threat(
        db: Session,
        *,
        threat_id: str,
        execution_controls: dict | None = None,
    ) -> dict:
        threat = ThreatRepository(db).get_by_id(threat_id)
        if not isinstance(threat, ThreatModel):
            return {"status": "not_found", "threat_id": threat_id}

        perception = build_threat_perception(threat)
        memory = recall_threat_context(
            db,
            target=str(perception.get("target") or ""),
            fingerprint=str(getattr(threat, "fingerprint", "") or "") or None,
        )
        raw_mcp_context = (
            execution_controls.get("mcp_context") if isinstance(execution_controls, dict) else {}
        )
        mcp_context = normalize_mcp_context(
            raw_mcp_context if isinstance(raw_mcp_context, dict) else {},
            target=str(perception.get("target") or ""),
        )
        if mcp_context:
            perception["mcp_context"] = mcp_context
        score = score_perception(perception)
        drift = analyze_risk_drift(
            db,
            target=str(perception.get("target") or ""),
            current_score=float(score["risk_score"]),
        )

        factors = [
            *perception.get("factors", []),
            f"scoring_model:{score['scoring_model']}",
            *mcp_risk_factors(mcp_context),
            *[str(item) for item in drift.get("signals", []) if item],
        ]
        if drift.get("severity") in {"high", "critical"}:
            factors.append(f"drift_severity:{drift['severity']}")
        if memory:
            factors.append(f"memory_matches:{len(memory)}")
        if mcp_context:
            factors.append("mcp_context_present")

        controls = {
            **(execution_controls or {}),
            "threat_id": threat_id,
            "perception": perception,
            "risk_score_inputs": score["score_inputs"],
            "risk_drift": drift,
            "memory": memory,
            "mcp_context": mcp_context,
        }

        verdict = generate_verdict(
            target=str(perception["target"]),
            risk_score=float(score["risk_score"]),
            factors=factors,
            execution_controls=controls,
        )
        AutonomyService.persist_verdict(db, verdict)
        risk_memory = record_risk_memory(db, verdict=verdict)
        return {
            "status": "ok",
            "threat_id": threat_id,
            "perception": perception,
            "risk": score,
            "risk_memory": risk_memory,
            "memory": memory,
            "verdict": verdict,
        }

    @staticmethod
    def _risk_level(score_0_100: float) -> str:
        if score_0_100 >= 82:
            return "critical"
        if score_0_100 >= 60:
            return "high"
        if score_0_100 >= 35:
            return "medium"
        return "low"

    @staticmethod
    def _identity_activity_risk_boost(activity: dict) -> float:
        event_count = int(activity.get("event_count", 0) or 0)
        raw_event_types = activity.get("event_types")
        raw_signals = activity.get("signals")
        event_types = raw_event_types if isinstance(raw_event_types, list) else []
        signals = raw_signals if isinstance(raw_signals, list) else []
        if event_count <= 1:
            return 0.0
        boost = min(9.0, float(event_count - 1) * 3.0)
        boost += min(4.5, float(len(signals)) * 1.5)
        if len(event_types) >= 2:
            boost += 3.0
        return round(min(15.0, boost), 2)

    @staticmethod
    def _rag_domain(perception: dict, controls: dict | None = None) -> str:
        controls = controls if isinstance(controls, dict) else {}
        source = str(perception.get("source") or "").lower()
        entity_type = str(perception.get("entity_type") or "").lower()
        if controls.get("identity_contract") or source.startswith("identity:") or entity_type == "user":
            return "identity"
        if (
            controls.get("devsecops_contract")
            or source.startswith("devsecops:")
            or source.startswith("secops:identity_pipeline_correlation")
            or source.startswith("secops:integration_security_abuse")
            or entity_type in {"repository", "pipeline", "artifact"}
        ):
            return "devsecops"
        return "generic"

    @staticmethod
    def _enrich_with_rag(
        *,
        perception: dict,
        factors: list[str],
        controls: dict | None = None,
    ) -> tuple[list[str], dict]:
        controls = controls if isinstance(controls, dict) else {}
        if controls.get("rag_disabled") is True:
            return factors, {}
        domain = AutonomyService._rag_domain(perception, controls)
        query = " ".join(
            str(item)
            for item in [
                perception.get("source"),
                perception.get("event_type"),
                perception.get("target"),
                perception.get("risk_level"),
            ]
            if item
        )
        context = retrieve_defensive_context(query=query, domain=domain, factors=factors)
        payload = rag_payload(context)
        enriched = list(dict.fromkeys([*factors, *rag_factors(context)]))
        if payload.get("references"):
            enriched.append("rag_context_present")
        return enriched, payload

    @staticmethod
    def _threat_event_perception(event: ThreatEvent, db: Session | None = None) -> dict:
        try:
            mitre_tags = json.loads(event.mitre_tags or "[]")
        except json.JSONDecodeError:
            mitre_tags = []
        try:
            normalized_payload = json.loads(event.normalized_payload or event.normalized or "{}")
        except json.JSONDecodeError:
            normalized_payload = {}

        severity_score = max(0.0, min(100.0, float(event.severity or 0) * 10.0))
        mitre_score = min(25.0, len(mitre_tags) * 8.0)
        high_impact = {
            "T1078",
            "T1110",
            "T1003",
            "T1055",
            "T1059",
            "T1486",
            "T1041",
        }
        high_impact_hits = sorted(set(str(tag).upper() for tag in mitre_tags) & high_impact)
        entity_bonus = 8.0 if event.entity_type in {"user", "host"} else 3.0
        network_bonus = 5.0 if event.src_ip or event.dst_ip else 0.0
        rule_risk_score = max(
            0.0,
            min(
                100.0,
                (severity_score * 0.55)
                + mitre_score
                + entity_bonus
                + network_bonus
                + (len(high_impact_hits) * 6.0),
            ),
        )
        persisted_risk_score = max(0.0, min(100.0, float(event.risk_score or 0.0)))
        risk_score = max(rule_risk_score, persisted_risk_score)
        factors = [
            f"source:{event.source}",
            f"event_type:{event.event_type}",
            f"severity:{event.severity}",
            f"entity_type:{event.entity_type or 'unknown'}",
            *[f"mitre:{tag}" for tag in mitre_tags],
            *[f"high_impact:{tag}" for tag in high_impact_hits],
        ]
        if persisted_risk_score > rule_risk_score:
            factors.append(f"source_risk_score:{persisted_risk_score}")
        activity: dict = {}
        identity_context = normalized_payload.get("identity_context")
        if isinstance(identity_context, dict):
            subject = identity_context.get("subject")
            session = identity_context.get("session")
            geo = identity_context.get("geo")
            signals = identity_context.get("signals")
            if isinstance(subject, dict):
                provider = subject.get("provider")
                if provider:
                    factors.append(f"identity_provider:{provider}")
                if subject.get("privileged"):
                    factors.append("identity_privileged:true")
            if isinstance(session, dict):
                if session.get("mfa_present") is False:
                    factors.append("identity_mfa:absent")
                if session.get("ip_address"):
                    factors.append("identity_session:ip_present")
                if session.get("device_id"):
                    factors.append("identity_session:device_present")
            if isinstance(geo, dict):
                country = geo.get("country")
                if country:
                    factors.append(f"identity_geo_country:{country}")
            if isinstance(signals, list):
                factors.extend(f"identity_signal:{item}" for item in signals if item)
        if db is not None and event.entity_type == "user" and event.entity_id:
            activity = summarize_identity_activity(db, entity_id=event.entity_id, limit=10)
            if activity["event_count"] > 1:
                factors.append(f"identity_recent_events:{activity['event_count']}")
            for event_type in activity["event_types"][:5]:
                factors.append(f"identity_recent_event_type:{event_type}")
            for signal in activity["signals"][:8]:
                factors.append(f"identity_recent_signal:{signal}")
            activity_boost = AutonomyService._identity_activity_risk_boost(activity)
            if activity_boost:
                risk_score = min(100.0, risk_score + activity_boost)
                factors.append(f"identity_activity_risk_boost:{activity_boost}")
        devsecops_context = normalized_payload.get("devsecops_context")
        devsecops_identity_activity: dict = {}
        if isinstance(devsecops_context, dict):
            pipeline = devsecops_context.get("pipeline")
            actor = devsecops_context.get("actor")
            finding = devsecops_context.get("finding")
            controls = devsecops_context.get("controls")
            signals = devsecops_context.get("signals")
            if isinstance(pipeline, dict):
                provider = pipeline.get("provider")
                repository = pipeline.get("repository")
                environment = pipeline.get("environment")
                pipeline_id = pipeline.get("pipeline_id")
                artifact = pipeline.get("artifact")
                if provider:
                    factors.append(f"devsecops_provider:{provider}")
                if repository:
                    factors.append(f"devsecops_repository:{repository}")
                if environment:
                    factors.append(f"devsecops_environment:{environment}")
                if pipeline_id:
                    factors.append(f"devsecops_pipeline:{pipeline_id}")
                if artifact:
                    factors.append(f"devsecops_artifact:{artifact}")
            if isinstance(actor, dict):
                identity_id = actor.get("identity_id")
                if identity_id:
                    factors.append(f"devsecops_actor:{identity_id}")
                    if db is not None:
                        identity_entity_id = (
                            str(identity_id)
                            if str(identity_id).startswith("user:")
                            else f"user:{identity_id}"
                        )
                        devsecops_identity_activity = summarize_identity_activity(
                            db,
                            entity_id=identity_entity_id,
                            limit=10,
                        )
                        if devsecops_identity_activity["event_count"]:
                            factors.append(
                                "devsecops_identity_correlation:true"
                            )
                            factors.append(
                                "devsecops_identity_events:"
                                f"{devsecops_identity_activity['event_count']}"
                            )
                            factors.append(
                                "devsecops_identity_risk_level:"
                                f"{devsecops_identity_activity['risk_level']}"
                            )
                            for signal in devsecops_identity_activity["signals"][:8]:
                                factors.append(f"devsecops_identity_signal:{signal}")
                            boost = min(
                                15.0,
                                max(
                                    5.0,
                                    float(devsecops_identity_activity["max_risk_score"]) * 0.12,
                                ),
                            )
                            risk_score = min(100.0, risk_score + boost)
                            factors.append(f"devsecops_identity_risk_boost:{round(boost, 2)}")
                if actor.get("privileged"):
                    factors.append("devsecops_privileged_actor:true")
            if isinstance(finding, dict):
                critical_count = int(finding.get("critical_count") or 0)
                high_count = int(finding.get("high_count") or 0)
                if critical_count:
                    factors.append(f"devsecops_critical_findings:{critical_count}")
                if high_count:
                    factors.append(f"devsecops_high_findings:{high_count}")
                if finding.get("secret_detected"):
                    factors.append("devsecops_secret_detected:true")
                cve_ids = finding.get("cve_ids")
                if isinstance(cve_ids, list):
                    factors.extend(f"devsecops_cve:{item}" for item in cve_ids[:8] if item)
            if isinstance(controls, dict):
                if controls.get("production_target"):
                    factors.append("devsecops_production_target:true")
                if controls.get("deployment_blocked"):
                    factors.append("devsecops_deployment_blocked:true")
            if isinstance(signals, list):
                factors.extend(f"devsecops_signal:{item}" for item in signals if item)
        return {
            "event_id": event.id,
            "source_event_id": event.event_id,
            "source": event.source,
            "target": event.entity_id or "unknown:unknown",
            "event_type": event.event_type,
            "severity": event.severity,
            "entity_id": event.entity_id,
            "entity_type": event.entity_type,
            "mitre_tags": mitre_tags,
            "normalized_payload": normalized_payload,
            "identity_activity": activity,
            "devsecops_context": devsecops_context if isinstance(devsecops_context, dict) else {},
            "devsecops_identity_activity": devsecops_identity_activity,
            "risk_score": round(risk_score, 2),
            "risk_level": AutonomyService._risk_level(risk_score),
            "factors": list(dict.fromkeys(factors)),
        }

    @staticmethod
    def issue_verdict_from_threat_event(
        db: Session,
        *,
        event_id: str,
        execution_controls: dict | None = None,
    ) -> dict:
        event = (
            db.query(ThreatEvent)
            .filter((ThreatEvent.id == event_id) | (ThreatEvent.event_id == event_id))
            .first()
        )
        if not isinstance(event, ThreatEvent):
            return {"status": "not_found", "event_id": event_id}

        perception = AutonomyService._threat_event_perception(event, db=db)
        base_controls = {
            **(execution_controls or {}),
            "threat_event_id": event.id,
            "perception": perception,
            "aresx_contract": "threat_event.v1",
        }
        mcp_context = normalize_mcp_context(
            base_controls.get("mcp_context")
            if isinstance(base_controls.get("mcp_context"), dict)
            else {},
            target=str(perception["target"]),
        )
        perception_factors = [
            *[str(item) for item in perception["factors"]],
            *mcp_risk_factors(mcp_context),
        ]
        enriched_factors, rag_context = AutonomyService._enrich_with_rag(
            perception=perception,
            factors=list(dict.fromkeys(perception_factors)),
            controls=base_controls,
        )
        controls = {
            **base_controls,
            "mcp_context": mcp_context,
            "rag_context": rag_context,
            "rag_references": [
                item.get("doc_id")
                for item in rag_context.get("references", [])
                if isinstance(item, dict) and item.get("doc_id")
            ],
        }
        verdict = generate_verdict(
            target=str(perception["target"]),
            risk_score=float(perception["risk_score"]),
            factors=enriched_factors,
            execution_controls=controls,
        )
        recommended_action = {
            "action_type": verdict.get("action_type", "observe"),
            "target": perception["target"],
            "parameters": {
                "source": event.source,
                "event_id": event.event_id,
                "entity_type": event.entity_type,
            },
            "priority": 1,
        }
        verdict.update(
            {
                "threat_event_id": event.id,
                "status": "approved" if not verdict.get("requires_human") else "pending",
                "severity": perception["risk_level"],
                "recommended_actions": [recommended_action],
                "primary_action": verdict.get("action_type", "observe"),
                "confidence_score": verdict.get("confidence", 0.0),
                "requires_human_approval": verdict.get("requires_human", False),
                "policy_rule": str(
                    verdict.get("execution_controls", {})
                    .get("policy_result", {})
                    .get("code", "")
                ),
                "ttl_seconds": 3600,
                "xai_explanation": {
                    "method": "heuristic",
                    "summary": verdict.get("justification_xai", ""),
                    "top_factors": perception["factors"][:5],
                },
            }
        )
        verdict["signature"] = sign_payload({k: v for k, v in verdict.items() if k != "signature"})
        AutonomyService.persist_verdict(db, verdict)
        risk_memory = record_risk_memory(db, verdict=verdict)
        audit_autonomy_event(
            db,
            verdict_id=str(verdict.get("verdict_id", "")),
            actor="redqueen",
            action="aresx_verdict_emitted",
            result={
                "threat_event_id": event.id,
                "source": event.source,
                "event_id": event.event_id,
                "risk_score": verdict.get("risk_score"),
                "action_type": verdict.get("action_type"),
                "requires_human": verdict.get("requires_human"),
            },
        )
        return {
            "status": "ok",
            "event_id": event.id,
            "source_event_id": event.event_id,
            "perception": perception,
            "risk": {
                "risk_score": perception["risk_score"],
                "risk_level": perception["risk_level"],
                "scoring_model": "redqueen.aresx_event_rules.v1",
            },
            "risk_memory": risk_memory,
            "verdict": verdict,
        }

    @staticmethod
    def execute_verdict(
        db: Session,
        *,
        verdict: dict,
        human_approved: bool,
        approval_evidence: dict | None = None,
    ) -> dict:
        AutonomyService.persist_verdict(db, verdict)

        validation = validate_verdict(verdict)
        if not validation.valid:
            rejection: dict[str, object] = {
                "status": "rejected",
                "code": validation.code,
                "detail": validation.detail,
            }
            result = build_execution_result(
                verdict=verdict,
                execution={"status": "failed", "duration_ms": 0, "executed_steps": []},
            )
            AutonomyService.persist_execution_result(db, result)
            audit_autonomy_event(
                db,
                verdict_id=str(verdict.get("verdict_id", "")),
                actor="ares",
                action="execution_rejected",
                result={"code": validation.code, "detail": validation.detail},
            )
            rejection["result"] = result
            return rejection

        if verdict.get("requires_human") and not human_approved:
            audit_autonomy_event(
                db,
                verdict_id=str(verdict.get("verdict_id", "")),
                actor="ares",
                action="execution_pending_human_approval",
                result={"reason": "requires_human", "action_type": verdict.get("action_type")},
            )
            return {
                "status": "pending_human_approval",
                "verdict_id": verdict.get("verdict_id"),
            }

        controls = verdict.get("execution_controls") or {}
        dry_run = bool(controls.get("dry_run", False))
        if verdict.get("requires_human") and not dry_run:
            approval_check = verify_approval_payload(verdict=verdict, approval=approval_evidence)
            if not approval_check.get("valid", False):
                code = str(approval_check.get("code") or "approval_invalid")
                detail = str(approval_check.get("detail") or "Human approval evidence is invalid")
                audit_autonomy_event(
                    db,
                    verdict_id=str(verdict.get("verdict_id", "")),
                    actor="ares",
                    action="execution_rejected",
                    result={"code": code, "detail": detail},
                )
                return {
                    "status": "rejected",
                    "code": code,
                    "detail": detail,
                    "verdict_id": verdict.get("verdict_id"),
                }
            audit_autonomy_event(
                db,
                verdict_id=str(verdict.get("verdict_id", "")),
                actor="human",
                action="execution_approved",
                result={
                    "approver": approval_evidence.get("approver") if approval_evidence else "",
                    "approval_signature": approval_evidence.get("signature") if approval_evidence else "",
                },
            )
            if approval_evidence:
                AutonomyService.persist_approval(db, approval_evidence)

        plan = build_plan(verdict)
        advisor_review = review_plan(verdict=verdict, plan=plan, controls=controls)
        plan["advisor_review"] = advisor_review
        firewall_decision = evaluate_internal_firewall(
            verdict=verdict,
            plan=plan,
            advisor_review=advisor_review,
            controls=controls,
        )
        plan["internal_firewall"] = {
            "allowed": firewall_decision.allowed,
            "code": firewall_decision.code,
            "detail": firewall_decision.detail,
            "severity": firewall_decision.severity,
            "evidence": firewall_decision.evidence,
        }
        if not firewall_decision.allowed:
            execution = {
                "status": "failed",
                "duration_ms": 0,
                "executed_steps": [],
                "rollback_events": [],
                "error": firewall_decision.detail,
            }
            result = build_execution_result(verdict=verdict, execution=execution)
            AutonomyService.persist_execution_result(db, result)
            audit_autonomy_event(
                db,
                verdict_id=str(verdict.get("verdict_id", "")),
                actor="ares_firewall",
                action="execution_blocked",
                result=plan["internal_firewall"],
            )
            return {
                "status": "rejected",
                "code": firewall_decision.code,
                "detail": firewall_decision.detail,
                "verdict_id": verdict.get("verdict_id"),
                "plan": plan,
                "result": result,
            }
        execution = execute_plan(plan, controls=controls)
        result = build_execution_result(verdict=verdict, execution=execution)
        AutonomyService.persist_execution_result(db, result)
        audit_autonomy_event(
            db,
            verdict_id=str(verdict.get("verdict_id", "")),
            actor="ares",
            action="execution_completed",
            result={
                "status": execution.get("status"),
                "duration_ms": execution.get("duration_ms", 0),
                "result_hash": result.get("result_hash"),
                "advisor_review": advisor_review,
            },
        )

        return {
            "status": "executed" if execution.get("status") == "success" else "failed",
            "plan": plan,
            "execution": execution,
            "result": result,
        }

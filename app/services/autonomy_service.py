from __future__ import annotations

import json
from datetime import datetime

from sqlalchemy.orm import Session

from app.ares.advisor import review_plan
from app.ares.approval import verify_approval_payload
from app.ares.executor import execute_plan
from app.ares.memory import read_ares_memory
from app.ares.monitor import evaluate_ares_health
from app.ares.planner import build_plan
from app.ares.reporter import build_execution_result
from app.ares.validator import validate_verdict
from app.core.audit import audit_autonomy_event
from app.core.mcp_context import mcp_risk_factors, normalize_mcp_context
from app.models.approval_record import ApprovalRecord
from app.models.execution_result import ExecutionResult
from app.models.threat_model import ThreatModel
from app.models.verdict import Verdict
from app.redqueen.decision_engine import generate_verdict
from app.redqueen.memory import recall_threat_context
from app.redqueen.perception import build_threat_perception
from app.redqueen.risk_memory import read_entity_risk_memory, record_risk_memory
from app.redqueen.risk_scorer import score_perception
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
            target=str(verdict_data.get("target", "unknown")),
            action_type=str(verdict_data.get("action_type", "observe")),
            risk_score=float(verdict_data.get("risk_score", 0.0)),
            confidence=float(verdict_data.get("confidence", 0.0)),
            factors=json.dumps(verdict_data.get("factors", []), ensure_ascii=False),
            justification_xai=str(verdict_data.get("justification_xai", "")),
            policy_check=bool(verdict_data.get("policy_check", False)),
            requires_human=bool(verdict_data.get("requires_human", False)),
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
            status=str(result_data.get("status", "unknown")),
            duration_ms=int(result_data.get("duration_ms", 0)),
            evidence=json.dumps(result_data.get("evidence", []), ensure_ascii=False),
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
        verdict = generate_verdict(
            target=target,
            risk_score=risk_score,
            factors=factors,
            execution_controls={**controls, "mcp_context": mcp_context},
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

        factors = [
            *perception.get("factors", []),
            f"scoring_model:{score['scoring_model']}",
            *mcp_risk_factors(mcp_context),
        ]
        if memory:
            factors.append(f"memory_matches:{len(memory)}")
        if mcp_context:
            factors.append("mcp_context_present")

        controls = {
            **(execution_controls or {}),
            "threat_id": threat_id,
            "perception": perception,
            "risk_score_inputs": score["score_inputs"],
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

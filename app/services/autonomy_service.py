from __future__ import annotations

import json
from datetime import datetime

from sqlalchemy.orm import Session

from app.ares.executor import execute_plan
from app.ares.planner import build_plan
from app.ares.reporter import build_execution_result
from app.ares.validator import validate_verdict
from app.models.execution_result import ExecutionResult
from app.models.threat_model import ThreatModel
from app.models.verdict import Verdict
from app.redqueen.decision_engine import generate_verdict
from app.redqueen.memory import recall_threat_context
from app.redqueen.perception import build_threat_perception
from app.redqueen.risk_scorer import score_perception
from app.repositories.execution_result_repository import ExecutionResultRepository
from app.repositories.threat_repository import ThreatRepository
from app.repositories.verdict_repository import VerdictRepository


class AutonomyService:
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
    def issue_verdict(
        db: Session,
        *,
        target: str,
        risk_score: float,
        factors: list[str],
        execution_controls: dict | None = None,
    ) -> dict:
        verdict = generate_verdict(
            target=target,
            risk_score=risk_score,
            factors=factors,
            execution_controls=execution_controls or {},
        )
        AutonomyService.persist_verdict(db, verdict)
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
        score = score_perception(perception)
        memory = recall_threat_context(
            db,
            target=str(perception.get("target") or ""),
            fingerprint=str(getattr(threat, "fingerprint", "") or "") or None,
        )
        mcp_context = (
            execution_controls.get("mcp_context")
            if isinstance(execution_controls, dict)
            and isinstance(execution_controls.get("mcp_context"), dict)
            else {}
        )

        factors = [
            *perception.get("factors", []),
            f"scoring_model:{score['scoring_model']}",
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
        return {
            "status": "ok",
            "threat_id": threat_id,
            "perception": perception,
            "risk": score,
            "memory": memory,
            "verdict": verdict,
        }

    @staticmethod
    def execute_verdict(
        db: Session,
        *,
        verdict: dict,
        human_approved: bool,
    ) -> dict:
        AutonomyService.persist_verdict(db, verdict)

        if verdict.get("requires_human") and not human_approved:
            return {
                "status": "pending_human_approval",
                "verdict_id": verdict.get("verdict_id"),
            }

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
            rejection["result"] = result
            return rejection

        plan = build_plan(verdict)
        controls = verdict.get("execution_controls") or {}
        execution = execute_plan(plan, controls=controls)
        result = build_execution_result(verdict=verdict, execution=execution)
        AutonomyService.persist_execution_result(db, result)

        return {
            "status": "executed" if execution.get("status") == "success" else "failed",
            "plan": plan,
            "execution": execution,
            "result": result,
        }

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.security import require_admin_or_control_token
from app.ctf_lab.service import get_scenario, list_scenarios, replay_scenario
from app.db.session import get_db

router = APIRouter(
    prefix="/api/v1/ctf-lab",
    tags=["ctf-lab"],
    dependencies=[Depends(require_admin_or_control_token)],
)


class ReplayScenarioRequest(BaseModel):
    run_label: str = Field(default="", max_length=80)


@router.get("/status")
def ctf_lab_status():
    return {
        "module": "ctf_lab",
        "status": "enabled",
        "mode": "defensive_synthetic_lab_only",
        "capabilities": [
            "scenario_registry",
            "synthetic_event_replay",
            "attack_reality_scoring",
            "ares_hunter_trace_scorecard",
            "false_positive_training",
        ],
        "boundaries": [
            "owned_lab_environment_only",
            "no_external_targets",
            "dry_run_default",
            "operator_approval_before_disruptive_actions",
        ],
    }


@router.get("/scenarios")
def read_scenarios():
    return list_scenarios()


@router.get("/scenarios/{scenario_id}")
def read_scenario(scenario_id: str):
    scenario = get_scenario(scenario_id)
    if not scenario:
        raise HTTPException(status_code=404, detail="CTF scenario not found")
    return scenario


@router.post("/scenarios/{scenario_id}/replay")
def replay_ctf_scenario(
    scenario_id: str,
    payload: ReplayScenarioRequest | None = None,
    db: Session = Depends(get_db),
):
    payload = payload or ReplayScenarioRequest()
    result = replay_scenario(db, scenario_id, run_label=payload.run_label)
    if not result:
        raise HTTPException(status_code=404, detail="CTF scenario not found")
    return result

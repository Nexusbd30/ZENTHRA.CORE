from __future__ import annotations

import pytest

from app.actions.devsecops import DevSecOpsAction
from app.core.settings import settings


def devsecops_controls():
    return {
        "action_domain": "devsecops",
        "devsecops_provider": "github_actions",
        "change_ticket": "DEVSECOPS-001",
        "mcp_context": {"evidence_refs": ["case-1"]},
        "perception": {
            "devsecops_context": {
                "pipeline": {
                    "provider": "github_actions",
                    "pipeline_id": "release-prod",
                    "repository": "zenthra/core-security",
                    "environment": "production",
                },
                "actor": {"identity_id": "devops@corp.com", "privileged": True},
                "finding": {"secret_detected": True, "critical_count": 1},
                "controls": {"production_target": True, "deployment_blocked": True},
            }
        },
    }


def test_devsecops_action_translates_block_deployment_to_command(monkeypatch):
    monkeypatch.setattr(settings, "ACTION_EXECUTION_MODE", "mock")
    action = DevSecOpsAction()

    result = action.execute_step(
        {"step": "block_deployment", "payload": {"target": "repository:zenthra/core-security"}},
        devsecops_controls(),
    )

    assert result.status == "ok"
    assert result.evidence == {
        "mode": "mock",
        "command": "devsecops.block_deployment",
        "payload": {
            "target": "repository:zenthra/core-security",
            "action_domain": "devsecops",
            "provider": "github_actions",
            "change_ticket": "DEVSECOPS-001",
            "mcp_context": {"evidence_refs": ["case-1"]},
            "pipeline": {
                "provider": "github_actions",
                "pipeline_id": "release-prod",
                "repository": "zenthra/core-security",
                "environment": "production",
            },
            "actor": {"identity_id": "devops@corp.com", "privileged": True},
            "finding": {"secret_detected": True, "critical_count": 1},
            "controls": {"production_target": True, "deployment_blocked": True},
        },
        "status": "ok",
    }
    assert result.rollback_payload == {
        "step": "block_deployment",
        "target": "repository:zenthra/core-security",
        "provider": "github_actions",
        "change_ticket": "DEVSECOPS-001",
        "pipeline": {
            "provider": "github_actions",
            "pipeline_id": "release-prod",
            "repository": "zenthra/core-security",
            "environment": "production",
        },
    }


def test_devsecops_action_does_not_create_rollback_for_pipeline_token_revocation(monkeypatch):
    monkeypatch.setattr(settings, "ACTION_EXECUTION_MODE", "mock")
    action = DevSecOpsAction()

    result = action.execute_step(
        {"step": "revoke_pipeline_token", "payload": {"target": "pipeline:release-prod"}},
        devsecops_controls(),
    )

    assert result.evidence["command"] == "devsecops.revoke_pipeline_token"
    assert result.rollback_payload is None


def test_devsecops_action_rejects_unsupported_provider_action(monkeypatch):
    monkeypatch.setattr(settings, "ACTION_EXECUTION_MODE", "mock")
    controls = devsecops_controls()
    controls["devsecops_provider"] = "sonarqube"
    action = DevSecOpsAction()

    with pytest.raises(ValueError, match="does not support command"):
        action.execute_step(
            {"step": "block_deployment", "payload": {"target": "repository:zenthra/core-security"}},
            controls,
        )

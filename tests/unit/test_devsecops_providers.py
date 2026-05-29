from __future__ import annotations

import pytest

from app.secops.providers import (
    action_preflight_payload,
    provider_capability_payload,
    strongest_supported_devsecops_action,
    validate_devsecops_action,
    validate_devsecops_command,
)


def test_github_actions_supports_full_devsecops_action_set():
    payload = provider_capability_payload("github-actions")

    assert payload["provider"] == "github_actions"
    assert "block_deployment" in payload["actions"]
    assert "revoke_pipeline_token" in payload["actions"]
    assert "devsecops.quarantine_artifact" in payload["commands"]


def test_sonarqube_rejects_direct_deployment_block():
    with pytest.raises(ValueError, match="does not support action"):
        validate_devsecops_action("sonarqube", "block_deployment")


def test_jenkins_rejects_artifact_quarantine_command():
    with pytest.raises(ValueError, match="does not support command"):
        validate_devsecops_command("jenkins", "devsecops.quarantine_artifact")


def test_devsecops_preflight_reports_supported_actions():
    payload = action_preflight_payload("jenkins", "quarantine_artifact")

    assert payload["provider"] == "jenkins"
    assert payload["supported"] is False
    assert payload["recommended_action"] == "block_deployment"
    assert payload["adjusted"] is True
    assert payload["reason"] == "provider_capability_missing"
    assert "block_deployment" in payload["supported_actions"]


def test_secops_internal_provider_supports_materialized_correlation_actions():
    payload = provider_capability_payload("secops")

    assert payload["provider"] == "secops"
    assert "block_deployment" in payload["actions"]
    assert "revoke_pipeline_token" in payload["actions"]


def test_strongest_supported_devsecops_action_degrades_for_scanner_provider():
    assert strongest_supported_devsecops_action("sonarqube", 95) == "require_release_approval"
    assert strongest_supported_devsecops_action("unknown-provider", 95) == "soar_delegate"

from __future__ import annotations

import pytest

from app.core.settings import settings


def monitor_headers(monkeypatch):
    monkeypatch.setattr(settings, "VAELQORIX_CONTROL_TOKEN", "control-test-token")
    monkeypatch.setattr(settings, "CONTROL_TOKEN_CAPABILITIES", ",".join(__import__("app.core.enterprise_security", fromlist=["ENTERPRISE_CAPABILITIES"]).ENTERPRISE_CAPABILITIES))
    return {"Authorization": "Bearer control-test-token"}


@pytest.mark.asyncio
async def test_ctf_lab_lists_defensive_scenarios(test_client, monkeypatch):
    response = await test_client.get("/api/v1/ctf-lab/scenarios", headers=monitor_headers(monkeypatch))

    assert response.status_code == 200
    body = response.json()
    assert body["schema"] == "vaelqorix.ctf_lab.defensive.v1"
    assert body["mode"] == "defensive_synthetic_lab_only"
    assert body["count"] >= 3
    assert "no_external_targets" in body["guardrails"]
    assert {item["id"] for item in body["items"]} >= {
        "identity_credential_foothold",
        "endpoint_lateral_movement",
        "benign_noise_triage",
    }


@pytest.mark.asyncio
async def test_ctf_lab_replays_scenario_into_attack_analysis_and_hunter_trace(
    test_client,
    db_session,
    monkeypatch,
):
    headers = monitor_headers(monkeypatch)

    response = await test_client.post(
        "/api/v1/ctf-lab/scenarios/identity_credential_foothold/replay",
        headers=headers,
        json={"run_label": "unit-ctf-identity"},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["schema"] == "vaelqorix.ctf_lab.replay_result.v1"
    assert body["status"] == "passed"
    assert body["synthetic_events_inserted"] == 3
    assert body["actual_classification"] in {"confirmed_attack", "probable_attack"}
    assert body["scorecard"]["detection_passed"] is True
    assert body["hunter_trace"]["mode"] == "defensive_hunt_inside_owned_environment"
    assert body["hunter_trace"]["expulsion_readiness"] == "operator_gated"
    assert "synthetic_events_only" in body["guardrails"]


@pytest.mark.asyncio
async def test_ctf_lab_replays_benign_noise_without_over_response(
    test_client,
    db_session,
    monkeypatch,
):
    response = await test_client.post(
        "/api/v1/ctf-lab/scenarios/benign_noise_triage/replay",
        headers=monitor_headers(monkeypatch),
        json={"run_label": "unit-ctf-benign"},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "passed"
    assert body["actual_classification"] == "false_positive_likely"
    assert body["analysis"]["recommended_action"] == "observe"
    assert body["scorecard"]["requires_human_review"] is True


@pytest.mark.asyncio
async def test_ctf_lab_unknown_scenario_returns_not_found(test_client, monkeypatch):
    response = await test_client.get(
        "/api/v1/ctf-lab/scenarios/not-present",
        headers=monitor_headers(monkeypatch),
    )

    assert response.status_code == 404

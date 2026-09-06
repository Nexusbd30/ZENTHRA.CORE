from __future__ import annotations

import pytest

from app.core.settings import settings


def monitor_headers(monkeypatch):
    monkeypatch.setattr(settings, "VAELQORIX_MONITOR_TOKEN", "monitor-test-token")
    return {"Authorization": "Bearer monitor-test-token"}


@pytest.mark.asyncio
async def test_autonomy_maturity_control_exposes_redqueen_and_ares(test_client, monkeypatch):
    response = await test_client.get("/api/v1/control/maturity", headers=monitor_headers(monkeypatch))

    assert response.status_code == 200
    body = response.json()
    assert body["schema"] == "vaelqorix.autonomy_control.maturity.v1"
    assert body["overall_score"] >= 70
    assert body["redqueen"]["module"] == "redqueen"
    assert body["ares"]["module"] == "ares"
    assert body["redqueen"]["dimensions"]
    assert body["ares"]["dimensions"]
    assert "signed verdict payloads" in " ".join(body["redqueen"]["strengths"])
    assert "kill switch" in " ".join(body["ares"]["strengths"])
    assert body["shared_rectification"]


@pytest.mark.asyncio
async def test_autonomy_maturity_module_endpoints(test_client, monkeypatch):
    headers = monitor_headers(monkeypatch)
    redqueen = await test_client.get("/api/v1/control/maturity/redqueen", headers=headers)
    ares = await test_client.get("/api/v1/control/maturity/ares", headers=headers)

    assert redqueen.status_code == 200
    assert ares.status_code == 200
    assert redqueen.json()["concept"].startswith("defensive autonomous reasoning")
    assert ares.json()["concept"].startswith("defensive execution")


@pytest.mark.asyncio
async def test_autonomy_capability_map_defines_ctf_grc_and_pentest_boundaries(
    test_client, monkeypatch
):
    response = await test_client.get("/api/v1/control/capabilities", headers=monitor_headers(monkeypatch))

    assert response.status_code == 200
    body = response.json()
    assert body["schema"] == "vaelqorix.autonomy_control.capability_map.v1"

    capabilities = {item["key"]: item for item in body["capabilities"]}
    assert capabilities["defensive_ctf_lab"]["status"] == "ready_to_build"
    assert capabilities["technical_grc"]["status"] == "foundation_ready"
    assert capabilities["authorized_pentesting"]["status"] == "blocked_until_guardrails"
    assert "no public targets" in capabilities["defensive_ctf_lab"]["required_guardrails"]
    assert "signed authorization and target allowlist" in capabilities["authorized_pentesting"]["required_guardrails"]
    assert body["next_build_order"] == [
        "defensive_ctf_lab",
        "technical_grc",
        "authorized_pentesting_guardrails",
    ]

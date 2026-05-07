import pytest

from app.core.settings import settings
from app.models.audit_record import AuditRecord


def autonomy_headers(monkeypatch):
    monkeypatch.setattr(settings, "ZENTHRA_MONITOR_TOKEN", "monitor-test-token")
    return {"Authorization": "Bearer monitor-test-token"}


@pytest.mark.asyncio
async def test_lifecycle_writes_verifiable_audit_chain(test_client, db_session, monkeypatch):
    before = db_session.query(AuditRecord).count()

    resp = await test_client.post(
        "/api/v1/ares/lifecycle",
        headers=autonomy_headers(monkeypatch),
        json={
            "target": "audit-asset-01",
            "risk_score": 78,
            "factors": ["suspicious_auth"],
            "execution_controls": {"change_ticket": "AUDIT-001"},
            "human_approved": True,
        },
    )
    assert resp.status_code == 200, resp.text
    verdict_id = resp.json()["verdict"]["verdict_id"]

    after = db_session.query(AuditRecord).count()
    assert after >= before + 2

    audit_resp = await test_client.get(
        f"/api/v1/ares/audit?verdict_id={verdict_id}",
        headers=autonomy_headers(monkeypatch),
    )
    assert audit_resp.status_code == 200
    body = audit_resp.json()
    assert body["count"] >= 2
    assert {item["action"] for item in body["items"]} >= {
        "verdict_issued",
        "execution_completed",
    }

    verify_resp = await test_client.get(
        "/api/v1/ares/audit/verify",
        headers=autonomy_headers(monkeypatch),
    )
    assert verify_resp.status_code == 200
    assert verify_resp.json()["valid"] is True

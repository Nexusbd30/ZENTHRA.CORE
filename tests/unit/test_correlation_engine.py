from datetime import datetime, timedelta

from app.models.threat_model import ThreatModel
from app.services.correlation_engine import CorrelationEngine


class FakePromClient:
    def __init__(self, alerts):
        self._alerts = alerts

    def get_firing_alerts(self):
        return list(self._alerts)

    @staticmethod
    def build_fingerprint(labels, target_service=None):
        alertname = str(labels.get("alertname", "")).strip()
        instance = str(labels.get("instance", "")).strip()
        job = str(labels.get("job", "")).strip()
        service = str(labels.get("service", "")).strip() or (target_service or "").strip()
        base = f"{alertname}|{instance}|{job}"
        return f"{base}|{service}" if service else base


def _alert(alertname, instance="node-1", job="prometheus", severity="critical"):
    return {
        "labels": {
            "alertname": alertname,
            "instance": instance,
            "job": job,
            "severity": severity,
        },
        "annotations": {"summary": f"{alertname} firing"},
        "state": "firing",
        "activeAt": "2026-04-14T00:00:00Z",
        "value": "1",
    }


def test_correlation_engine_creates_updates_and_resolves_incidents(db_session, monkeypatch):
    monkeypatch.setattr("app.services.correlation_engine.AUTO_RESOLVE_GRACE_MINUTES", 0)

    engine = CorrelationEngine(FakePromClient([_alert("BackendDown")]))
    first = engine.run_correlation(db_session)

    assert first["created_count"] == 1
    assert first["updated_count"] == 0

    incident = db_session.query(ThreatModel).one()
    assert incident.siem_metadata["status"] == "open"
    assert incident.siem_metadata["occurrences"] == 1

    second = engine.run_correlation(db_session)
    assert second["created_count"] == 0
    assert second["updated_count"] == 1

    db_session.refresh(incident)
    assert incident.siem_metadata["status"] == "open"

    meta = dict(incident.siem_metadata or {})
    meta["last_seen_at"] = (datetime.utcnow() - timedelta(minutes=5)).isoformat()
    incident.siem_metadata = meta
    db_session.add(incident)
    db_session.commit()

    resolver = CorrelationEngine(FakePromClient([]))
    third = resolver.run_correlation(db_session)

    assert third["resolved_count"] == 1


def test_correlation_engine_creates_composite_incident(db_session):
    alerts = [_alert("HighLatencyP95"), _alert("HighErrorRate")]
    engine = CorrelationEngine(FakePromClient(alerts))

    result = engine.run_correlation(db_session)

    assert result["created_count"] == 3
    assert "BackendDegradation" in result["rules_triggered"]

    fingerprints = {row.fingerprint for row in db_session.query(ThreatModel).all()}
    assert "composite|BackendDegradation|HighErrorRate|HighLatencyP95" in fingerprints

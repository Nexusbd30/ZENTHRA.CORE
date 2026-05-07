from app.redqueen.decision_engine import generate_verdict
from app.redqueen.risk_memory import read_entity_risk_memory, record_risk_memory


def test_redqueen_risk_memory_tracks_entity_profile_and_trend(db_session, monkeypatch):
    target = "risk-memory-asset-001"
    monkeypatch.setattr(
        "app.redqueen.decision_engine.ai_provider.complete",
        lambda *_args, **_kwargs: (
            '{"action_type":"soar_delegate","confidence":0.80,'
            '"reasoning":"first observation","factors":["baseline"]}'
        ),
    )
    first = generate_verdict(
        target=target,
        risk_score=55,
        factors=["bruteforce"],
        execution_controls={},
    )
    first_memory = record_risk_memory(db_session, verdict=first)

    monkeypatch.setattr(
        "app.redqueen.decision_engine.ai_provider.complete",
        lambda *_args, **_kwargs: (
            '{"action_type":"identity_lockdown","confidence":0.90,'
            '"reasoning":"risk increased","factors":["credential_stuffing"]}'
        ),
    )
    second = generate_verdict(
        target=target,
        risk_score=76,
        factors=["credential_stuffing"],
        execution_controls={"change_ticket": "TEST-RISK-MEMORY-001"},
    )
    second_memory = record_risk_memory(db_session, verdict=second)
    memory = read_entity_risk_memory(db_session, target=target)

    assert first_memory["trend"] == "new"
    assert second_memory["trend"] == "rising"
    assert memory["profile"]["entity_id"] == target
    assert memory["profile"]["anomaly_score"] == 76
    assert memory["profile"]["baseline_vector"][:2] == [76.0, 55.0]
    assert memory["scores"][0]["trend"] == "rising"

from __future__ import annotations

from datetime import datetime, timedelta
from uuid import uuid4

from app.models.approval_record import ApprovalRecord
from app.models.entity_profile import EntityProfile
from app.models.execution_result import ExecutionResult
from app.models.risk_score import RiskScore
from app.models.verdict import Verdict
from app.repositories.approval_repository import ApprovalRepository
from app.repositories.execution_result_repository import ExecutionResultRepository
from app.repositories.risk_repository import RiskRepository
from app.repositories.threat_repository import ThreatRepository
from app.repositories.user_repository import UserRepository
from app.repositories.verdict_repository import VerdictRepository
from app.schemas.threat_schema import ThreatCreate, ThreatUpdate
from app.schemas.user_schema import UserCreate, UserUpdate


def test_threat_repository_crud_filters_and_invalid_ids(db_session):
    repo = ThreatRepository(db_session)
    assert repo._normalize_id("not-a-uuid") is None

    open_threat = repo.create(
        ThreatCreate(
            title="Open Threat",
            source="sentinel/siem",
            description="open",
            level="high",
            category="other",
            score=90,
            target_service="api",
        )
    )
    open_threat.fingerprint = "fp-open"
    open_threat.siem_metadata = {"status": "open"}

    closed_threat = repo.create(
        ThreatCreate(
            title="Closed Threat",
            source="wazuh/edr",
            description="closed",
            level="low",
            category="other",
            score=20,
            target_service="host",
        )
    )
    closed_threat.fingerprint = "fp-closed"
    closed_threat.siem_metadata = {"status": "closed"}
    db_session.commit()

    assert repo.get_by_id("bad") is None
    assert repo.get_by_id(open_threat.id).title == "Open Threat"
    assert len(repo.get_all(skip=0, limit=10)) >= 2
    assert repo.get_all_filtered(source="sentinel/siem")[0].id == open_threat.id
    assert repo.get_all_filtered(fingerprint="fp-closed")[0].id == closed_threat.id
    assert repo.get_all_filtered(title="open")[0].id == open_threat.id
    assert repo.get_all_filtered(active=True)[0].id == open_threat.id
    assert repo.get_all_filtered(active=False)[0].id == closed_threat.id
    assert repo.get_all_filtered(sort="created_at", order="asc")

    updated = repo.update(open_threat.id, ThreatUpdate(title="Updated Threat", score=95))
    assert updated.title == "Updated Threat"
    assert updated.score == 95
    assert repo.update("bad", ThreatUpdate(title="ignored")) is None

    assert repo.delete("bad") is False
    assert repo.delete(str(uuid4())) is False
    assert repo.delete(closed_threat.id) is True
    assert repo.get_by_id(closed_threat.id) is None


def test_user_repository_crud_filtering_and_update_rules(db_session):
    first = UserRepository.create_user(
        db_session,
        UserCreate(
            email="repo-user@example.com",
            full_name="Repo User",
            password="password123",
            role="user",
            is_active=True,
        ),
        hashed_password="hashed",
    )
    second = UserRepository.create_user(
        db_session,
        UserCreate(
            email="repo-admin@example.com",
            full_name="Repo Admin",
            password="password123",
            role="admin",
            is_active=False,
        ),
        hashed_password="hashed-admin",
    )

    assert UserRepository.get_user_by_email(db_session, first.email).id == first.id
    assert UserRepository.get_user_by_id(db_session, first.id).email == first.email
    assert UserRepository.get_user_by_email(db_session, "missing@example.com") is None

    updated = UserRepository.update_user(
        db_session,
        first,
        UserUpdate(full_name="Updated User", role="", is_active=False),
    )
    assert updated.full_name == "Updated User"
    assert updated.role == "user"
    assert updated.is_active is False

    admins, admin_total = UserRepository.get_users_filtered(db_session, role="admin")
    assert admin_total >= 1
    assert any(user.id == second.id for user in admins)

    inactive, inactive_total = UserRepository.get_users_filtered(db_session, is_active=False)
    assert inactive_total >= 2
    assert any(user.id == first.id for user in inactive)

    searched, search_total = UserRepository.get_users_filtered(db_session, search="repo")
    assert search_total >= 2
    assert {user.email for user in searched} >= {first.email, second.email}

    UserRepository.delete_user(db_session, second)
    assert UserRepository.get_user_by_id(db_session, second.id) is None


def test_risk_approval_execution_and_verdict_repositories(db_session):
    score_old = RiskRepository.create_score(
        db_session,
        RiskScore(
            asset_id="asset-1",
            entity_id="asset-1",
            score_0_100=30,
            risk_score=30,
            risk_level="low",
            timestamp=datetime.utcnow() - timedelta(minutes=5),
        ),
    )
    score_new = RiskRepository.create_score(
        db_session,
        RiskScore(
            asset_id="asset-1",
            entity_id="asset-1",
            score_0_100=80,
            risk_score=80,
            risk_level="high",
            timestamp=datetime.utcnow(),
        ),
    )
    scores = RiskRepository.latest_scores(db_session, "asset-1", limit=2)
    assert [row.id for row in scores] == [score_new.id, score_old.id]

    profile = RiskRepository.upsert_profile(
        db_session,
        EntityProfile(
            entity_id="entity-1",
            entity_type="user",
            baseline_vector="[1]",
            anomaly_score=0.2,
            risk_factors="[]",
        ),
    )
    assert profile.entity_type == "user"

    updated_profile = RiskRepository.upsert_profile(
        db_session,
        EntityProfile(
            entity_id="entity-1",
            entity_type="service",
            baseline_vector="[2]",
            anomaly_score=0.7,
            last_seen=datetime.utcnow(),
            risk_factors='["drift"]',
        ),
    )
    assert updated_profile.entity_type == "service"
    assert RiskRepository.get_profile(db_session, "entity-1").anomaly_score == 0.7
    assert RiskRepository.get_profile(db_session, "missing") is None

    approval = ApprovalRecord(
        verdict_id="verdict-1",
        target="target",
        action_type="observe",
        risk_score=10,
        approver="lead",
        reason="ok",
        signature="sig-1",
    )
    created_approval = ApprovalRepository.create(db_session, approval)
    duplicate_approval = ApprovalRepository.create(
        db_session,
        ApprovalRecord(
            verdict_id="verdict-1",
            target="target",
            action_type="observe",
            risk_score=10,
            approver="lead",
            reason="duplicate",
            signature="sig-1",
        ),
    )
    assert duplicate_approval.approval_id == created_approval.approval_id
    assert ApprovalRepository.list_by_verdict(db_session, "verdict-1")[0].signature == "sig-1"

    result = ExecutionResultRepository.create(
        db_session,
        ExecutionResult(
            verdict_id="verdict-1",
            ares_id="ares-1",
            action_type="observe",
            target_entity="target",
            status="success",
        ),
    )
    assert ExecutionResultRepository.list_by_verdict(db_session, "verdict-1")[0].id == result.id

    verdict = VerdictRepository.create(
        db_session,
        Verdict(
            verdict_id="verdict-1",
            target="target",
            action_type="observe",
            risk_score=10,
            confidence=0.8,
            signature="sig",
        ),
    )
    assert VerdictRepository.get_by_id(db_session, "verdict-1").verdict_id == verdict.verdict_id
    assert VerdictRepository.get_by_id(db_session, "missing") is None

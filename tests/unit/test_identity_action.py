from __future__ import annotations

import pytest

from app.actions.identity import IdentityAction
from app.core.settings import settings


def test_identity_action_translates_steps_to_provider_commands(monkeypatch):
    monkeypatch.setattr(settings, "ACTION_EXECUTION_MODE", "mock")
    action = IdentityAction()

    result = action.execute_step(
        {"step": "disable_credentials", "payload": {"target": "user:alice@corp.com"}},
        {
            "identity_provider": "entra",
            "action_domain": "identity",
            "change_ticket": "ID-001",
            "mcp_context": {"evidence_refs": ["case-1"]},
        },
    )

    assert result.status == "ok"
    assert result.evidence == {
        "mode": "mock",
        "command": "identity.disable_credentials",
        "payload": {
            "target": "user:alice@corp.com",
            "provider": "entra",
            "action_domain": "identity",
            "change_ticket": "ID-001",
            "mcp_context": {"evidence_refs": ["case-1"]},
            "provider_capabilities": {
                "supports_webhook_bridge": True,
                "notes": "",
            },
        },
        "status": "ok",
    }
    assert result.rollback_payload == {
        "step": "disable_credentials",
        "target": "user:alice@corp.com",
        "provider": "entra",
        "change_ticket": "ID-001",
    }


def test_identity_action_does_not_create_rollback_for_session_revocation(monkeypatch):
    monkeypatch.setattr(settings, "ACTION_EXECUTION_MODE", "mock")
    action = IdentityAction()

    result = action.execute_step(
        {"step": "revoke_sessions", "payload": {"target": "user:alice@corp.com"}},
        {"identity_provider": "okta"},
    )

    assert result.evidence["command"] == "identity.revoke_sessions"
    assert result.rollback_payload is None


def test_identity_action_rejects_unsupported_provider_command(monkeypatch):
    monkeypatch.setattr(settings, "ACTION_EXECUTION_MODE", "mock")
    action = IdentityAction()

    with pytest.raises(ValueError, match="does not support command"):
        action.execute_step(
            {"step": "degrade_privileges", "payload": {"target": "user:alice@corp.com"}},
            {"identity_provider": "auth0"},
        )


def test_identity_action_rejects_unknown_provider(monkeypatch):
    monkeypatch.setattr(settings, "ACTION_EXECUTION_MODE", "mock")
    action = IdentityAction()

    with pytest.raises(ValueError, match="Unsupported identity provider"):
        action.execute_step(
            {"step": "resolve_identity", "payload": {"target": "user:alice@corp.com"}},
            {"identity_provider": "unknown-idp"},
        )

from __future__ import annotations

from app.ares.validator import validate_verdict
from app.core.signing import sign_payload
from app.redqueen.policy_matrix import evaluate_policy


def _signed_verdict(*, controls: dict) -> dict:
    verdict = {
        "verdict_id": "crypto-verdict-1",
        "timestamp": "2026-01-01T00:00:00+00:00",
        "target": "vault/prod/api-key",
        "action_type": "crypto_rotate",
        "confidence": 0.88,
        "risk_score": 78,
        "factors": ["secret_exposure"],
        "policy_check": True,
        "requires_human": True,
        "justification_xai": "Rotate exposed credential.",
        "causal_chain": {},
        "execution_controls": controls,
    }
    verdict["signature"] = sign_payload(verdict)
    return verdict


def test_crypto_rotate_policy_requires_traceability():
    policy = evaluate_policy(score=78, action_type="crypto_rotate")

    assert policy["allowed"] is True
    assert policy["disruptive"] is True
    assert policy["requires_human"] is True


def test_crypto_rotate_validator_rejects_missing_traceability():
    result = validate_verdict(_signed_verdict(controls={}))

    assert result.valid is False
    assert result.code == "execution_control_missing"


def test_crypto_rotate_validator_accepts_change_ticket():
    result = validate_verdict(
        _signed_verdict(controls={"change_ticket": "CHG-CRYPTO-1", "key_id": "kms-key-01"})
    )

    assert result.valid is True
    assert result.code == "ok"

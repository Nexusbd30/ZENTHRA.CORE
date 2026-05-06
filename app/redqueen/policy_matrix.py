from __future__ import annotations


def evaluate_policy(score: float, action_type: str) -> dict:
    requires_human = action_type.startswith("ot_") or score > 95
    allowed = score <= 100 and score >= 0
    return {
        "allowed": allowed,
        "requires_human": requires_human,
        "max_autonomy_score": 95.0,
        "explanation": "policy-matrix-phase-1",
    }

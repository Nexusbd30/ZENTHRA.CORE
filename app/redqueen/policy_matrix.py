from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ActionPolicy:
    min_score: float
    max_score: float
    max_autonomy_score: float
    severity: int
    disruptive: bool = False
    always_requires_human: bool = False


ACTION_POLICIES: dict[str, ActionPolicy] = {
    "observe": ActionPolicy(0, 100, 100, severity=0),
    "soar_delegate": ActionPolicy(0, 100, 90, severity=1),
    "crypto_rotate": ActionPolicy(55, 100, 75, severity=2, disruptive=True),
    "endpoint_isolate": ActionPolicy(50, 100, 82, severity=2, disruptive=True),
    "identity_lockdown": ActionPolicy(65, 100, 78, severity=3, disruptive=True),
    "network_isolate": ActionPolicy(
        85,
        100,
        70,
        severity=4,
        disruptive=True,
        always_requires_human=True,
    ),
}


def _normalize_score(score: float) -> float:
    try:
        return float(score)
    except (TypeError, ValueError):
        return -1.0


def evaluate_policy(score: float, action_type: str) -> dict:
    normalized_score = _normalize_score(score)
    action = str(action_type or "observe").strip().lower()
    policy = ACTION_POLICIES.get(action)

    if not 0 <= normalized_score <= 100:
        return {
            "allowed": False,
            "code": "score_out_of_range",
            "requires_human": True,
            "max_autonomy_score": 0.0,
            "severity": 0,
            "disruptive": False,
            "explanation": "Risk score must be between 0 and 100",
        }

    if policy is None:
        return {
            "allowed": False,
            "code": "action_unknown",
            "requires_human": True,
            "max_autonomy_score": 0.0,
            "severity": 0,
            "disruptive": False,
            "explanation": f"Action '{action}' is not in the RedQueen policy matrix",
        }

    minimum_met = normalized_score >= policy.min_score
    score_not_excessive = normalized_score <= policy.max_score
    allowed = minimum_met and score_not_excessive
    requires_human = (
        policy.always_requires_human
        or normalized_score > policy.max_autonomy_score
        or action.startswith("ot_")
    )

    if not minimum_met:
        code = "risk_below_action_minimum"
        explanation = (
            f"Action '{action}' requires risk >= {policy.min_score}, got {normalized_score}"
        )
    elif not score_not_excessive:
        code = "risk_above_action_maximum"
        explanation = (
            f"Action '{action}' allows risk <= {policy.max_score}, got {normalized_score}"
        )
    elif requires_human:
        code = "human_required"
        explanation = (
            f"Action '{action}' is allowed but requires human approval above "
            f"autonomy score {policy.max_autonomy_score}"
        )
    else:
        code = "ok"
        explanation = f"Action '{action}' is allowed for risk {normalized_score}"

    return {
        "allowed": allowed,
        "code": code,
        "requires_human": requires_human,
        "max_autonomy_score": policy.max_autonomy_score,
        "severity": policy.severity,
        "disruptive": policy.disruptive,
        "explanation": explanation,
    }

from __future__ import annotations

from app.core.ai_provider import ai_provider

SYSTEM_PROMPT = (
    "You are RedQueen XAI. Explain security verdicts in clear, concise Spanish. "
    "Always include: riesgo, accion, razon causal y limitaciones."
)


def generate_xai_explanation(
    *,
    target: str,
    risk_score: float,
    action_type: str,
    confidence: float,
    factors: list[str],
    requires_human: bool,
    causal_chain: dict | None = None,
) -> str:
    factors_text = ", ".join(factors) if factors else "sin factores explicitos"
    user_prompt = (
        f"target={target}; risk_score={risk_score}; action={action_type}; "
        f"confidence={confidence}; requires_human={requires_human}; factors={factors_text}; "
        f"causal_chain={causal_chain or {}}"
    )
    return ai_provider.complete(SYSTEM_PROMPT, user_prompt)

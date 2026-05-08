from __future__ import annotations

from statistics import mean, pstdev

from sqlalchemy.orm import Session

from app.repositories.risk_repository import RiskRepository


def _severity(delta: float, z_score: float) -> str:
    if delta >= 25 or z_score >= 2.5:
        return "critical"
    if delta >= 15 or z_score >= 1.75:
        return "high"
    if delta >= 8 or z_score >= 1.0:
        return "medium"
    if delta <= -15:
        return "falling"
    return "stable"


def analyze_risk_drift(
    db: Session,
    *,
    target: str,
    current_score: float | None = None,
    limit: int = 10,
) -> dict:
    scores = RiskRepository.latest_scores(db, target, limit=max(2, min(limit, 50)))
    historical = [float(row.score_0_100) for row in scores]

    if current_score is None:
        observed = historical[0] if historical else 0.0
        baseline_values = historical[1:]
    else:
        observed = float(current_score)
        baseline_values = historical

    if not baseline_values:
        return {
            "target": target,
            "status": "insufficient_history",
            "severity": "info",
            "current_score": round(observed, 2),
            "baseline_mean": None,
            "delta": 0.0,
            "z_score": 0.0,
            "samples": len(historical),
            "signals": [],
            "recommended_controls": {"dry_run": True},
        }

    baseline_mean = mean(baseline_values)
    baseline_std = pstdev(baseline_values) if len(baseline_values) > 1 else 0.0
    delta = observed - baseline_mean
    z_score = delta / baseline_std if baseline_std > 0 else (delta / 10.0)
    severity = _severity(delta, z_score)

    signals: list[str] = []
    if severity in {"medium", "high", "critical"}:
        signals.append(f"drift:{severity}")
    if delta >= 15:
        signals.append("drift:risk_spike")
    if z_score >= 1.75:
        signals.append("drift:statistical_outlier")
    if delta <= -15:
        signals.append("drift:risk_drop")

    recommended_controls: dict[str, object] = {}
    if severity in {"high", "critical"}:
        recommended_controls["requires_human"] = True
    if severity == "critical":
        recommended_controls["dry_run"] = True

    return {
        "target": target,
        "status": "ok",
        "severity": severity,
        "current_score": round(observed, 2),
        "baseline_mean": round(baseline_mean, 2),
        "baseline_std": round(baseline_std, 2),
        "delta": round(delta, 2),
        "z_score": round(z_score, 4),
        "samples": len(baseline_values),
        "signals": signals,
        "recommended_controls": recommended_controls,
    }

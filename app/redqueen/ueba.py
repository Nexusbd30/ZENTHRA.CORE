from __future__ import annotations

from typing import Any


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _int(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _float(value: Any) -> float:
    try:
        return float(value or 0.0)
    except (TypeError, ValueError):
        return 0.0


def analyze_ueba_signals(perception: dict[str, Any]) -> dict[str, Any]:
    metadata = _dict(perception.get("metadata"))
    labels = _dict(perception.get("labels"))
    annotations = _dict(perception.get("annotations"))
    siem = _dict(perception.get("siem"))

    behavior = _dict(metadata.get("behavior"))
    identity = _dict(metadata.get("identity"))
    network = _dict(metadata.get("network"))
    endpoint = _dict(metadata.get("endpoint"))

    failed_logins = _int(
        behavior.get("failed_logins")
        or identity.get("failed_logins")
        or labels.get("failed_logins")
    )
    distinct_sources = _int(
        behavior.get("distinct_source_ips")
        or identity.get("distinct_source_ips")
        or network.get("distinct_source_ips")
    )
    geo_velocity_kmh = _float(
        behavior.get("geo_velocity_kmh")
        or identity.get("geo_velocity_kmh")
        or metadata.get("geo_velocity_kmh")
    )
    new_country = bool(
        behavior.get("new_country")
        or identity.get("new_country")
        or metadata.get("new_country")
    )
    off_hours = bool(
        behavior.get("off_hours")
        or identity.get("off_hours")
        or metadata.get("off_hours")
    )
    privileged = bool(
        behavior.get("privileged_account")
        or identity.get("privileged_account")
        or metadata.get("privileged_account")
    )
    process_anomaly = bool(
        behavior.get("process_anomaly")
        or endpoint.get("process_anomaly")
        or metadata.get("process_anomaly")
    )
    bytes_out = _float(
        behavior.get("bytes_out")
        or network.get("bytes_out")
        or metadata.get("bytes_out")
        or siem.get("value")
    )

    text = " ".join(
        str(value).lower()
        for value in [
            perception.get("title"),
            perception.get("description"),
            annotations.get("summary"),
            annotations.get("description"),
            *list(perception.get("factors") or []),
        ]
        if value
    )

    signals: list[str] = []
    score = 0.0
    if failed_logins >= 10:
        signals.append("ueba:credential_attack")
        score += min(30.0, failed_logins * 1.5)
    if distinct_sources >= 5:
        signals.append("ueba:source_fanout")
        score += min(18.0, distinct_sources * 2.0)
    if geo_velocity_kmh >= 900:
        signals.append("ueba:impossible_travel")
        score += 24.0
    if new_country:
        signals.append("ueba:new_country")
        score += 8.0
    if off_hours:
        signals.append("ueba:off_hours")
        score += 6.0
    if privileged:
        signals.append("ueba:privileged_account")
        score += 12.0
    if process_anomaly:
        signals.append("ueba:process_anomaly")
        score += 14.0
    if bytes_out >= 500_000_000:
        signals.append("ueba:large_egress")
        score += 16.0
    if "impossible travel" in text:
        signals.append("ueba:impossible_travel_text")
        score += 10.0
    if "password spray" in text or "credential stuffing" in text:
        signals.append("ueba:credential_attack_text")
        score += 10.0

    unique_signals = list(dict.fromkeys(signals))
    return {
        "anomaly_score": round(min(100.0, score), 2),
        "signals": unique_signals,
        "failed_logins": failed_logins,
        "distinct_source_ips": distinct_sources,
        "geo_velocity_kmh": geo_velocity_kmh,
        "new_country": new_country,
        "off_hours": off_hours,
        "privileged_account": privileged,
        "process_anomaly": process_anomaly,
        "bytes_out": bytes_out,
    }

from __future__ import annotations

from ipaddress import ip_address
from typing import Any


def enrich_iocs(event: dict[str, Any]) -> dict[str, Any]:
    payload = event.get("normalized_payload")
    payload = payload if isinstance(payload, dict) else {}
    values = [event.get("src_ip"), event.get("dst_ip"), payload.get("src_ip"), payload.get("dst_ip")]
    ip_enrichment: list[dict[str, Any]] = []
    for value in values:
        if not value:
            continue
        text = str(value)
        try:
            parsed = ip_address(text)
        except ValueError:
            continue
        ip_enrichment.append(
            {
                "ip": text,
                "scope": "private" if parsed.is_private else "public",
                "routable": not (parsed.is_private or parsed.is_loopback or parsed.is_reserved),
            }
        )
    return {
        "event_id": event.get("event_id"),
        "ips": list({item["ip"]: item for item in ip_enrichment}.values()),
        "domain": payload.get("domain") or payload.get("dns_query") or "",
        "asn": payload.get("asn") or "",
        "geo_country": payload.get("geo_country") or event.get("geo_country") or "",
    }

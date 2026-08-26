from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from ipaddress import ip_address
from urllib.parse import urlparse


class DnsTargetError(ValueError):
    """Raised when a DNS firewall target is unsafe or malformed."""


@dataclass(frozen=True)
class NormalizedDnsTarget:
    value: str
    target_type: str


def normalize_target(target: str) -> NormalizedDnsTarget:
    raw = str(target or "").strip()
    if not raw or len(raw) > 255:
        raise DnsTargetError("DNS target must contain between 1 and 255 characters")

    candidate = raw
    if "://" in candidate:
        parsed = urlparse(candidate)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            raise DnsTargetError("Only HTTP(S) URLs with a hostname are accepted")
        candidate = parsed.hostname

    candidate = candidate.rstrip(".").lower()
    try:
        parsed_ip = ip_address(candidate)
    except ValueError:
        parsed_ip = None

    if parsed_ip is not None:
        if parsed_ip.is_loopback or parsed_ip.is_link_local or parsed_ip.is_multicast:
            raise DnsTargetError("Loopback, link-local and multicast targets are not allowed")
        return NormalizedDnsTarget(str(parsed_ip), "ip")

    if candidate == "localhost" or ".." in candidate or candidate.startswith("."):
        raise DnsTargetError("Invalid DNS domain")
    labels = candidate.split(".")
    if len(labels) < 2 or any(not label or len(label) > 63 for label in labels):
        raise DnsTargetError("A fully qualified DNS domain is required")
    if any(not all(char.isalnum() or char == "-" for char in label) for label in labels):
        raise DnsTargetError("DNS labels may contain only letters, numbers and hyphens")
    if any(label.startswith("-") or label.endswith("-") for label in labels):
        raise DnsTargetError("DNS labels cannot start or end with a hyphen")
    return NormalizedDnsTarget(candidate, "domain")


def stable_idempotency_key(
    *, tenant_id: str, verdict_id: str, action: str, target: str, step: str
) -> str:
    import hashlib

    material = ":".join(
        value.strip().lower()
        for value in (tenant_id, verdict_id, action, target, step)
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class DnsBlockRequest:
    tenant_id: str
    target: NormalizedDnsTarget
    action: str
    idempotency_key: str
    verdict_id: str = ""
    change_ticket: str = ""
    expires_at: datetime | None = None


@dataclass(frozen=True)
class ProviderResult:
    status: str
    provider_request_id: str = ""
    provider_rule_id: str = ""
    evidence: dict[str, object] | None = None
    error_code: str = ""

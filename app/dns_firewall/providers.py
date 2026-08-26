from __future__ import annotations

from typing import Protocol

from app.actions._dispatch import dispatch_command
from app.core.settings import settings
from app.dns_firewall.contracts import DnsBlockRequest, ProviderResult


class DnsFirewallProvider(Protocol):
    name: str

    def apply_block(self, request: DnsBlockRequest) -> ProviderResult:
        ...

    def remove_block(self, request: DnsBlockRequest, provider_rule_id: str) -> ProviderResult:
        ...


class WebhookDnsFirewallProvider:
    name = "webhook"

    def _dispatch(self, command: str, request: DnsBlockRequest, **extra: str) -> ProviderResult:
        payload = {
            "tenant_id": request.tenant_id,
            "target": request.target.value,
            "target_type": request.target.target_type,
            "action": request.action,
            "verdict_id": request.verdict_id,
            "change_ticket": request.change_ticket,
            "idempotency_key": request.idempotency_key,
            **extra,
        }
        result = dispatch_command(
            url=settings.DNS_FIREWALL_CONTROL_URL,
            command=command,
            payload=payload,
        )
        return ProviderResult(
            status=str(result.get("status") or "ok"),
            provider_request_id=str(result.get("request_id") or result.get("id") or ""),
            provider_rule_id=str(result.get("rule_id") or ""),
            evidence=result,
        )

    def apply_block(self, request: DnsBlockRequest) -> ProviderResult:
        return self._dispatch("dns_firewall_block", request)

    def remove_block(self, request: DnsBlockRequest, provider_rule_id: str) -> ProviderResult:
        return self._dispatch(
            "dns_firewall_rollback", request, provider_rule_id=provider_rule_id
        )


def get_provider(name: str) -> DnsFirewallProvider:
    normalized = str(name or "").strip().lower()
    if normalized in {"webhook", "generic"}:
        return WebhookDnsFirewallProvider()
    raise ValueError(f"Unsupported DNS firewall provider: {name}")

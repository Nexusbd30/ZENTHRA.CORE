from __future__ import annotations

import hashlib
from datetime import UTC, datetime
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

    def verify_block(self, request: DnsBlockRequest, provider_rule_id: str) -> ProviderResult:
        ...


class WebhookDnsFirewallProvider:
    name = "webhook"

    @staticmethod
    def _fallback_rule_id(request: DnsBlockRequest) -> str:
        return hashlib.sha256(
            f"{request.tenant_id}:{request.target.value}:{request.idempotency_key}".encode(
                "utf-8"
            )
        ).hexdigest()[:32]

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
            provider_request_id=str(
                result.get("request_id") or result.get("id") or f"webhook-{request.idempotency_key[:12]}"
            ),
            provider_rule_id=str(result.get("rule_id") or self._fallback_rule_id(request)),
            evidence=result,
        )

    def apply_block(self, request: DnsBlockRequest) -> ProviderResult:
        return self._dispatch("dns_firewall_block", request)

    def remove_block(self, request: DnsBlockRequest, provider_rule_id: str) -> ProviderResult:
        return self._dispatch(
            "dns_firewall_rollback", request, provider_rule_id=provider_rule_id
        )

    def verify_block(self, request: DnsBlockRequest, provider_rule_id: str) -> ProviderResult:
        result = self._dispatch("dns_firewall_verify", request, provider_rule_id=provider_rule_id)
        if result.status in {"ok", "applied"}:
            return ProviderResult(
                status="verified",
                provider_request_id=result.provider_request_id,
                provider_rule_id=result.provider_rule_id or provider_rule_id,
                evidence={**(result.evidence or {}), "verification_status": "verified"},
            )
        return result


_SANDBOX_RULES: dict[str, dict[str, object]] = {}


class SandboxDnsFirewallProvider:
    name = "sandbox"

    @staticmethod
    def reset() -> None:
        _SANDBOX_RULES.clear()

    def apply_block(self, request: DnsBlockRequest) -> ProviderResult:
        existing = _SANDBOX_RULES.get(request.idempotency_key)
        if existing:
            return ProviderResult(
                status="applied",
                provider_request_id=str(existing["provider_request_id"]),
                provider_rule_id=str(existing["provider_rule_id"]),
                evidence={**existing, "idempotent_replay": True},
            )

        provider_rule_id = hashlib.sha256(
            f"{request.tenant_id}:{request.target.value}:{request.idempotency_key}".encode(
                "utf-8"
            )
        ).hexdigest()[:32]
        provider_request_id = f"sandbox-dns-{provider_rule_id[:12]}"
        evidence = {
            "provider": self.name,
            "provider_request_id": provider_request_id,
            "provider_rule_id": provider_rule_id,
            "tenant_id": request.tenant_id,
            "target": request.target.value,
            "target_type": request.target.target_type,
            "action": request.action,
            "verdict_id": request.verdict_id,
            "change_ticket": request.change_ticket,
            "idempotency_key": request.idempotency_key,
            "status": "applied",
            "applied_at": datetime.now(UTC).isoformat(),
        }
        _SANDBOX_RULES[request.idempotency_key] = evidence
        return ProviderResult(
            status="applied",
            provider_request_id=provider_request_id,
            provider_rule_id=provider_rule_id,
            evidence=evidence,
        )

    def remove_block(self, request: DnsBlockRequest, provider_rule_id: str) -> ProviderResult:
        existing = _SANDBOX_RULES.pop(request.idempotency_key, None)
        return ProviderResult(
            status="removed" if existing else "not_found",
            provider_request_id=str((existing or {}).get("provider_request_id") or ""),
            provider_rule_id=provider_rule_id,
            evidence={
                "provider": self.name,
                "tenant_id": request.tenant_id,
                "target": request.target.value,
                "provider_rule_id": provider_rule_id,
                "status": "removed" if existing else "not_found",
                "removed_at": datetime.now(UTC).isoformat(),
            },
        )

    def verify_block(self, request: DnsBlockRequest, provider_rule_id: str) -> ProviderResult:
        existing = _SANDBOX_RULES.get(request.idempotency_key)
        matched = bool(
            existing
            and existing.get("provider_rule_id") == provider_rule_id
            and existing.get("tenant_id") == request.tenant_id
            and existing.get("target") == request.target.value
        )
        return ProviderResult(
            status="verified" if matched else "verification_failed",
            provider_request_id=str((existing or {}).get("provider_request_id") or ""),
            provider_rule_id=provider_rule_id,
            error_code="" if matched else "dns_rule_read_back_mismatch",
            evidence={
                "provider": self.name,
                "tenant_id": request.tenant_id,
                "target": request.target.value,
                "provider_rule_id": provider_rule_id,
                "status": "verified" if matched else "verification_failed",
                "read_back": existing or {},
                "verified_at": datetime.now(UTC).isoformat(),
            },
        )


def get_provider(name: str) -> DnsFirewallProvider:
    normalized = str(name or "").strip().lower()
    if normalized in {"webhook", "generic", "umbrella"}:
        return WebhookDnsFirewallProvider()
    if normalized in {"sandbox", "contract", "local_sandbox"}:
        return SandboxDnsFirewallProvider()
    raise ValueError(f"Unsupported DNS firewall provider: {name}")

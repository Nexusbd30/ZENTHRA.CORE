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
                result.get("request_id") or ""
            ),
            provider_rule_id=str(result.get("rule_id") or ""),
            evidence=result,
        )

    def apply_block(self, request: DnsBlockRequest) -> ProviderResult:
        result = self._dispatch("dns_firewall_block", request)
        if not result.provider_rule_id or not result.provider_request_id:
            raise RuntimeError("DNS controller must return a rule_id and request_id")
        return result

    @staticmethod
    def _matches(result: ProviderResult, request: DnsBlockRequest, rule_id: str, present: bool) -> bool:
        evidence = result.evidence or {}
        return (bool(rule_id) and evidence.get("rule_id") == rule_id
                and evidence.get("tenant_id") == request.tenant_id
                and evidence.get("target") == request.target.value
                and evidence.get("present") is present)

    def remove_block(self, request: DnsBlockRequest, provider_rule_id: str) -> ProviderResult:
        result = self._dispatch("dns_firewall_rollback", request, provider_rule_id=provider_rule_id)
        if result.status not in {"removed", "not_found", "ok"}:
            return result
        check = self._dispatch("dns_firewall_verify", request, provider_rule_id=provider_rule_id)
        verified = self._matches(check, request, provider_rule_id, False)
        return ProviderResult(status="removed" if verified else "rollback_verification_failed",
                              provider_request_id=check.provider_request_id, provider_rule_id=provider_rule_id,
                              evidence={"rollback": result.evidence, "read_back": check.evidence})

    def verify_block(self, request: DnsBlockRequest, provider_rule_id: str) -> ProviderResult:
        result = self._dispatch("dns_firewall_verify", request, provider_rule_id=provider_rule_id)
        verified = result.status in {"ok", "applied", "verified"} and self._matches(result, request, provider_rule_id, True)
        return ProviderResult(status="verified" if verified else "verification_failed",
                              provider_request_id=result.provider_request_id, provider_rule_id=provider_rule_id,
                              evidence=result.evidence, error_code="" if verified else "dns_read_back_mismatch")


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
        evidence: dict[str, object] = {
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

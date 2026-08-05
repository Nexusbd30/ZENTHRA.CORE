from __future__ import annotations

from dataclasses import dataclass

from app.platform.blacknode import blacknode_gateway


@dataclass
class ValidationResult:
    valid: bool
    code: str
    detail: str


def validate_verdict(verdict: dict) -> ValidationResult:
    decision = blacknode_gateway.validate_verdict(verdict)
    return ValidationResult(decision.allowed, decision.code, decision.detail)

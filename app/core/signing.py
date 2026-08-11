from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any

from app.core.secrets import get_secret
from app.core.settings import settings


def _normalize_payload(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign_payload(payload: dict[str, Any]) -> str:
    default_secret: object = settings.SECRET_KEY
    if hasattr(default_secret, "get_secret_value"):
        default_secret = default_secret.get_secret_value()
    secret_key = get_secret(
        "SECRET_KEY",
        str(default_secret) if default_secret is not None else None,
    )
    key = str(secret_key).encode("utf-8")
    raw = _normalize_payload(payload)
    return hmac.new(key, raw, hashlib.sha256).hexdigest()


def verify_payload_signature(payload: dict[str, Any], signature: str) -> bool:
    expected = sign_payload(payload)
    return hmac.compare_digest(expected, signature)

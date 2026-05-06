from __future__ import annotations

import json
import logging
import re
from typing import Any

import requests

from app.core.settings import settings

LOG = logging.getLogger("aresx.ai")


class AIProvider:
    def complete(self, system_prompt: str, user_prompt: str) -> str:
        raise NotImplementedError


class LocalStubProvider(AIProvider):
    def complete(self, system_prompt: str, user_prompt: str) -> str:
        return (
            "{\"action_type\":\"soar_delegate\",\"confidence\":0.7,"
            "\"reasoning\":\"fallback-stub\",\"factors\":[\"stub\"]}"
        )


class OllamaProvider(AIProvider):
    def complete(self, system_prompt: str, user_prompt: str) -> str:
        payload = {
            "model": settings.AI_MODEL,
            "stream": False,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "options": {"temperature": float(settings.AI_TEMPERATURE)},
            "format": "json",
        }
        url = settings.AI_BASE_URL.rstrip("/") + "/api/chat"
        response = requests.post(url, json=payload, timeout=float(settings.AI_TIMEOUT_SEC))
        response.raise_for_status()
        data = response.json()

        message = data.get("message", {})
        content = message.get("content")
        if isinstance(content, str) and content.strip():
            return content.strip()

        return json.dumps(data, ensure_ascii=False)


class SafeAIProvider(AIProvider):
    def __init__(self) -> None:
        provider_name = (settings.AI_PROVIDER or "local_stub").strip().lower()
        if provider_name == "ollama":
            self.provider: AIProvider = OllamaProvider()
        else:
            self.provider = LocalStubProvider()

    def complete(self, system_prompt: str, user_prompt: str) -> str:
        if not settings.AI_ENABLED:
            return LocalStubProvider().complete(system_prompt, user_prompt)

        try:
            return self.provider.complete(system_prompt, user_prompt)
        except Exception as exc:  # noqa: BLE001
            LOG.warning("AI provider failed, fallback to local stub: %s", exc)
            return LocalStubProvider().complete(system_prompt, user_prompt)

    @staticmethod
    def parse_json(text: str) -> dict[str, Any]:
        stripped = (text or "").strip()
        if not stripped:
            return {}

        try:
            return json.loads(stripped)
        except json.JSONDecodeError:
            pass

        code_block = re.search(r"```(?:json)?\s*(\{[\s\S]*\})\s*```", stripped)
        if code_block:
            try:
                return json.loads(code_block.group(1))
            except json.JSONDecodeError:
                return {}

        first_obj = re.search(r"\{[\s\S]*\}", stripped)
        if first_obj:
            try:
                return json.loads(first_obj.group(0))
            except json.JSONDecodeError:
                return {}

        return {}


ai_provider = SafeAIProvider()

from __future__ import annotations

from typing import Any


def nested_get(data: dict[str, Any], path: str, default: Any = None) -> Any:
    current: Any = data
    for part in path.split("."):
        if not isinstance(current, dict):
            return default
        current = current.get(part)
    return default if current is None else current


def first_value(data: dict[str, Any], paths: list[str], default: Any = None) -> Any:
    for path in paths:
        value = nested_get(data, path)
        if value not in (None, ""):
            return value
    return default


def compact_labels(values: dict[str, Any]) -> dict[str, str]:
    return {key: str(value) for key, value in values.items() if value not in (None, "")}

from __future__ import annotations

from typing import Any, Callable

from app.ingestion.adapters.edr import adapt_edr_event
from app.ingestion.adapters.iam import adapt_iam_event
from app.ingestion.adapters.netflow import adapt_netflow_event
from app.ingestion.adapters.qradar import adapt_qradar_event
from app.ingestion.adapters.wazuh import adapt_wazuh_event

ADAPTERS: dict[str, Callable[[dict[str, Any]], dict[str, Any]]] = {
    "edr": adapt_edr_event,
    "iam": adapt_iam_event,
    "netflow": adapt_netflow_event,
    "qradar": adapt_qradar_event,
    "wazuh": adapt_wazuh_event,
}


def adapt_event(adapter: str, payload: dict[str, Any]) -> dict[str, Any]:
    key = adapter.strip().lower()
    if key not in ADAPTERS:
        raise KeyError(key)
    return ADAPTERS[key](payload)

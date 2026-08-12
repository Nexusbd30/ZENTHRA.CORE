from __future__ import annotations

from typing import Any, Protocol


class AgentRuntime(Protocol):
    """Contract for CortexFlow-compatible agent runtimes."""

    def build_status(self) -> dict[str, Any]:
        """Return runtime capabilities and operational status."""


class WorkflowEngine(Protocol):
    """Contract for VaelqorixFlow-compatible workflow engines."""

    def build_status(self) -> dict[str, Any]:
        """Return workflow and approval capabilities."""


class SecurityGateway(Protocol):
    """Contract for BlackNode-compatible security gateways."""

    def build_status(self) -> dict[str, Any]:
        """Return authentication, authorization, audit and risk status."""


class KnowledgeRetriever(Protocol):
    """Contract for VaelqorixVault-compatible knowledge retrieval services."""

    def build_status(self) -> dict[str, Any]:
        """Return RAG, memory and citation capabilities."""


class ToolRegistry(Protocol):
    """Contract for VaelqorixAPI-compatible tool registries."""

    def build_status(self) -> dict[str, Any]:
        """Return tool and integration registry capabilities."""


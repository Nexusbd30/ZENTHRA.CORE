from app.core.enterprise_security import (
    build_enterprise_readiness,
    build_security_context,
    has_capability,
)


def test_enterprise_security_context_maps_roles_to_capabilities():
    context = build_security_context(
        actor="analyst@corp.com",
        role="analyst",
        tenant_id="tenant-a",
    )

    assert context.actor == "analyst@corp.com"
    assert context.role == "analyst"
    assert context.tenant_id == "tenant-a"
    assert "identity:triage" in context.capabilities
    assert "soc:read" in context.capabilities
    assert "soc:materialize" in context.capabilities
    assert "soc:execute" not in context.capabilities
    assert "security:admin" not in context.capabilities
    assert has_capability("admin", "security:admin") is True
    assert has_capability("secops_lead", "soc:execute") is True
    assert has_capability("viewer", "ares:execute") is False


def test_enterprise_readiness_prefers_enterprise_identity_and_devsecops_providers():
    readiness = build_enterprise_readiness(tenant_id="tenant-b")

    assert readiness["overall"] == "ready_for_controlled_pilot"
    assert readiness["tenant"]["tenant_id"] == "tenant-b"
    assert readiness["rbac"]["capability_count"] >= 1
    assert "entra" in readiness["integrations"]["identity"]["preferred_available"]
    assert "azure_devops" in readiness["integrations"]["devsecops"]["preferred_available"]
    assert readiness["integrations"]["siem_soc"]["coverage"] == "contract_ready"
    assert readiness["security_runtime"]["rate_limit_store"]["backend"] == "in_memory"
    assert readiness["security_runtime"]["rate_limit_store"]["distributed"] is False
    assert readiness["security_runtime"]["replay_guard_store"]["backend"] == "in_memory"
    assert readiness["security_runtime"]["replay_guard_store"]["distributed"] is False

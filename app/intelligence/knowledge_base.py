from __future__ import annotations

from app.intelligence.contracts import KnowledgeDocument

KNOWLEDGE_BASE: tuple[KnowledgeDocument, ...] = (
    KnowledgeDocument(
        doc_id="identity-token-abuse",
        title="Identity token abuse containment",
        domain="identity",
        tags=("identity", "token_reuse", "mfa_absent", "privileged_identity", "T1078", "T1528"),
        summary="Privileged token reuse should be contained by revoking sessions, enforcing MFA, and degrading privileges when provider capabilities allow it.",
        recommended_actions=("revoke_session", "require_mfa", "degrade_privileges"),
        evidence_requirements=("identity_event_id", "provider", "session_context", "approval_for_lockdown"),
    ),
    KnowledgeDocument(
        doc_id="identity-lockdown-policy",
        title="Identity lockdown policy",
        domain="identity",
        tags=("identity_compromise", "mfa_bypass", "privilege_escalation", "critical"),
        summary="Critical identity compromise can justify credential disablement, but provider preflight and human approval must be preserved for disruptive changes.",
        recommended_actions=("identity_lockdown", "degrade_privileges", "revoke_session"),
        evidence_requirements=("provider_preflight", "change_ticket", "identity_activity"),
    ),
    KnowledgeDocument(
        doc_id="devsecops-secret-exposure",
        title="Secret exposure in pipeline",
        domain="devsecops",
        tags=("secret_exposure", "secret_leak", "critical_cvss", "T1552", "production_target"),
        summary="Secrets exposed in CI/CD require deployment blocking, artifact quarantine, token revocation, and secret rotation evidence before release resumes.",
        recommended_actions=("block_deployment", "quarantine_artifact", "revoke_pipeline_token", "crypto_rotate"),
        evidence_requirements=("scanner_alert", "repository", "pipeline_run", "secret_rotation_status"),
    ),
    KnowledgeDocument(
        doc_id="devsecops-production-release-guard",
        title="Production release protection",
        domain="devsecops",
        tags=("production_target", "deployment_anomaly", "deployment_blocked", "release"),
        summary="Production deployment anomalies should prefer release approval gates or deployment blocks depending on risk and blast radius.",
        recommended_actions=("require_release_approval", "block_deployment"),
        evidence_requirements=("environment", "release_owner", "change_ticket"),
    ),
    KnowledgeDocument(
        doc_id="identity-pipeline-correlation",
        title="Identity and pipeline compromise correlation",
        domain="devsecops",
        tags=(
            "identity_pipeline_correlation",
            "devsecops_identity_correlation",
            "privileged_identity",
            "secret_exposure",
            "T1078",
        ),
        summary="A privileged identity anomaly correlated with CI/CD secret exposure is treated as a compound intrusion path and should freeze production release paths until reviewed.",
        recommended_actions=("block_deployment", "revoke_pipeline_token", "quarantine_artifact"),
        evidence_requirements=("identity_activity", "pipeline_context", "correlation_score"),
    ),
    KnowledgeDocument(
        doc_id="mcp-governed-execution",
        title="MCP governed execution",
        domain="generic",
        tags=("mcp", "allowed_actions", "blocked_actions", "evidence_refs", "governance"),
        summary="MCP context constrains RedQueen output and ARES execution through allowlists, blocklists, evidence references, and blast-radius metadata.",
        recommended_actions=("observe", "soar_delegate"),
        evidence_requirements=("mcp_tools", "evidence_refs", "policy_result"),
    ),
)


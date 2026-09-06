from __future__ import annotations


def autonomy_capability_map() -> dict:
    capabilities = [
        {
            "key": "defensive_ctf_lab",
            "label": "CTF defensivo / lab",
            "status": "ready_to_build",
            "maturity": 82,
            "decision": "Puede operar ahora en laboratorio controlado.",
            "scope": [
                "ingestion of simulated SIEM EDR IAM and network events",
                "attack reality analysis by entity and timeline",
                "RedQueen verdict generation with dry-run controls",
                "ARES hunter trace and defensive eviction plan",
                "audit evidence and analyst review",
            ],
            "enabled_capabilities": [
                "create replayable defensive scenarios",
                "score attacker progression and confidence",
                "trace suspected foothold and lateral movement",
                "recommend containment and expulsion steps",
                "record evidence for after-action review",
            ],
            "required_guardrails": [
                "owned isolated lab only",
                "dry_run true by default",
                "no public targets",
                "operator approval before disruptive action",
                "full audit chain enabled",
            ],
            "rectification": [
                "add CTF scenario registry with goals flags and expected detections",
                "store labelled replay datasets for RedQueen calibration",
                "score participants by detection time containment quality and evidence quality",
            ],
        },
        {
            "key": "technical_grc",
            "label": "GRC tecnico",
            "status": "foundation_ready",
            "maturity": 68,
            "decision": "La base tecnica existe; falta una capa normativa formal.",
            "scope": [
                "control maturity for RedQueen and ARES",
                "readiness and security posture snapshots",
                "audit chain and evidence inventory",
                "risk-based rectification priorities",
            ],
            "enabled_capabilities": [
                "map technical controls to maturity gaps",
                "explain strengths weaknesses and remediation priorities",
                "support audit evidence collection",
                "track operational readiness before production",
            ],
            "required_guardrails": [
                "framework mapping must be explicit",
                "evidence must be immutable or exportable",
                "risk owners and review dates required",
                "no compliance claim without control evidence",
            ],
            "rectification": [
                "map controls to NIST CSF CIS Controls ISO 27001 and MITRE ATT&CK",
                "add evidence retention policy and executive report export",
                "add risk register with owner due date severity and acceptance state",
            ],
        },
        {
            "key": "authorized_pentesting",
            "label": "Pentesting real autorizado",
            "status": "blocked_until_guardrails",
            "maturity": 41,
            "decision": "No debe operar de forma autonoma contra objetivos reales todavia.",
            "scope": [
                "authorized owned assets only",
                "planning and evidence analysis",
                "defensive validation and exposure review",
                "lab or staging execution before production",
            ],
            "enabled_capabilities": [
                "prepare scope and rules of engagement",
                "review findings and correlate defensive telemetry",
                "validate exposure using safe read-only checks",
                "recommend mitigations and retest criteria",
            ],
            "required_guardrails": [
                "signed authorization and target allowlist",
                "read-only mode unless explicit approval exists",
                "rate limits and kill switch per operation",
                "complete command and evidence logging",
                "automatic block on out-of-scope targets",
            ],
            "rectification": [
                "build pentest scope validator and target allowlist enforcement",
                "add per-operation approval tokens and rate-limit budgets",
                "connect provider read-back before allowing any live validation workflow",
            ],
        },
    ]
    return {
        "module": "autonomy_control",
        "schema": "vaelqorix.autonomy_control.capability_map.v1",
        "summary": "ARES and RedQueen are ready for defensive CTF/lab, usable for technical GRC foundations, and blocked for autonomous real pentesting until guardrails are complete.",
        "capabilities": capabilities,
        "next_build_order": [
            "defensive_ctf_lab",
            "technical_grc",
            "authorized_pentesting_guardrails",
        ],
        "non_negotiable_boundaries": [
            "no offensive activity outside owned and authorized environments",
            "no autonomous disruptive action without approval evidence",
            "dry-run and audit are default for lab and staging",
            "production execution requires provider read-back and rollback verification",
        ],
    }

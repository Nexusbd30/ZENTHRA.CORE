from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def read_text(relative_path: str) -> str:
    return (ROOT / relative_path).read_text(encoding="utf-8")


def fail(message: str) -> str:
    return message


def check_absent(path: str, patterns: dict[str, str]) -> list[str]:
    text = read_text(path)
    findings: list[str] = []
    for pattern, message in patterns.items():
        if re.search(pattern, text, flags=re.IGNORECASE):
            findings.append(fail(f"{path}: {message}"))
    return findings


def check_json(path: str) -> list[str]:
    data = json.loads(read_text(path))
    dependencies = data.get("dependencies", {})
    findings: list[str] = []
    if dependencies.get("axios") and dependencies["axios"] < "1.18.0":
        findings.append(fail(f"{path}: axios must stay at 1.18.0 or newer"))
    if dependencies.get("react-router-dom") and dependencies["react-router-dom"] < "7.18.2":
        findings.append(fail(f"{path}: react-router-dom must stay at 7.18.2 or newer"))
    return findings


def main() -> int:
    findings: list[str] = []

    findings.extend(
        check_absent(
            "requirements.txt",
            {
                r"\bpython-jose\b": "python-jose must not return; use PyJWT[crypto]",
                r"\becdsa==": "ecdsa must not be pinned directly",
            },
        )
    )
    findings.extend(
        check_absent(
            "VAELQORIX.XDR_COMMAND/src/api/vaelqorixApi.js",
            {
                r"VITE_VAELQORIX_MONITOR_TOKEN": "monitor token must never be read by the browser",
            },
        )
    )
    findings.extend(
        check_absent(
            ".github/workflows/cd.yml",
            {
                r"branches:\s*\[\"main\",\s*\"master\"\]": "production CD must deploy from main only",
                r"deployment-redqueen\.yaml\s*\n\s*kubectl apply -f infra/k8s/service\.yaml\s*\n\s*kubectl apply -f infra/k8s/hpa\.yaml": "production CD must deploy all workloads, not only RedQueen",
                r"kubectl apply -f infra/k8s/configmap\.yaml": "production CD must generate runtime config from the production environment",
            },
        )
    )

    package_findings = check_json("VAELQORIX.XDR_COMMAND/package.json")
    findings.extend(package_findings)

    env_example = read_text(".env.example")
    required_env_flags = {
        "SECRET_BACKEND=file",
        "VAELQORIX_PUBLIC_REGISTRATION_ENABLED=false",
        "RATE_LIMIT_BACKEND=redis",
        "REPLAY_GUARD_BACKEND=redis",
        "ARES_KILL_SWITCH_BACKEND=redis",
    }
    for expected in sorted(required_env_flags):
        if expected not in env_example:
            findings.append(fail(f".env.example: missing production default {expected}"))

    workflow = read_text(".github/workflows/cd.yml")
    required_workloads = [
        "deployment-api.yaml",
        "deployment-redqueen.yaml",
        "deployment-ares.yaml",
        "deployment-ingestion.yaml",
        "deployment-frontend.yaml",
        "job-migrate.yaml",
        "ingress.yaml",
    ]
    for name in required_workloads:
        if name not in workflow:
            findings.append(fail(f".github/workflows/cd.yml: missing {name}"))

    if findings:
        print("production preflight failed:")
        for item in findings:
            print(f"- {item}")
        return 1

    print("production preflight passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

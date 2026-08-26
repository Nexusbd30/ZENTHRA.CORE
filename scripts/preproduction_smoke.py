from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


@dataclass(frozen=True)
class Check:
    path: str
    expected_status: int = 200


CHECKS = (
    Check("/health"),
    Check("/ready"),
    Check("/api/v1/redqueen/status"),
    Check("/api/v1/ares/status"),
    Check("/api/v1/connectors/readiness"),
)


def _request_json(url: str, timeout: float) -> tuple[int, dict[str, object]]:
    request = Request(url, headers={"Accept": "application/json"})
    try:
        with urlopen(request, timeout=timeout) as response:
            payload = response.read().decode("utf-8")
            return response.status, json.loads(payload or "{}")
    except HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"{url} returned HTTP {exc.code}: {body[:300]}") from exc
    except URLError as exc:
        raise RuntimeError(f"{url} is unreachable: {exc.reason}") from exc
    except TimeoutError as exc:
        raise RuntimeError(f"{url} timed out") from exc


def run_smoke(base_url: str, timeout: float) -> list[str]:
    findings: list[str] = []
    normalized_base = base_url.rstrip("/")
    for check in CHECKS:
        url = f"{normalized_base}{check.path}"
        try:
            status, payload = _request_json(url, timeout)
        except RuntimeError as exc:
            findings.append(str(exc))
            continue
        if status != check.expected_status:
            findings.append(f"{url} returned {status}, expected {check.expected_status}")
        if check.path in {"/health", "/ready"} and payload.get("status") not in {"ok", "ready"}:
            findings.append(f"{url} returned unexpected status payload: {payload}")
    return findings


def main() -> int:
    parser = argparse.ArgumentParser(description="Run public preproduction smoke checks.")
    parser.add_argument("base_url", help="Public preproduction base URL, for example https://preproduc.example.com")
    parser.add_argument("--timeout", type=float, default=8.0)
    args = parser.parse_args()

    if not args.base_url.startswith("https://"):
        print("preproduction smoke failed:")
        print("- base_url must use HTTPS")
        return 1

    findings = run_smoke(args.base_url, args.timeout)
    if findings:
        print("preproduction smoke failed:")
        for finding in findings:
            print(f"- {finding}")
        return 1

    print("preproduction smoke passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

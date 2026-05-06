from __future__ import annotations

import hashlib
import json
import os
import re
from collections import deque
from datetime import datetime
from pathlib import Path

LOG_LINE_RE = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3}) - "
    r"(?P<level>[A-Z]+) - (?P<logger>[^ ]+) - (?P<message>.*)$"
)
REQUEST_RE = re.compile(
    r"^(?P<method>[A-Z]+) (?P<path>\S+) -> (?P<status>\d{3}) \((?P<duration_ms>[\d.]+)ms\)$"
)
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def list_runtime_logs(limit: int = 200, severity: str | None = None, search: str | None = None) -> dict:
    log_dir = Path("logs")
    candidate_files = [
        log_dir / "app.log",
        log_dir / "alerts_audit.log",
        *[log_dir / f"app.log.{idx}" for idx in range(1, 6)],
    ]

    rows = []
    normalized_severity = (severity or "").strip().lower()
    if normalized_severity == "all":
        normalized_severity = ""
    search_term = (search or "").strip().lower()

    for file_path in candidate_files:
        if not file_path.exists() or not file_path.is_file():
            continue

        try:
            with file_path.open("r", encoding="utf-8", errors="replace") as handle:
                for line in deque(handle, maxlen=limit * 3):
                    parsed = _parse_log_line(line.rstrip("\n"), file_path.name)
                    if not parsed:
                        continue
                    if normalized_severity and parsed["severity"] != normalized_severity:
                        continue
                    if search_term and search_term not in json.dumps(parsed, ensure_ascii=False).lower():
                        continue
                    rows.append(parsed)
        except OSError:
            continue

    rows.sort(key=lambda item: item["timestamp"], reverse=True)
    rows = rows[:limit]

    return {
        "items": rows,
        "total": len(rows),
        "files": [path.name for path in candidate_files if path.exists()],
        "generated_at": datetime.utcnow().isoformat(),
    }


def _parse_log_line(line: str, source_file: str) -> dict | None:
    match = LOG_LINE_RE.match(line.strip())
    if not match:
        return None

    timestamp_raw = match.group("timestamp")
    level = match.group("level")
    logger_name = match.group("logger")
    message = match.group("message")

    try:
        timestamp = datetime.strptime(timestamp_raw, "%Y-%m-%d %H:%M:%S,%f")
    except ValueError:
        timestamp = datetime.utcnow()

    request_match = REQUEST_RE.match(message)
    method = request_match.group("method") if request_match else ""
    path = request_match.group("path") if request_match else ""
    status_code = int(request_match.group("status")) if request_match else None
    duration_ms = float(request_match.group("duration_ms")) if request_match else None

    ips = IP_RE.findall(message)
    source_ip = ips[0] if ips else "n/a"
    dest_ip = ips[1] if len(ips) > 1 else "n/a"
    protocol = _derive_protocol(path, message)
    action = _derive_action(level, status_code, message)
    severity = _derive_severity(level, status_code, path)

    event_seed = f"{timestamp_raw}|{level}|{logger_name}|{message}|{source_file}"
    event_id = hashlib.sha1(event_seed.encode("utf-8")).hexdigest()[:8].upper()

    return {
        "timestamp": timestamp.isoformat(),
        "event_id": f"ZX-{event_id}",
        "source_ip": source_ip,
        "dest_ip": dest_ip,
        "protocol": protocol,
        "action": action,
        "severity": severity,
        "message": message,
        "logger": logger_name,
        "level": level,
        "status_code": status_code,
        "path": path,
        "request_method": method,
        "duration_ms": duration_ms,
        "source_file": source_file,
        "raw": line,
        "metadata": {
          "logger": logger_name,
          "source_file": source_file,
          "status_code": status_code,
          "path": path,
          "request_method": method,
          "duration_ms": duration_ms,
          "pid": os.getpid(),
        },
    }


def _derive_protocol(path: str, message: str) -> str:
    upper_message = message.upper()
    if "/auth/" in path:
        return "AUTH"
    if "/monitoring/" in path:
        return "HTTP:MON"
    if "/threats/" in path:
        return "HTTP:THR"
    if "/users/" in path:
        return "HTTP:USR"
    if "HOOK" in upper_message:
        return "WEBHOOK"
    return "HTTP:API"


def _derive_action(level: str, status_code: int | None, message: str) -> str:
    if status_code is not None:
        if status_code >= 500:
            return "FAILED"
        if status_code >= 400:
            return "BLOCKED"
        return "ALLOWED"

    if level in {"ERROR", "CRITICAL"}:
        return "BLOCKED"
    if "warning" in message.lower():
        return "FLAGGED"
    return "ALLOWED"


def _derive_severity(level: str, status_code: int | None, path: str) -> str:
    if level in {"CRITICAL", "ERROR"} or (status_code is not None and status_code >= 500):
        return "critical"
    if level == "WARNING" or (status_code is not None and status_code >= 400):
        return "high"
    if "/monitoring/" in path or level == "INFO":
        return "low"
    return "medium"

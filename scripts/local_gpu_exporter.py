from __future__ import annotations

import csv
import shutil
import subprocess
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from io import StringIO


PORT = 9400
QUERY_FIELDS = [
    "index",
    "name",
    "utilization.gpu",
    "memory.used",
    "memory.total",
    "temperature.gpu",
    "power.draw",
]


def _float_or_zero(value: str) -> float:
    cleaned = (value or "").strip()
    if cleaned in {"", "[Not Supported]", "N/A"}:
        return 0.0
    try:
        return float(cleaned)
    except ValueError:
        return 0.0


def _escape_label(value: str) -> str:
    return value.replace("\\", "\\\\").replace("\n", " ").replace('"', '\\"')


def _nvidia_smi_path() -> str | None:
    return shutil.which("nvidia-smi") or r"C:\Windows\System32\nvidia-smi.exe"


def collect_metrics() -> tuple[int, str]:
    now = int(time.time())
    smi = _nvidia_smi_path()
    lines = [
        "# HELP vaelqorix_gpu_exporter_up Whether the local GPU exporter can read GPU telemetry.",
        "# TYPE vaelqorix_gpu_exporter_up gauge",
    ]

    if not smi:
        lines.append("vaelqorix_gpu_exporter_up 0")
        return 503, "\n".join(lines) + "\n"

    cmd = [
        smi,
        f"--query-gpu={','.join(QUERY_FIELDS)}",
        "--format=csv,noheader,nounits",
    ]
    try:
        completed = subprocess.run(
            cmd,
            check=True,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except Exception as exc:  # noqa: BLE001
        lines.append("vaelqorix_gpu_exporter_up 0")
        lines.append(f'vaelqorix_gpu_exporter_error{{message="{_escape_label(str(exc))}"}} 1')
        return 503, "\n".join(lines) + "\n"

    rows = list(csv.reader(StringIO(completed.stdout)))
    if not rows:
        lines.append("vaelqorix_gpu_exporter_up 0")
        return 503, "\n".join(lines) + "\n"

    lines.extend(
        [
            "vaelqorix_gpu_exporter_up 1",
            "# HELP nvidia_smi_utilization_gpu GPU utilization percent from nvidia-smi.",
            "# TYPE nvidia_smi_utilization_gpu gauge",
            "# HELP nvidia_smi_utilization_gpu_ratio GPU utilization ratio from nvidia-smi.",
            "# TYPE nvidia_smi_utilization_gpu_ratio gauge",
            "# HELP nvidia_smi_memory_used_bytes GPU memory used in bytes from nvidia-smi.",
            "# TYPE nvidia_smi_memory_used_bytes gauge",
            "# HELP nvidia_smi_memory_total_bytes GPU memory total in bytes from nvidia-smi.",
            "# TYPE nvidia_smi_memory_total_bytes gauge",
            "# HELP nvidia_smi_temperature_gpu_celsius GPU temperature in Celsius from nvidia-smi.",
            "# TYPE nvidia_smi_temperature_gpu_celsius gauge",
            "# HELP nvidia_smi_power_draw_watts GPU power draw in watts from nvidia-smi.",
            "# TYPE nvidia_smi_power_draw_watts gauge",
            "# HELP nvidia_smi_scrape_timestamp_seconds Last successful GPU scrape timestamp.",
            "# TYPE nvidia_smi_scrape_timestamp_seconds gauge",
        ]
    )

    for row in rows:
        cells = [cell.strip() for cell in row]
        if len(cells) < len(QUERY_FIELDS):
            continue
        index, name, util, mem_used, mem_total, temp, power = cells[: len(QUERY_FIELDS)]
        labels = f'gpu="{_escape_label(index)}",name="{_escape_label(name)}"'
        util_value = max(0.0, min(_float_or_zero(util), 100.0))
        lines.append(f"nvidia_smi_utilization_gpu{{{labels}}} {util_value}")
        lines.append(f"nvidia_smi_utilization_gpu_ratio{{{labels}}} {util_value / 100.0}")
        lines.append(f"nvidia_smi_memory_used_bytes{{{labels}}} {_float_or_zero(mem_used) * 1024 * 1024}")
        lines.append(f"nvidia_smi_memory_total_bytes{{{labels}}} {_float_or_zero(mem_total) * 1024 * 1024}")
        lines.append(f"nvidia_smi_temperature_gpu_celsius{{{labels}}} {_float_or_zero(temp)}")
        lines.append(f"nvidia_smi_power_draw_watts{{{labels}}} {_float_or_zero(power)}")
        lines.append(f"nvidia_smi_scrape_timestamp_seconds{{{labels}}} {now}")

    return 200, "\n".join(lines) + "\n"


class MetricsHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        if self.path not in {"/", "/metrics"}:
            self.send_response(404)
            self.end_headers()
            return
        status, body = collect_metrics()
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, format: str, *args: object) -> None:
        return


def main() -> None:
    server = ThreadingHTTPServer(("0.0.0.0", PORT), MetricsHandler)
    print(f"VAELQORIX local GPU exporter listening on 0.0.0.0:{PORT}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()

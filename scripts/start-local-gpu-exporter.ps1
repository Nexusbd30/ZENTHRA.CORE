$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $PSScriptRoot
$python = Join-Path $root "venv\Scripts\python.exe"
$exporter = Join-Path $root "scripts\local_gpu_exporter.py"

if (-not (Test-Path $python)) {
  throw "Python venv not found: $python"
}

if (-not (Test-Path $exporter)) {
  throw "GPU exporter not found: $exporter"
}

Start-Process -FilePath $python -ArgumentList @($exporter) -WindowStyle Hidden
Write-Host "VAELQORIX local GPU exporter started on http://127.0.0.1:9400/metrics"

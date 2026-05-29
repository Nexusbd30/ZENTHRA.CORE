$ErrorActionPreference = "Stop"

$root = Resolve-Path (Join-Path $PSScriptRoot "..")
Set-Location $root

$python = Resolve-Path ".\venv\Scripts\python.exe"
& $python -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8010

param(
    [int]$Port = 8010,
    [switch]$Reload,
    [switch]$KillExisting
)

$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$python = Join-Path $repoRoot "venv\Scripts\python.exe"

if (-not (Test-Path $python)) {
    throw "No se encontro el entorno virtual en $python"
}

$env:ENV = "development"
$env:SQLALCHEMY_DATABASE_URI = "sqlite:///./app.db"
$env:VAELQORIX_CORRELATION_ENABLED = "false"
if (-not $env:VAELQORIX_MONITOR_TOKEN) {
    $env:VAELQORIX_MONITOR_TOKEN = "dev-monitor-token"
}

$listeners = Get-NetTCPConnection -LocalAddress "127.0.0.1" -LocalPort $Port -State Listen -ErrorAction SilentlyContinue
if ($listeners) {
    $pids = @($listeners | Select-Object -ExpandProperty OwningProcess -Unique)
    if (-not $KillExisting) {
        $pidList = $pids -join ", "
        throw "El puerto $Port ya esta ocupado por PID(s): $pidList. Ejecuta con -KillExisting o usa -Port 8011."
    }
    foreach ($processId in $pids) {
        Stop-Process -Id $processId -Force
    }
}

$args = @("app.main:app", "--port", "$Port")
if ($Reload) {
    $args += "--reload"
}

& $python -m uvicorn @args

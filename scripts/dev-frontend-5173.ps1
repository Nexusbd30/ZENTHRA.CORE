$ErrorActionPreference = "Stop"

$root = Resolve-Path (Join-Path $PSScriptRoot "..\VAELQORIX.XDR_COMMAND")
Set-Location $root

corepack pnpm run dev -- --host 0.0.0.0 --port 5173 --strictPort

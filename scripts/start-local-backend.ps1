$ErrorActionPreference = "Stop"

Set-Location "C:\Users\mamad\NEXUS"

$env:ENV = "development"
$env:SQLALCHEMY_DATABASE_URI = ""
$env:VAELQORIX_CORRELATION_ENABLED = "true"

& "C:\Users\mamad\NEXUS\venv\Scripts\python.exe" -m uvicorn app.main:app --host 127.0.0.1 --port 8010

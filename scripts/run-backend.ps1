param(
  [string]$BindHost = "0.0.0.0",
  [int]$Port = 8000
)

$root = Split-Path -Parent $PSScriptRoot
$python = Join-Path $root "backend\.venv\Scripts\python.exe"
$backend = Join-Path $root "backend"

if (-not (Test-Path $python)) {
  Write-Error "Missing backend virtual environment at backend\.venv. Create it first with: python -m venv backend\.venv"
  exit 1
}

Push-Location $backend
try {
  & $python -m uvicorn app.main:app --reload --host $BindHost --port $Port
}
finally {
  Pop-Location
}

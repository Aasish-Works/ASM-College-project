param(
  [int]$Port = 5173
)

$root = Split-Path -Parent $PSScriptRoot
$frontend = Join-Path $root "frontend"

Push-Location $frontend
try {
  python -m http.server $Port
}
finally {
  Pop-Location
}

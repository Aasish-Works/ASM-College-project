$root = Split-Path -Parent $PSScriptRoot
$database = Join-Path $root "backend\asm.db"

if (Test-Path $database) {
  Remove-Item $database -Force
  Write-Host "Removed $database"
}
else {
  Write-Host "No database file found at $database"
}

Write-Host "Start the backend again to recreate a clean database."

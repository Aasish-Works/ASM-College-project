$uri = "http://127.0.0.1:8000/system/reset-data"

try {
  $response = Invoke-RestMethod -Method POST -Uri $uri
  $response | ConvertTo-Json -Depth 8
}
catch {
  Write-Error "Could not reset runtime data through $uri. Make sure the backend is running."
  exit 1
}

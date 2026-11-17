#requires -Version 5.1
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ConfigDir = Join-Path $HOME '.pi\agent'
$ModelsFile = Join-Path $ConfigDir 'models.json'
$Incoming = Invoke-RestMethod -Uri '{{public_url}}/config/pi/{{token}}'
New-Item -ItemType Directory -Path $ConfigDir -Force | Out-Null
$Existing = [pscustomobject]@{ providers = [pscustomobject]@{} }
if (Test-Path $ModelsFile) { $Existing = Get-Content -Path $ModelsFile -Raw | ConvertFrom-Json }
if ($null -eq $Existing.providers) { $Existing | Add-Member -NotePropertyName providers -NotePropertyValue ([pscustomobject]@{}) -Force }
foreach ($Property in $Incoming.providers.PSObject.Properties) {
  $Existing.providers | Add-Member -NotePropertyName $Property.Name -NotePropertyValue $Property.Value -Force
}
$Json = $Existing | ConvertTo-Json -Depth 30
$Utf8 = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText($ModelsFile, $Json + [Environment]::NewLine, $Utf8)
Write-Host "Pool providers merged into $ModelsFile. Open /model in Pi to reload them."

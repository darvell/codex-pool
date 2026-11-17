#requires -Version 5.1
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$Token = '{{token}}'
$BaseUrl = '{{public_url}}'
$ConfigDir = Join-Path $HOME '.grok'
$ConfigFile = Join-Path $ConfigDir 'config.toml'
$AuthFile = Join-Path $ConfigDir 'auth.json'
$AuthBackup = Join-Path $ConfigDir 'auth.json.before-codex-pool'
$AuthUrl = "$BaseUrl/config/grok/$Token"

New-Item -ItemType Directory -Path $ConfigDir -Force | Out-Null
if (Get-Command grok -ErrorAction SilentlyContinue) {
  try { & grok leader kill | Out-Null } catch {}
}
if (Test-Path $AuthFile) {
  if (Test-Path $AuthBackup) { Remove-Item -Force $AuthFile } else { Move-Item -Force $AuthFile $AuthBackup }
}
$Credential = Invoke-RestMethod -Uri $AuthUrl
$ApiKey = [string]$Credential.api_key
if ([string]::IsNullOrWhiteSpace($ApiKey)) { throw 'Pool credential response did not contain api_key' }

$Existing = ''
if (Test-Path $ConfigFile) { $Existing = Get-Content -Path $ConfigFile -Raw }
$Lines = @($Existing -split '[\r\n]+')
$Output = New-Object System.Collections.Generic.List[string]
$InManaged = $false
$InEndpoints = $false
$SawEndpoints = $false
$WroteModelsBase = $false

foreach ($Line in $Lines) {
  if ($Line -eq '# BEGIN CODEX-POOL GROK') { $InManaged = $true; continue }
  if ($InManaged) {
    if ($Line -eq '# END CODEX-POOL GROK') { $InManaged = $false }
    continue
  }
  if ($Line -match '^\s*\[') {
    if ($InEndpoints -and -not $WroteModelsBase) { $Output.Add('models_base_url = "' + $BaseUrl + '/v1"') }
    $InEndpoints = $Line -match '^\s*\[endpoints\]\s*$'
    if ($InEndpoints) { $SawEndpoints = $true; $WroteModelsBase = $false }
  }
  if ($InEndpoints -and $Line -match '^\s*models_base_url\s*=') {
    $Output.Add('models_base_url = "' + $BaseUrl + '/v1"')
    $WroteModelsBase = $true
    continue
  }
  $Output.Add($Line)
}
if ($InEndpoints -and -not $WroteModelsBase) { $Output.Add('models_base_url = "' + $BaseUrl + '/v1"') }
if (-not $SawEndpoints) { $Output.Add(''); $Output.Add('[endpoints]'); $Output.Add('models_base_url = "' + $BaseUrl + '/v1"') }

$Output.Add('')
$Output.Add('# BEGIN CODEX-POOL GROK')
$Models = @({{models}})
foreach ($Model in $Models) {
  $Output.Add('[model."' + $Model.Id + '"]')
  $Output.Add('api_key = "' + ($ApiKey -replace '"', '\"') + '"')
  $Output.Add('api_backend = "' + $Model.Backend + '"')
}
$Output.Add('# END CODEX-POOL GROK')

$Utf8 = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText($ConfigFile, (($Output -join [Environment]::NewLine).Trim() + [Environment]::NewLine), $Utf8)
Write-Host "Grok Build model discovery and inference now use codex-pool. Config saved to $ConfigFile"

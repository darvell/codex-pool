#requires -Version 5.1
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ConfigUrl = '{{public_url}}/config/cute-code/{{token}}'

function Set-Utf8NoBom {
  param([string]$Path, [string]$Value)
  $utf8 = New-Object System.Text.UTF8Encoding($false)
  [System.IO.File]::WriteAllText($Path, $Value, $utf8)
}

Write-Host 'Installing cute-code...'
try {
  Invoke-Expression (Invoke-RestMethod 'https://git.irrigate.cc/pp/cute-code/raw/branch/main/install.ps1')
} catch {
  Write-Host "Warning: cute-code installer failed or was already installed: $_"
}

Write-Host 'Configuring cute-code for Codex Pool...'
$claudeDir = $env:CLAUDE_CONFIG_DIR
if ([string]::IsNullOrWhiteSpace($claudeDir)) { $claudeDir = Join-Path $HOME '.claude' }
New-Item -ItemType Directory -Force -Path $claudeDir | Out-Null
$settingsFile = Join-Path $claudeDir 'settings.json'

$incoming = Invoke-RestMethod -Uri $ConfigUrl
$settings = $null
try { $settings = Get-Content -Path $settingsFile -Raw | ConvertFrom-Json } catch {}
if ($null -eq $settings) { $settings = New-Object PSObject }

foreach ($prop in $incoming.PSObject.Properties) {
  $settings | Add-Member -MemberType NoteProperty -Name $prop.Name -Value $prop.Value -Force
}

Set-Utf8NoBom -Path $settingsFile -Value ($settings | ConvertTo-Json -Depth 20)
Write-Host "cute-code pool settings saved to $settingsFile"
Write-Host 'Run: cute-code --model gpt-6-astra'

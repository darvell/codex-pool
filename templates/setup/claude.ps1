#requires -Version 5.1
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$BaseUrl = '{{public_url}}'
$OAuthToken = '{{access_token}}'

# PS 5.1 writes UTF-8 with BOM which breaks JSON parsers. Write without BOM.
function Set-Utf8NoBom {
  param([string]$Path, [string]$Value)
  $utf8 = New-Object System.Text.UTF8Encoding($false)
  [System.IO.File]::WriteAllText($Path, $Value, $utf8)
}

function Read-JsonObject {
  param([string]$Path)
  if (-not (Test-Path $Path)) { return (New-Object PSObject) }
  try {
    $raw = Get-Content -Path $Path -Raw
    if ([string]::IsNullOrWhiteSpace($raw)) { return (New-Object PSObject) }
    $obj = $raw | ConvertFrom-Json
    if ($null -eq $obj) { return (New-Object PSObject) }
    return $obj
  } catch {
    $backup = $Path + '.bak'
    Copy-Item -Path $Path -Destination $backup -Force -ErrorAction SilentlyContinue
    Write-Host ("Warning: could not parse " + $Path + "; backed it up to " + $backup + " and recreated it.")
    return (New-Object PSObject)
  }
}

function Has-Property {
  param($Obj, [string]$Name)
  if ($null -eq $Obj) { return $false }
  if ($Obj -is [System.Collections.IDictionary]) { return $Obj.Contains($Name) }
  $prop = $null
  try { $prop = $Obj.PSObject.Properties[$Name] } catch { return $false }
  return ($null -ne $prop)
}

function Get-Property {
  param($Obj, [string]$Name)
  if (-not (Has-Property $Obj $Name)) { return $null }
  if ($Obj -is [System.Collections.IDictionary]) { return $Obj[$Name] }
  return $Obj.PSObject.Properties[$Name].Value
}

function Remove-ObjectProperty {
  param([object]$Object, [string]$Name)
  if ($null -eq $Object) { return }
  if ($Object -is [System.Collections.IDictionary]) {
    if ($Object.Contains($Name)) { $Object.Remove($Name) | Out-Null }
    return
  }
  try {
    if ($Object.PSObject.Properties[$Name]) {
      $Object.PSObject.Properties.Remove($Name)
    }
  } catch {}
}

Write-Host 'Configuring Claude Code for pool access...'
Write-Host ''

$conflictingEnvVars = @(
  'ANTHROPIC_AUTH_TOKEN',
  'ANTHROPIC_API_KEY',
  'CLAUDE_CODE_USE_BEDROCK',
  'CLAUDE_CODE_USE_VERTEX',
  'CLAUDE_CODE_USE_FOUNDRY',
  'CLAUDE_CODE_PROVIDER_MANAGED_BY_HOST',
  'ANTHROPIC_UNIX_SOCKET',
  'CLAUDE_CODE_SIMPLE'
)

# Claude Code disables Claude.ai OAuth mode when these auth/provider vars are present.
foreach ($name in $conflictingEnvVars) {
  Remove-Item -Path ("Env:" + $name) -ErrorAction SilentlyContinue
  [Environment]::SetEnvironmentVariable($name, $null, 'User')
}

# Set env vars for this process and the user's default Windows environment.
$env:ANTHROPIC_BASE_URL = $BaseUrl
$env:CLAUDE_CODE_OAUTH_TOKEN = $OAuthToken
[Environment]::SetEnvironmentVariable('ANTHROPIC_BASE_URL', $BaseUrl, 'User')
[Environment]::SetEnvironmentVariable('CLAUDE_CODE_OAUTH_TOKEN', $OAuthToken, 'User')

# Persist env vars for future PowerShell sessions.
$profilePath = $PROFILE.CurrentUserAllHosts
New-Item -ItemType Directory -Force -Path (Split-Path $profilePath) | Out-Null
if (-not (Test-Path $profilePath)) { New-Item -ItemType File -Force -Path $profilePath | Out-Null }

$start = '# >>> Claude Code Pool Configuration >>>'
$end = '# <<< Claude Code Pool Configuration <<<'
$nl = [Environment]::NewLine
$blockLines = @(
  $start,
  'Remove-Item Env:\ANTHROPIC_AUTH_TOKEN -ErrorAction SilentlyContinue',
  'Remove-Item Env:\ANTHROPIC_API_KEY -ErrorAction SilentlyContinue',
  'Remove-Item Env:\CLAUDE_CODE_USE_BEDROCK -ErrorAction SilentlyContinue',
  'Remove-Item Env:\CLAUDE_CODE_USE_VERTEX -ErrorAction SilentlyContinue',
  'Remove-Item Env:\CLAUDE_CODE_USE_FOUNDRY -ErrorAction SilentlyContinue',
  'Remove-Item Env:\CLAUDE_CODE_PROVIDER_MANAGED_BY_HOST -ErrorAction SilentlyContinue',
  'Remove-Item Env:\ANTHROPIC_UNIX_SOCKET -ErrorAction SilentlyContinue',
  'Remove-Item Env:\CLAUDE_CODE_SIMPLE -ErrorAction SilentlyContinue',
  ('$env:ANTHROPIC_BASE_URL = "' + $BaseUrl + '"'),
  ('$env:CLAUDE_CODE_OAUTH_TOKEN = "' + $OAuthToken + '"'),
  $end
)
$block = $blockLines -join $nl

$existing = ''
try { $existing = Get-Content -Path $profilePath -Raw } catch {}
if ($null -eq $existing) { $existing = '' }

$pattern = [regex]::Escape($start) + '.*?' + [regex]::Escape($end)
if ([regex]::IsMatch($existing, $pattern, [Text.RegularExpressions.RegexOptions]::Singleline)) {
  $updated = [regex]::Replace($existing, $pattern, $block, [Text.RegularExpressions.RegexOptions]::Singleline)
} else {
  $sep = ''; if ($existing -and -not ($existing.EndsWith($nl))) { $sep = $nl }
  $updated = $existing + $sep + $nl + $block + $nl
}

Set-Utf8NoBom -Path $profilePath -Value $updated
Write-Host ("Added Claude Code pool config to " + $profilePath)

# Claude Code reads user settings from CLAUDE_CONFIG_DIR when set, otherwise ~/.claude.
$claudeDir = $env:CLAUDE_CONFIG_DIR
if ([string]::IsNullOrWhiteSpace($claudeDir)) { $claudeDir = Join-Path $HOME '.claude' }
New-Item -ItemType Directory -Force -Path $claudeDir | Out-Null

# Update settings.json with pool env and remove auth/provider settings that override OAuth.
$settingsFile = Join-Path $claudeDir 'settings.json'
$settings = Read-JsonObject -Path $settingsFile
Remove-ObjectProperty -Object $settings -Name 'apiKeyHelper'
$envObj = Get-Property $settings 'env'
if ($null -eq $envObj) { $envObj = New-Object PSObject }
foreach ($name in $conflictingEnvVars) { Remove-ObjectProperty -Object $envObj -Name $name }
$envObj | Add-Member -MemberType NoteProperty -Name ANTHROPIC_BASE_URL -Value $BaseUrl -Force
$envObj | Add-Member -MemberType NoteProperty -Name CLAUDE_CODE_OAUTH_TOKEN -Value $OAuthToken -Force
$settings | Add-Member -MemberType NoteProperty -Name env -Value $envObj -Force
Set-Utf8NoBom -Path $settingsFile -Value ($settings | ConvertTo-Json -Depth 10)
Write-Host ("Updated " + $settingsFile)

# Update ~/.claude.json (skip onboarding)
$claudeJsonFile = Join-Path $HOME '.claude.json'
$claudeJson = Read-JsonObject -Path $claudeJsonFile
$claudeJson | Add-Member -MemberType NoteProperty -Name hasCompletedOnboarding -Value $true -Force
Set-Utf8NoBom -Path $claudeJsonFile -Value ($claudeJson | ConvertTo-Json -Depth 10)
Write-Host ("Updated " + $claudeJsonFile)

Write-Host ''
Write-Host 'Setup complete!'
Write-Host ''
Write-Host ("Claude Code will now use the pool proxy at: " + $BaseUrl)
Write-Host ''
Write-Host 'Start a new terminal, or run: . $PROFILE'

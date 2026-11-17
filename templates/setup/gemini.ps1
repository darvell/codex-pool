#requires -Version 5.1
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$BaseUrl = '{{public_url}}'
$PoolToken = '{{access_token}}'

# PS 5.1 writes UTF-8 with BOM which breaks parsers. Write without BOM.
function Set-Utf8NoBom {
  param([string]$Path, [string]$Value)
  $utf8 = New-Object System.Text.UTF8Encoding($false)
  [System.IO.File]::WriteAllText($Path, $Value, $utf8)
}

Write-Host 'Configuring Gemini CLI for pool access...'
Write-Host ''

# Set env vars for the current session
$env:CODE_ASSIST_ENDPOINT = $BaseUrl
$env:GOOGLE_GENAI_USE_GCA = '1'
$env:GOOGLE_CLOUD_ACCESS_TOKEN = $PoolToken

# Persist env vars for future PowerShell sessions
$profilePath = $PROFILE.CurrentUserAllHosts
New-Item -ItemType Directory -Force -Path (Split-Path $profilePath) | Out-Null
if (-not (Test-Path $profilePath)) { New-Item -ItemType File -Force -Path $profilePath | Out-Null }

$start = '# >>> Gemini Pool Configuration >>>'
$end = '# <<< Gemini Pool Configuration <<<'
$nl = [Environment]::NewLine
$blockLines = @(
  $start,
  ('$env:CODE_ASSIST_ENDPOINT = "' + $BaseUrl + '"'),
  ('$env:GOOGLE_GENAI_USE_GCA = "1"'),
  ('$env:GOOGLE_CLOUD_ACCESS_TOKEN = "' + $PoolToken + '"'),
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
Write-Host ("Added Gemini pool config to " + $profilePath)

Write-Host ''
Write-Host 'Setup complete!'
Write-Host ''
Write-Host ("Gemini CLI will use the pool proxy at: " + $BaseUrl)
Write-Host 'No Google login required - validation is bypassed.'
Write-Host ''
Write-Host 'Start a new terminal, or run: . $PROFILE'

#requires -Version 5.1
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$Token = '{{token}}'
$BaseUrl = '{{public_url}}'

$authDir = Join-Path $HOME '.codex'
$configFile = Join-Path $authDir 'config.toml'
$authFile = Join-Path $authDir 'auth.json'
$modelCatalog = Join-Path $authDir 'model_catalog.json'
$mcpScript = Join-Path $authDir 'model_sync.ps1'
$nl = [Environment]::NewLine

# PS 5.1 compat wrapper: ConvertFrom-Json -Depth was added in PS 6
function ConvertFrom-JsonCompat {
  param([Parameter(ValueFromPipeline)]$InputObject)
  process {
    if ($PSVersionTable.PSVersion.Major -ge 6) {
      $InputObject | ConvertFrom-Json -Depth 20
    } else {
      $InputObject | ConvertFrom-Json
    }
  }
}

# PS 5.1 writes UTF-8 with BOM which breaks JSON/TOML parsers. Write without BOM.
function Set-Utf8NoBom {
  param([string]$Path, [string]$Value)
  $utf8 = New-Object System.Text.UTF8Encoding($false)
  [System.IO.File]::WriteAllText($Path, $Value, $utf8)
}

# Safe property check that works with Set-StrictMode -Version Latest
function Has-Property {
  param($Obj, [string]$Name)
  if ($null -eq $Obj) { return $false }
  if ($Obj -is [System.Collections.IDictionary]) { return $Obj.ContainsKey($Name) }
  return [bool]($Obj.PSObject.Properties.Name -contains $Name)
}

Write-Host 'Initializing Codex Pool setup...'
New-Item -ItemType Directory -Path $authDir -Force | Out-Null

Write-Host '1. Fetching credentials...'
$authUrl = "$BaseUrl/config/codex/$Token"
if ($PSVersionTable.PSEdition -eq 'Desktop') {
  $authContent = (Invoke-WebRequest -UseBasicParsing -Uri $authUrl).Content
} else {
  $authContent = (Invoke-WebRequest -Uri $authUrl).Content
}
Set-Utf8NoBom -Path $authFile -Value $authContent

Write-Host '2. Fetching model catalog...'
$raw = Get-Content -Path $authFile -Raw
$auth = $raw | ConvertFrom-JsonCompat
$accessToken = $null
if ($auth -and (Has-Property $auth 'tokens') -and (Has-Property $auth.tokens 'access_token')) {
  $accessToken = [string]$auth.tokens.access_token
} elseif ($auth -and (Has-Property $auth 'access_token')) {
  $accessToken = [string]$auth.access_token
}
if ([string]::IsNullOrWhiteSpace($accessToken)) {
  throw 'Pool credentials are missing. Generate a new setup command from the pool page.'
}
$modelsUrl = $BaseUrl.TrimEnd('/') + '/backend-api/codex/models?client_version=0.125.0'
$headers = @{ Authorization = "Bearer $accessToken" }
$tmp = [System.IO.Path]::GetTempFileName()
try {
  if ($PSVersionTable.PSEdition -eq 'Desktop') {
    Invoke-WebRequest -UseBasicParsing -Uri $modelsUrl -Headers $headers -OutFile $tmp -TimeoutSec 10 | Out-Null
  } else {
    Invoke-WebRequest -Uri $modelsUrl -Headers $headers -OutFile $tmp -TimeoutSec 10 | Out-Null
  }
  Move-Item -Force -Path $tmp -Destination $modelCatalog
  Write-Host "Model catalog saved to $modelCatalog"
} catch {
  throw 'Model catalog download failed. Check your connection and rerun setup.'
} finally {
  if (Test-Path $tmp) { Remove-Item -Force $tmp -ErrorAction SilentlyContinue }
}

Write-Host '3. Installing model sync MCP sidecar...'
$mcpContent = @'
param(
  [string]$BaseUrl = ""
)

$ErrorActionPreference = 'Stop'

$authDir = Join-Path $HOME '.codex'
$authFile = Join-Path $authDir 'auth.json'
$modelCatalog = Join-Path $authDir 'model_catalog.json'

# PS 5.1 compat wrapper: ConvertFrom-Json -Depth was added in PS 6
function ConvertFrom-JsonCompat {
  param([Parameter(ValueFromPipeline)]$InputObject)
  process {
    if ($PSVersionTable.PSVersion.Major -ge 6) {
      $InputObject | ConvertFrom-Json -Depth 20
    } else {
      $InputObject | ConvertFrom-Json
    }
  }
}

function Refresh-ModelCatalog {
  param([string]$Url)
  if ([string]::IsNullOrWhiteSpace($Url)) { return }
  if (-not (Test-Path $authFile)) { return }

  try {
    $raw = Get-Content -Path $authFile -Raw
    $auth = $raw | ConvertFrom-JsonCompat
  } catch {
    return
  }

  $token = $null
  if ($auth -and $auth.tokens -and $auth.tokens.access_token) {
    $token = [string]$auth.tokens.access_token
  } elseif ($auth -and $auth.access_token) {
    $token = [string]$auth.access_token
  }
  if ([string]::IsNullOrWhiteSpace($token)) { return }

  $modelsUrl = $Url.TrimEnd('/') + '/backend-api/codex/models?client_version=0.125.0'
  $headers = @{ Authorization = "Bearer $token" }

  try {
    $tmp = [System.IO.Path]::GetTempFileName()
    if ($PSVersionTable.PSEdition -eq 'Desktop') {
      Invoke-WebRequest -UseBasicParsing -Uri $modelsUrl -Headers $headers -OutFile $tmp -TimeoutSec 5 | Out-Null
    } else {
      Invoke-WebRequest -Uri $modelsUrl -Headers $headers -OutFile $tmp -TimeoutSec 5 | Out-Null
    }
    Move-Item -Force -Path $tmp -Destination $modelCatalog
  } catch {
    if ($tmp -and (Test-Path $tmp)) { Remove-Item -Force -Path $tmp -ErrorAction SilentlyContinue }
  }
}

function Write-McpResponse {
  param(
    [string]$Payload,
    [string]$Transport = 'framed'
  )

  if ($Transport -eq 'jsonl') {
    [Console]::Out.WriteLine($Payload)
    [Console]::Out.Flush()
    return
  }

  $bytes = [System.Text.Encoding]::UTF8.GetBytes($Payload)
  $nl = [Environment]::NewLine
  [Console]::Out.Write("Content-Length: " + $bytes.Length + $nl + $nl + $Payload)
  [Console]::Out.Flush()
}

Refresh-ModelCatalog -Url $BaseUrl

while ($true) {
  $transport = 'framed'
  $contentLength = 0
  $body = ''

  $firstLine = [Console]::In.ReadLine()
  if ($null -eq $firstLine) { exit 0 }

  if ($firstLine -match '^[ \t]*\{') {
    $transport = 'jsonl'
    $body = $firstLine
  } else {
    $line = $firstLine
    while ($true) {
      if ($line -eq '') { break }
      if ($line -match '^(?i)content-length:') {
        $lengthText = ($line -split ':', 2)[1].Trim()
        [int]::TryParse($lengthText, [ref]$contentLength) | Out-Null
      }
      $line = [Console]::In.ReadLine()
      if ($null -eq $line) { exit 0 }
    }
  }

  if ($transport -eq 'framed' -and $contentLength -le 0) { continue }
  if ($transport -eq 'framed') {
    $buffer = New-Object char[] $contentLength
    $readTotal = 0
    while ($readTotal -lt $contentLength) {
      $readNow = [Console]::In.Read($buffer, $readTotal, $contentLength - $readTotal)
      if ($readNow -le 0) { exit 0 }
      $readTotal += $readNow
    }
    $body = -join $buffer
  }

  try {
    $request = $body | ConvertFrom-JsonCompat
  } catch {
    continue
  }

  if (-not $request.PSObject.Properties.Name.Contains('id')) {
    continue
  }

  $method = ''
  if ($request.PSObject.Properties.Name.Contains('method')) {
    $method = [string]$request.method
  }

  $result = $null
  switch ($method) {
    'initialize' {
      $result = @{
        protocolVersion = '2024-11-05'
        capabilities = @{
          tools = @{ listChanged = $false }
          resources = @{ listChanged = $false }
          prompts = @{ listChanged = $false }
        }
        serverInfo = @{
          name = 'model_sync'
          version = '1.0.0'
        }
      }
    }
    'tools/list' { $result = @{ tools = @() } }
    'resources/list' { $result = @{ resources = @() } }
    'prompts/list' { $result = @{ prompts = @() } }
    'ping' { $result = @{} }
    default {
      $errorResponse = @{
        jsonrpc = '2.0'
        id = $request.id
        error = @{
          code = -32601
          message = 'Method not found'
        }
      } | ConvertTo-Json -Compress -Depth 20
      Write-McpResponse -Payload $errorResponse -Transport $transport
      continue
    }
  }

  $response = @{
    jsonrpc = '2.0'
    id = $request.id
    result = $result
  } | ConvertTo-Json -Compress -Depth 20
  Write-McpResponse -Payload $response -Transport $transport
}
'@
Set-Content -Path $mcpScript -Value $mcpContent -Encoding UTF8

# Find PowerShell executable path robustly
$mcpCommand = $null
try { $mcpCommand = (Get-Process -Id $PID).Path } catch {}
if ([string]::IsNullOrWhiteSpace($mcpCommand)) {
  try { $mcpCommand = (Get-Command pwsh -ErrorAction SilentlyContinue).Source } catch {}
}
if ([string]::IsNullOrWhiteSpace($mcpCommand)) {
  try { $mcpCommand = (Get-Command powershell -ErrorAction SilentlyContinue).Source } catch {}
}
if ([string]::IsNullOrWhiteSpace($mcpCommand)) {
  $mcpCommand = 'powershell'
}

$modelCatalogToml = $modelCatalog -replace '\\', '\\\\'
$mcpScriptToml = $mcpScript -replace '\\', '\\\\'
$mcpCommandToml = $mcpCommand -replace '\\', '\\\\'

Write-Host '4. Updating configuration...'
if (-not (Test-Path $configFile)) {
  New-Item -ItemType File -Path $configFile -Force | Out-Null
}

$existing = ''
try { $existing = Get-Content -Path $configFile -Raw } catch {}
if ($null -eq $existing) { $existing = '' }

# Only a root model selects the default; profile models remain independent.
$rootConfig = ($existing -split '(?m)^[ \t]*\[', 2)[0]
if ($rootConfig -notmatch '(?m)^[ \t]*model[ \t]*=') {
  $existing = 'model = "gpt-6-astra"' + $nl + $existing
  Set-Utf8NoBom -Path $configFile -Value $existing
}

if ($existing -notmatch 'codex-pool') {
  $new = @"
# Codex Pool Proxy Config
model_provider = "codex-pool"
chatgpt_base_url = "$BaseUrl/backend-api"
experimental_realtime_webrtc_call_base_url = "$BaseUrl/v1"
experimental_realtime_ws_base_url = "$BaseUrl/v1"
realtime.version = "v3"
realtime.transport = "webrtc"
model_catalog_json = "$modelCatalogToml"

$existing

[model_providers.codex-pool]
name = "OpenAI via codex-pool proxy"
base_url = "$BaseUrl"
wire_api = "responses"
requires_openai_auth = true
supports_websockets = true

[model_providers.codex-pool.features]
responses_websockets_v2 = true

[mcp_servers.model_sync]
command = "$mcpCommandToml"
args = ["-NoLogo", "-NoProfile", "-File", "$mcpScriptToml", "$BaseUrl"]
"@

  Set-Utf8NoBom -Path $configFile -Value $new
  Write-Host "Configuration updated in $configFile"
} else {
  $updated = $false

  if ($existing -notmatch '(?m)^[ \t]*model_catalog_json[ \t]*=') {
    $existing = 'model_catalog_json = "' + $modelCatalogToml + '"' + $nl + $existing
    $updated = $true
  }

  if ($existing -notmatch '(?m)^[ \t]*experimental_realtime_webrtc_call_base_url[ \t]*=') {
    $existing = 'experimental_realtime_webrtc_call_base_url = "' + $BaseUrl + '/v1"' + $nl + $existing
    $updated = $true
  }

  if ($existing -notmatch '(?m)^[ \t]*experimental_realtime_ws_base_url[ \t]*=') {
    $existing = 'experimental_realtime_ws_base_url = "' + $BaseUrl + '/v1"' + $nl + $existing
    $updated = $true
  }

  if ($existing -notmatch '(?m)^[ \t]*realtime\.version[ \t]*=' -and $existing -notmatch '(?m)^\[realtime\]') {
    $existing = 'realtime.version = "v3"' + $nl + 'realtime.transport = "webrtc"' + $nl + $existing
    $updated = $true
  }

  if ($existing -match '(?m)^\[mcp_servers\.codex_pool_model_sync\]') {
    $existing = $existing -replace '(?m)^\[mcp_servers\.codex_pool_model_sync\]', '[mcp_servers.model_sync]'
    $updated = $true
  }

  if ($existing -notmatch '(?m)^\[mcp_servers\.model_sync\]') {
    $existing = $existing.TrimEnd() +
      $nl + $nl +
      '[mcp_servers.model_sync]' + $nl +
      'command = "' + $mcpCommandToml + '"' + $nl +
      'args = ["-NoLogo", "-NoProfile", "-File", "' + $mcpScriptToml + '", "' + $BaseUrl + '"]' + $nl
    $updated = $true
  }

  if ($updated) {
    Set-Utf8NoBom -Path $configFile -Value $existing
    Write-Host "Configuration updated in $configFile"
  } else {
    Write-Host "Configuration already present in $configFile. Skipping."
  }
}

try {
  if (Get-Command codex -ErrorAction SilentlyContinue) {
    & codex features enable realtime_conversation | Out-Null
  }
} catch {}

Write-Host 'Setup complete! You are ready to use the pool.'

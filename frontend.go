package main

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

//go:embed templates/friend_landing.html templates/local_landing.html templates/og-image.png templates/og-image-transparent.png
var friendContent embed.FS

func (h *proxyHandler) serveFriendLanding(w http.ResponseWriter, r *http.Request) {
	var templateFile string
	var templateData map[string]string

	if h.cfg.friendCode == "" {
		// Local/personal mode - no friend code required
		templateFile = "templates/local_landing.html"
		templateData = map[string]string{
			"BaseURL": getPublicURL(),
		}
		if templateData["BaseURL"] == "" {
			templateData["BaseURL"] = "http://localhost:8989"
		}
	} else {
		// Friend mode - requires friend code
		templateFile = "templates/friend_landing.html"
		templateData = map[string]string{
			"FriendName": getFriendName(),
			"Tagline":    getFriendTagline(),
		}
	}

	data, err := friendContent.ReadFile(templateFile)
	if err != nil {
		http.Error(w, "internal error: template missing", http.StatusInternalServerError)
		return
	}

	tmpl, err := template.New("landing").Parse(string(data))
	if err != nil {
		http.Error(w, "internal error: template parse failed", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	w.Header().Set("Cache-Control", "no-cache, must-revalidate")
	tmpl.Execute(w, templateData)
}

func (h *proxyHandler) serveOGImage(w http.ResponseWriter, r *http.Request) {
	data, err := friendContent.ReadFile("templates/og-image.png")
	if err != nil {
		http.Error(w, "image not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	w.Write(data)
}

func (h *proxyHandler) serveHeroImage(w http.ResponseWriter, r *http.Request) {
	data, err := friendContent.ReadFile("templates/og-image-transparent.png")
	if err != nil {
		http.Error(w, "image not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	w.Write(data)
}

func (h *proxyHandler) handleFriendClaim(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if h.cfg.friendCode == "" {
		http.Error(w, "feature disabled", http.StatusForbidden)
		return
	}

	var req struct {
		FriendCode string `json:"friend_code"`
		Email      string `json:"user_email"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}

	if req.FriendCode != h.cfg.friendCode {
		respondJSONError(w, http.StatusForbidden, "Invalid Friend Code")
		return
	}

	// Ensure pool users system is ready
	if h.poolUsers == nil {
		// If using friend code, we expect pool users to be usable if JWT secret is set.
		if getPoolJWTSecret() == "" {
			respondJSONError(w, http.StatusServiceUnavailable, "System error: Pool user system not configured (missing JWT secret).")
			return
		}
		// Try to initialize on demand? (Not ideal, handled in main.go)
		respondJSONError(w, http.StatusServiceUnavailable, "System error: User storage not initialized.")
		return
	}

	// Determine email - use guest@<host> if none provided
	email := req.Email
	if email == "" {
		guestDomain := "pool.local"
		if pubURL := getPublicURL(); pubURL != "" {
			if u, err := url.Parse(pubURL); err == nil && u.Host != "" {
				host := u.Hostname()
				// Only use if not an IP address
				if net.ParseIP(host) == nil {
					guestDomain = host
				}
			}
		}
		email = "guest@" + guestDomain
	}

	// Check for existing user with this email
	var newUser *PoolUser
	if existing := h.poolUsers.GetByEmail(email); existing != nil {
		newUser = existing
	} else {
		// Create new user
		newUser = &PoolUser{
			ID:        randomHex(8),
			Token:     randomHex(16),
			Email:     email,
			PlanType:  "pro",
			CreatedAt: time.Now(),
		}
		if err := h.poolUsers.Create(newUser); err != nil {
			log.Printf("failed to create friend user: %v", err)
			respondJSONError(w, http.StatusInternalServerError, "Failed to create user account.")
			return
		}
	}

	// Generate Auth JSON
	secret := getPoolJWTSecret()
	authData, err := generateCodexAuth(secret, newUser)
	if err != nil {
		respondJSONError(w, http.StatusInternalServerError, "Failed to generate credentials.")
		return
	}
	authJSONBytes, _ := json.MarshalIndent(authData, "", "  ")

	// Generate Gemini Auth JSON
	geminiAuthData, err := generateGeminiAuth(secret, newUser)
	if err != nil {
		respondJSONError(w, http.StatusInternalServerError, "Failed to generate gemini credentials.")
		return
	}
	geminiJSONBytes, _ := json.MarshalIndent(geminiAuthData, "", "  ")

	// Generate Claude Auth - returns JWT for use as API key
	claudeAuthData, err := generateClaudeAuth(secret, newUser)
	if err != nil {
		respondJSONError(w, http.StatusInternalServerError, "Failed to generate claude credentials.")
		return
	}

	// Generate Gemini API key for API key mode (bypasses OAuth)
	geminiAPIKey := generateGeminiAPIKey(secret, newUser)

	publicURL := h.getEffectivePublicURL(r)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"public_url":       publicURL,
		"download_token":   newUser.Token,
		"auth_json":        string(authJSONBytes),
		"gemini_auth_json": string(geminiJSONBytes),
		"gemini_api_key":   geminiAPIKey,               // API key for Gemini CLI API key mode
		"claude_api_key":   claudeAuthData.AccessToken, // JWT token to use as API key
	})
}

func respondJSONError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func (h *proxyHandler) getEffectivePublicURL(r *http.Request) string {
	if u := getPublicURL(); u != "" {
		return u
	}
	// Infer from request
	scheme := "http"
	if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
		scheme = "https"
	}
	host := r.Host
	if host == "" {
		host = "localhost:8989"
	}
	return fmt.Sprintf("%s://%s", scheme, host)
}

func wantsPowerShell(r *http.Request) bool {
	switch strings.ToLower(strings.TrimSpace(r.URL.Query().Get("shell"))) {
	case "powershell", "pwsh", "ps", "ps1":
		return true
	default:
		return false
	}
}

func (h *proxyHandler) serveCodexSetupScript(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimPrefix(r.URL.Path, "/setup/codex/")
	if token == "" || strings.Contains(token, "/") {
		http.Error(w, "invalid token", http.StatusBadRequest)
		return
	}
	publicURL := h.getEffectivePublicURL(r)

	if wantsPowerShell(r) {
		script := fmt.Sprintf(`#requires -Version 5.1
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$Token = '%s'
$BaseUrl = '%s'

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
try {
  $raw = Get-Content -Path $authFile -Raw
  $auth = $raw | ConvertFrom-JsonCompat
  $accessToken = $null
  if ($auth -and (Has-Property $auth 'tokens') -and (Has-Property $auth.tokens 'access_token')) {
    $accessToken = [string]$auth.tokens.access_token
  } elseif ($auth -and (Has-Property $auth 'access_token')) {
    $accessToken = [string]$auth.access_token
  }
  if (-not [string]::IsNullOrWhiteSpace($accessToken)) {
    $modelsUrl = $BaseUrl.TrimEnd('/') + '/backend-api/codex/models?client_version=0.106.0'
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
      if (Test-Path $tmp) { Remove-Item -Force $tmp -ErrorAction SilentlyContinue }
      Write-Host "Warning: Could not fetch model catalog (non-fatal): $_"
    }
  }
} catch {
  Write-Host "Warning: Could not parse auth for model catalog fetch (non-fatal): $_"
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

  $modelsUrl = $Url.TrimEnd('/') + '/backend-api/codex/models?client_version=0.106.0'
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

if ($existing -notmatch 'codex-pool') {
  $new = @"
# Codex Pool Proxy Config
model_provider = "codex-pool"
chatgpt_base_url = "$BaseUrl/backend-api"
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

Write-Host 'Setup complete! You are ready to use the pool.'
`, token, publicURL)

		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write([]byte(script))
		return
	}

	script := fmt.Sprintf(`#!/bin/bash
set -euo pipefail
TOKEN="%s"
BASE_URL="%s"
AUTH_DIR="$HOME/.codex"
CONFIG_FILE="$AUTH_DIR/config.toml"
AUTH_FILE="$AUTH_DIR/auth.json"
MODEL_CATALOG="$AUTH_DIR/model_catalog.json"
MCP_SCRIPT="$AUTH_DIR/model_sync.sh"

echo "Initializing Codex Pool setup..."
mkdir -p "$AUTH_DIR"

echo "1. Fetching credentials..."
curl -sL "$BASE_URL/config/codex/$TOKEN" -o "$AUTH_FILE"
chmod 600 "$AUTH_FILE"

echo "2. Fetching model catalog..."
ACCESS_TOKEN=$(sed -n 's/.*"access_token"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$AUTH_FILE" | head -n 1)
if [ -n "${ACCESS_TOKEN:-}" ]; then
    curl --connect-timeout 5 --max-time 10 -fsSL \
        -H "Authorization: Bearer $ACCESS_TOKEN" \
        "$BASE_URL/backend-api/codex/models?client_version=0.106.0" \
        -o "$MODEL_CATALOG" 2>/dev/null && chmod 600 "$MODEL_CATALOG" 2>/dev/null || true
fi

echo "3. Installing model sync MCP sidecar..."
cat <<'EOF' > "$MCP_SCRIPT"
#!/bin/bash
set -euo pipefail

BASE_URL="${1:-}"
AUTH_DIR="${HOME}/.codex"
AUTH_FILE="$AUTH_DIR/auth.json"
MODEL_CATALOG="$AUTH_DIR/model_catalog.json"
CLIENT_VERSION="0.106.0"

refresh_model_catalog() {
    if [ -z "$BASE_URL" ] || [ ! -f "$AUTH_FILE" ]; then
        return 0
    fi

    local token
    token=$(sed -n 's/.*"access_token"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$AUTH_FILE" | head -n 1)
    if [ -z "${token:-}" ]; then
        return 0
    fi

    local tmp_file
    tmp_file=$(mktemp "${MODEL_CATALOG}.tmp.XXXXXX")
    if curl --connect-timeout 2 --max-time 5 -fsSL -H "Authorization: Bearer $token" \
        "${BASE_URL%%/}/backend-api/codex/models?client_version=${CLIENT_VERSION}" \
        -o "$tmp_file"; then
        mv "$tmp_file" "$MODEL_CATALOG"
        chmod 600 "$MODEL_CATALOG" 2>/dev/null || true
    else
        rm -f "$tmp_file"
    fi
}

read_request() {
    local line content_length
    content_length=0

    if ! IFS= read -r line; then
        return 1
    fi
    line="${line%%$'\r'}"

    if [[ "$line" == \{* ]]; then
        MCP_TRANSPORT_MODE="jsonl"
        REQUEST_BODY="$line"
        return 0
    fi

    while true; do
        if [ -z "$line" ]; then
            break
        fi
        case "$line" in
            [Cc]ontent-[Ll]ength:*|[Cc]ONTENT-[Ll]ENGTH:*|CONTENT-LENGTH:*|content-length:*)
                content_length=$(printf '%%s' "${line#*:}" | tr -d '[:space:]')
                ;;
        esac
        if ! IFS= read -r line; then
            return 1
        fi
        line="${line%%$'\r'}"
    done

    if [ -z "$content_length" ] || ! [[ "$content_length" =~ ^[0-9]+$ ]] || [ "$content_length" -le 0 ]; then
        return 1
    fi

    MCP_TRANSPORT_MODE="framed"
    REQUEST_BODY=$(dd bs=1 count="$content_length" 2>/dev/null)
    return 0
}

write_response() {
    local payload="$1"
    if [ "${MCP_TRANSPORT_MODE:-framed}" = "jsonl" ]; then
        printf '%%s\n' "$payload"
        return
    fi

    local length
    length=$(printf '%%s' "$payload" | LC_ALL=C wc -c | tr -d '[:space:]')
    printf 'Content-Length: %%s\r\n\r\n%%s' "$length" "$payload"
}

handle_request() {
    local request="$1"
    local method id payload

    method=$(printf '%%s' "$request" | sed -n 's/.*"method"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n 1)
    id=$(printf '%%s' "$request" | sed -n 's/.*"id"[[:space:]]*:[[:space:]]*\([^,}]*\).*/\1/p' | head -n 1)
    if [ -z "${id:-}" ]; then
        return 0
    fi

    case "$method" in
        initialize)
            payload='{"jsonrpc":"2.0","id":'"$id"',"result":{"protocolVersion":"2024-11-05","capabilities":{"tools":{"listChanged":false},"resources":{"listChanged":false},"prompts":{"listChanged":false}},"serverInfo":{"name":"model_sync","version":"1.0.0"}}}'
            ;;
        tools/list)
            payload='{"jsonrpc":"2.0","id":'"$id"',"result":{"tools":[]}}'
            ;;
        resources/list)
            payload='{"jsonrpc":"2.0","id":'"$id"',"result":{"resources":[]}}'
            ;;
        prompts/list)
            payload='{"jsonrpc":"2.0","id":'"$id"',"result":{"prompts":[]}}'
            ;;
        ping)
            payload='{"jsonrpc":"2.0","id":'"$id"',"result":{}}'
            ;;
        *)
            payload='{"jsonrpc":"2.0","id":'"$id"',"error":{"code":-32601,"message":"Method not found"}}'
            ;;
    esac

    write_response "$payload"
}

refresh_model_catalog >/dev/null 2>&1 &

while true; do
    REQUEST_BODY=""
    if ! read_request; then
        exit 0
    fi
    handle_request "$REQUEST_BODY"
done
EOF
chmod 700 "$MCP_SCRIPT"

echo "4. Updating configuration..."
if [ ! -f "$CONFIG_FILE" ]; then
    touch "$CONFIG_FILE"
fi

# Check if config already exists to avoid duplication
if ! grep -q "codex-pool" "$CONFIG_FILE"; then
    # Create temp file with pool config at TOP, then append existing config
    TEMP_FILE=$(mktemp)
    cat <<EOF > "$TEMP_FILE"
# Codex Pool Proxy Config
model_provider = "codex-pool"
chatgpt_base_url = "$BASE_URL/backend-api"
model_catalog_json = "$MODEL_CATALOG"

EOF
    # Append existing config
    cat "$CONFIG_FILE" >> "$TEMP_FILE"

    # Add model_providers section at the end (sections go after top-level keys)
    cat <<EOF >> "$TEMP_FILE"

[model_providers.codex-pool]
name = "OpenAI via codex-pool proxy"
base_url = "$BASE_URL"
wire_api = "responses"
requires_openai_auth = true
supports_websockets = true

[model_providers.codex-pool.features]
responses_websockets_v2 = true

[mcp_servers.model_sync]
command = "bash"
args = ["$MCP_SCRIPT", "$BASE_URL"]
EOF

    mv "$TEMP_FILE" "$CONFIG_FILE"
    chmod 600 "$CONFIG_FILE"
    echo "Configuration updated in $CONFIG_FILE"
else
    UPDATED=0

    if ! grep -Eq '^[[:space:]]*model_catalog_json[[:space:]]*=' "$CONFIG_FILE"; then
        TEMP_FILE=$(mktemp)
        cat <<EOF > "$TEMP_FILE"
model_catalog_json = "$MODEL_CATALOG"
EOF
        cat "$CONFIG_FILE" >> "$TEMP_FILE"
        mv "$TEMP_FILE" "$CONFIG_FILE"
        UPDATED=1
    fi

    if grep -q '^\[mcp_servers\.codex_pool_model_sync\]' "$CONFIG_FILE"; then
        TEMP_FILE=$(mktemp)
        sed 's/^\[mcp_servers\.codex_pool_model_sync\]/[mcp_servers.model_sync]/' "$CONFIG_FILE" > "$TEMP_FILE"
        mv "$TEMP_FILE" "$CONFIG_FILE"
        UPDATED=1
    fi

    if ! grep -q '^\[mcp_servers\.model_sync\]' "$CONFIG_FILE"; then
        cat <<EOF >> "$CONFIG_FILE"

[mcp_servers.model_sync]
command = "bash"
args = ["$MCP_SCRIPT", "$BASE_URL"]
EOF
        UPDATED=1
    fi

    chmod 600 "$CONFIG_FILE"
    if [ "$UPDATED" -eq 1 ]; then
        echo "Configuration updated in $CONFIG_FILE"
    else
        echo "Configuration already present in $CONFIG_FILE. Skipping."
    fi
fi

echo "Setup complete! You are ready to use the pool."
`, token, publicURL)

	w.Header().Set("Content-Type", "text/x-shellscript")
	w.Write([]byte(script))
}

func (h *proxyHandler) serveGeminiSetupScript(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimPrefix(r.URL.Path, "/setup/gemini/")
	if token == "" || strings.Contains(token, "/") {
		http.Error(w, "invalid token", http.StatusBadRequest)
		return
	}

	// Validate token and get user to generate credentials
	if h.poolUsers == nil {
		http.Error(w, "pool users not configured", http.StatusServiceUnavailable)
		return
	}
	user := h.poolUsers.GetByToken(token)
	if user == nil {
		http.Error(w, "invalid token", http.StatusNotFound)
		return
	}
	if user.Disabled {
		http.Error(w, "user disabled", http.StatusForbidden)
		return
	}

	// Generate pool OAuth credentials for this user
	secret := getPoolJWTSecret()
	if secret == "" {
		http.Error(w, "JWT secret not configured", http.StatusServiceUnavailable)
		return
	}
	geminiAuth, err := generateGeminiAuth(secret, user)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	publicURL := h.getEffectivePublicURL(r)

	// Script sets env vars to bypass Google OAuth validation and route through proxy
	// Uses GOOGLE_GENAI_USE_GCA + GOOGLE_CLOUD_ACCESS_TOKEN to skip getTokenInfo() check
	if wantsPowerShell(r) {
		script := fmt.Sprintf(`#requires -Version 5.1
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$BaseUrl = '%s'
$PoolToken = '%s'

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
`, publicURL, geminiAuth.AccessToken)

		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write([]byte(script))
		return
	}

	script := fmt.Sprintf(`#!/bin/bash
set -e
BASE_URL="%s"
POOL_TOKEN="%s"

echo "Configuring Gemini CLI for pool access..."
echo ""

# Add env vars to shell profile
add_to_profile() {
    for profile in "$HOME/.zshrc" "$HOME/.bashrc"; do
        if [ -f "$profile" ]; then
            # Remove old Gemini-related env vars
            grep -v "GEMINI_API_KEY=" "$profile" 2>/dev/null | \
            grep -v "GOOGLE_GEMINI_BASE_URL=" 2>/dev/null | \
            grep -v "CODE_ASSIST_ENDPOINT=" 2>/dev/null | \
            grep -v "GOOGLE_GENAI_USE_GCA=" 2>/dev/null | \
            grep -v "GOOGLE_CLOUD_ACCESS_TOKEN=" 2>/dev/null > "$profile.tmp" || true
            mv "$profile.tmp" "$profile"

            # Add pool configuration
            cat >> "$profile" << 'ENVEOF'

# Gemini Pool Configuration
export CODE_ASSIST_ENDPOINT="%s"
export GOOGLE_GENAI_USE_GCA=1
export GOOGLE_CLOUD_ACCESS_TOKEN="%s"
ENVEOF
            echo "✓ Added Gemini pool config to $(basename $profile)"
            return
        fi
    done

    # Fallback: create .zshrc
    cat >> "$HOME/.zshrc" << 'ENVEOF'

# Gemini Pool Configuration
export CODE_ASSIST_ENDPOINT="%s"
export GOOGLE_GENAI_USE_GCA=1
export GOOGLE_CLOUD_ACCESS_TOKEN="%s"
ENVEOF
    echo "✓ Created ~/.zshrc with Gemini pool config"
}

add_to_profile

echo ""
echo "Setup complete!"
echo ""
echo "Gemini CLI will use the pool proxy at: $BASE_URL"
echo "No Google login required - validation is bypassed."
echo ""
echo "Run 'source ~/.zshrc' or start a new terminal, then run 'gemini'."
`, publicURL, geminiAuth.AccessToken,
		publicURL, geminiAuth.AccessToken,
		publicURL, geminiAuth.AccessToken)

	w.Header().Set("Content-Type", "text/x-shellscript")
	w.Write([]byte(script))
}

func (h *proxyHandler) serveClaudeSetupScript(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimPrefix(r.URL.Path, "/setup/claude/")
	if token == "" || strings.Contains(token, "/") {
		http.Error(w, "invalid token", http.StatusBadRequest)
		return
	}

	// Validate token and get user
	if h.poolUsers == nil {
		http.Error(w, "pool users not configured", http.StatusServiceUnavailable)
		return
	}
	user := h.poolUsers.GetByToken(token)
	if user == nil {
		http.Error(w, "invalid token", http.StatusNotFound)
		return
	}
	if user.Disabled {
		http.Error(w, "user disabled", http.StatusForbidden)
		return
	}

	// Generate Claude API key (JWT)
	secret := getPoolJWTSecret()
	if secret == "" {
		http.Error(w, "JWT secret not configured", http.StatusServiceUnavailable)
		return
	}
	claudeAuth, err := generateClaudeAuth(secret, user)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	publicURL := h.getEffectivePublicURL(r)

	if wantsPowerShell(r) {
		script := fmt.Sprintf(`#requires -Version 5.1
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$BaseUrl = '%s'
$OAuthToken = '%s'

# PS 5.1 writes UTF-8 with BOM which breaks JSON parsers. Write without BOM.
function Set-Utf8NoBom {
  param([string]$Path, [string]$Value)
  $utf8 = New-Object System.Text.UTF8Encoding($false)
  [System.IO.File]::WriteAllText($Path, $Value, $utf8)
}

Write-Host 'Configuring Claude Code for pool access...'
Write-Host ''

# Set env vars for the current session
$env:ANTHROPIC_BASE_URL = $BaseUrl
$env:CLAUDE_CODE_OAUTH_TOKEN = $OAuthToken

# Persist env vars for future PowerShell sessions
$profilePath = $PROFILE.CurrentUserAllHosts
New-Item -ItemType Directory -Force -Path (Split-Path $profilePath) | Out-Null
if (-not (Test-Path $profilePath)) { New-Item -ItemType File -Force -Path $profilePath | Out-Null }

$start = '# >>> Claude Code Pool Configuration >>>'
$end = '# <<< Claude Code Pool Configuration <<<'
$nl = [Environment]::NewLine
$blockLines = @(
  $start,
  ('$env:ANTHROPIC_BASE_URL = "' + $BaseUrl + '"'),
  ('$env:CLAUDE_CODE_OAUTH_TOKEN = "' + $OAuthToken + '"'),
  $end
)
$block = $blockLines -join $nl

$existing = ''
try { $existing = Get-Content -Path $profilePath -Raw } catch {}

$pattern = [regex]::Escape($start) + '.*?' + [regex]::Escape($end)
if ([regex]::IsMatch($existing, $pattern, [Text.RegularExpressions.RegexOptions]::Singleline)) {
  $updated = [regex]::Replace($existing, $pattern, $block, [Text.RegularExpressions.RegexOptions]::Singleline)
} else {
  $sep = ''; if ($existing -and -not ($existing.EndsWith($nl))) { $sep = $nl }
  $updated = $existing + $sep + $nl + $block + $nl
}

Set-Utf8NoBom -Path $profilePath -Value $updated
Write-Host ("Added Claude Code pool config to " + $profilePath)

# Ensure Claude config directory exists
$claudeDir = Join-Path $HOME '.claude'
New-Item -ItemType Directory -Force -Path $claudeDir | Out-Null

# Update ~/.claude/settings.json
$settingsFile = Join-Path $claudeDir 'settings.json'
$settings = $null
try { $settings = Get-Content -Path $settingsFile -Raw | ConvertFrom-Json } catch {}
if ($null -eq $settings) { $settings = New-Object PSObject }
# Build the env object with pool values
$envObj = $null
try { $envObj = $settings.env } catch {}
if ($null -eq $envObj) { $envObj = New-Object PSObject }
$envObj | Add-Member -MemberType NoteProperty -Name ANTHROPIC_BASE_URL -Value $BaseUrl -Force
$envObj | Add-Member -MemberType NoteProperty -Name CLAUDE_CODE_OAUTH_TOKEN -Value $OAuthToken -Force
$settings | Add-Member -MemberType NoteProperty -Name env -Value $envObj -Force
Set-Utf8NoBom -Path $settingsFile -Value ($settings | ConvertTo-Json -Depth 10)
Write-Host ("Updated " + $settingsFile)

# Update ~/.claude.json (skip onboarding)
$claudeJsonFile = Join-Path $HOME '.claude.json'
$claudeJson = $null
try { $claudeJson = Get-Content -Path $claudeJsonFile -Raw | ConvertFrom-Json } catch {}
if ($null -eq $claudeJson) { $claudeJson = New-Object PSObject }
$claudeJson | Add-Member -MemberType NoteProperty -Name hasCompletedOnboarding -Value $true -Force
Set-Utf8NoBom -Path $claudeJsonFile -Value ($claudeJson | ConvertTo-Json -Depth 10)
Write-Host ("Updated " + $claudeJsonFile)

Write-Host ''
Write-Host 'Setup complete!'
Write-Host ''
Write-Host ("Claude Code will now use the pool proxy at: " + $BaseUrl)
Write-Host ''
Write-Host 'Start a new terminal, or run: . $PROFILE'
`, publicURL, claudeAuth.AccessToken)

		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write([]byte(script))
		return
	}

	script := fmt.Sprintf(`#!/bin/bash
IS_SOURCED=0
if [ -n "$ZSH_VERSION" ]; then
    case $ZSH_EVAL_CONTEXT in *:file) IS_SOURCED=1 ;; esac
elif [ -n "$BASH_VERSION" ]; then
    if [ "${BASH_SOURCE[0]}" != "$0" ]; then IS_SOURCED=1; fi
fi
ERREXIT_WAS_SET=0
case $- in *e*) ERREXIT_WAS_SET=1 ;; esac
set -e
BASE_URL="%s"
OAUTH_TOKEN="%s"

echo "Configuring Claude Code for pool access..."
echo ""

# Set env vars in the current shell if this script is sourced
export ANTHROPIC_BASE_URL="$BASE_URL"
export CLAUDE_CODE_OAUTH_TOKEN="$OAUTH_TOKEN"

# Add env vars to shell profile (Claude Code reads tokens from process.env)
add_to_profile() {
    for profile in "$HOME/.zshrc" "$HOME/.bashrc" "$HOME/.bash_profile" "$HOME/.profile"; do
        if [ -f "$profile" ]; then
            # Remove old Claude pool-related env vars
            grep -v "CLAUDE_CODE_OAUTH_TOKEN=" "$profile" 2>/dev/null | \
            grep -v "ANTHROPIC_BASE_URL=" "$profile" 2>/dev/null | \
            grep -v "ANTHROPIC_AUTH_TOKEN=" "$profile" 2>/dev/null > "$profile.tmp" || true
            mv "$profile.tmp" "$profile"

            # Add pool configuration
            cat >> "$profile" << 'ENVEOF'

# Claude Code Pool Configuration
export ANTHROPIC_BASE_URL="%s"
export CLAUDE_CODE_OAUTH_TOKEN="%s"
ENVEOF
            echo "✓ Added Claude Code pool config to $(basename $profile)"
            return
        fi
    done

    # Fallback: create .zshrc
    cat >> "$HOME/.zshrc" << 'ENVEOF'

# Claude Code Pool Configuration
export ANTHROPIC_BASE_URL="%s"
export CLAUDE_CODE_OAUTH_TOKEN="%s"
ENVEOF
    echo "✓ Created ~/.zshrc with Claude Code pool config"
}

mkdir -p "$HOME/.claude"
SETTINGS_FILE="$HOME/.claude/settings.json"
CLAUDE_JSON="$HOME/.claude.json"

# Update settings.json with env vars
update_settings() {
    if command -v node &> /dev/null; then
        node << 'NODE_SCRIPT'
const fs = require('fs');
const path = require('path');
const file = path.join(process.env.HOME, '.claude', 'settings.json');
let settings = {};
try { settings = JSON.parse(fs.readFileSync(file, 'utf8')); } catch {}
settings.env = settings.env || {};
settings.env.ANTHROPIC_BASE_URL = '%s';
settings.env.CLAUDE_CODE_OAUTH_TOKEN = '%s';
fs.writeFileSync(file, JSON.stringify(settings, null, 2) + '\n');
console.log('✓ Updated settings.json (node)');
NODE_SCRIPT
    elif command -v python3 &> /dev/null; then
        python3 << 'PYTHON_SCRIPT'
import json, os
file = os.path.expanduser("~/.claude/settings.json")
try:
    with open(file) as f: settings = json.load(f)
except: settings = {}
settings.setdefault('env', {})
settings['env']['ANTHROPIC_BASE_URL'] = '%s'
settings['env']['CLAUDE_CODE_OAUTH_TOKEN'] = '%s'
with open(file, 'w') as f: json.dump(settings, f, indent=2); f.write('\n')
print("✓ Updated settings.json (python)")
PYTHON_SCRIPT
    else
        [ -f "$SETTINGS_FILE" ] && cp "$SETTINGS_FILE" "$SETTINGS_FILE.bak"
        cat > "$SETTINGS_FILE" << 'EOF'
{
  "env": {
    "ANTHROPIC_BASE_URL": "%s",
    "CLAUDE_CODE_OAUTH_TOKEN": "%s"
  }
}
EOF
        echo "✓ Created settings.json (bash fallback)"
    fi
}

# Update ~/.claude.json with hasCompletedOnboarding
update_claude_json() {
    if command -v node &> /dev/null; then
        node << 'NODE_SCRIPT'
const fs = require('fs');
const path = require('path');
const file = path.join(process.env.HOME, '.claude.json');
let config = {};
try { config = JSON.parse(fs.readFileSync(file, 'utf8')); } catch {}
config.hasCompletedOnboarding = true;
fs.writeFileSync(file, JSON.stringify(config, null, 2) + '\n');
console.log('✓ Updated .claude.json (node)');
NODE_SCRIPT
    elif command -v python3 &> /dev/null; then
        python3 << 'PYTHON_SCRIPT'
import json, os
file = os.path.expanduser("~/.claude.json")
try:
    with open(file) as f: config = json.load(f)
except: config = {}
config['hasCompletedOnboarding'] = True
with open(file, 'w') as f: json.dump(config, f, indent=2); f.write('\n')
print("✓ Updated .claude.json (python)")
PYTHON_SCRIPT
    else
        [ -f "$CLAUDE_JSON" ] && cp "$CLAUDE_JSON" "$CLAUDE_JSON.bak"
        if [ -f "$CLAUDE_JSON" ]; then
            # Try to preserve existing content (basic append)
            tmp=$(mktemp)
            cat "$CLAUDE_JSON" | sed 's/}$/,"hasCompletedOnboarding":true}/' > "$tmp"
            mv "$tmp" "$CLAUDE_JSON"
        else
            echo '{"hasCompletedOnboarding":true}' > "$CLAUDE_JSON"
        fi
        echo "✓ Updated .claude.json (bash fallback)"
    fi
}

update_settings
update_claude_json
add_to_profile

echo ""
echo "Setup complete!"
echo ""
echo "Claude Code will now use the pool proxy at: $BASE_URL"
echo ""
echo "Run 'source ~/.zshrc' (or ~/.bashrc) or start a new terminal, then run 'claude'."
if [ "$IS_SOURCED" -eq 1 ] && [ "$ERREXIT_WAS_SET" -eq 0 ]; then
    set +e
fi
`, publicURL, claudeAuth.AccessToken,
		publicURL, claudeAuth.AccessToken,
		publicURL, claudeAuth.AccessToken,
		publicURL, claudeAuth.AccessToken, // node
		publicURL, claudeAuth.AccessToken, // python
		publicURL, claudeAuth.AccessToken) // bash fallback

	w.Header().Set("Content-Type", "text/x-shellscript")
	w.Write([]byte(script))
}

// hashAccountID creates a short anonymized hash of an account identifier
func hashAccountID(id string) string {
	h := sha256.Sum256([]byte(id + "pool-salt-2024"))
	return hex.EncodeToString(h[:])[:12]
}

// PoolStats represents anonymized pool statistics
type PoolStats struct {
	TotalAccounts    int               `json:"total_accounts"`
	ActiveAccounts   int               `json:"active_accounts"`
	TotalPoolUsers   int               `json:"total_pool_users"`
	Accounts         []AccountStats    `json:"accounts"`
	AggregateUsage   AggregateStats    `json:"aggregate"`
	CapacityAnalysis *CapacityAnalysis `json:"capacity_analysis,omitempty"`
	Last24hTokens    int64             `json:"last_24h_tokens"`
	GeneratedAt      time.Time         `json:"generated_at"`
}

type AccountStats struct {
	ID                    string  `json:"id"` // hashed
	Type                  string  `json:"type"`
	PlanType              string  `json:"plan_type"`
	Status                string  `json:"status"` // healthy, degraded, dead
	PrimaryWindowUsed     float64 `json:"primary_window_used_pct"`
	SecondaryWindowUsed   float64 `json:"secondary_window_used_pct"`
	PrimaryResetMinutes   int     `json:"primary_reset_minutes"`
	SecondaryResetMinutes int     `json:"secondary_reset_minutes"`
	TotalInputTokens      int64   `json:"total_input_tokens"`
	TotalCachedTokens     int64   `json:"total_cached_tokens"`
	TotalOutputTokens     int64   `json:"total_output_tokens"`
	TotalReasoningTokens  int64   `json:"total_reasoning_tokens"`
	TotalBillableTokens   int64   `json:"total_billable_tokens"`
	CacheHitRate          float64 `json:"cache_hit_rate_pct"`
	CreditsBalance        float64 `json:"credits_balance,omitempty"`
	HasCredits            bool    `json:"has_credits"`
	Score                 float64 `json:"score"`
	IsPrimary             bool    `json:"is_primary"` // highest score for this provider type
}

type AggregateStats struct {
	TotalInputTokens     int64   `json:"total_input_tokens"`
	TotalCachedTokens    int64   `json:"total_cached_tokens"`
	TotalOutputTokens    int64   `json:"total_output_tokens"`
	TotalReasoningTokens int64   `json:"total_reasoning_tokens"`
	TotalBillableTokens  int64   `json:"total_billable_tokens"`
	AvgPrimaryUsed       float64 `json:"avg_primary_window_used_pct"`
	AvgSecondaryUsed     float64 `json:"avg_secondary_window_used_pct"`
	OverallCacheHitRate  float64 `json:"overall_cache_hit_rate_pct"`
}

// CapacityAnalysis contains token capacity estimation data for the stats API.
type CapacityAnalysis struct {
	TotalSamples int64                       `json:"total_samples"`
	Plans        map[string]PlanCapacityInfo `json:"plans"`
	ModelFormula string                      `json:"model_formula"`
}

type PlanCapacityInfo struct {
	SampleCount                int64   `json:"sample_count"`
	Confidence                 string  `json:"confidence"`
	TotalInputTokens           int64   `json:"total_input_tokens"`
	TotalOutputTokens          int64   `json:"total_output_tokens"`
	TotalCachedTokens          int64   `json:"total_cached_tokens"`
	TotalReasoningTokens       int64   `json:"total_reasoning_tokens"`
	OutputMultiplier           float64 `json:"output_multiplier"`
	EstimatedPrimaryCapacity   int64   `json:"estimated_5h_capacity"`
	EstimatedSecondaryCapacity int64   `json:"estimated_7d_capacity"`
}

func (h *proxyHandler) handlePoolStats(w http.ResponseWriter, r *http.Request) {
	// Require friend code authentication via query param or header
	friendCode := r.URL.Query().Get("code")
	if friendCode == "" {
		friendCode = r.Header.Get("X-Friend-Code")
	}

	if h.cfg.friendCode == "" || friendCode != h.cfg.friendCode {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	accounts := h.pool.allAccounts()

	stats := PoolStats{
		TotalAccounts: len(accounts),
		GeneratedAt:   time.Now(),
	}

	if h.poolUsers != nil {
		stats.TotalPoolUsers = len(h.poolUsers.List())
	}

	var totalInput, totalCached, totalOutput, totalReasoning, totalBillable int64
	var primarySum, secondarySum float64
	activeCount := 0

	for _, acc := range accounts {
		acc.mu.Lock()

		status := "healthy"
		if acc.Dead {
			status = "dead"
		} else if acc.Penalty > 0.5 {
			status = "degraded"
		} else {
			activeCount++
		}

		accType := "codex"
		if acc.Type == AccountTypeGemini {
			accType = "gemini"
		} else if acc.Type == AccountTypeClaude {
			accType = "claude"
		}

		cacheHitRate := float64(0)
		if acc.Totals.TotalInputTokens > 0 {
			cacheHitRate = float64(acc.Totals.TotalCachedTokens) / float64(acc.Totals.TotalInputTokens) * 100
		}

		primaryReset := 0
		secondaryReset := 0
		if !acc.Usage.PrimaryResetAt.IsZero() {
			primaryReset = int(time.Until(acc.Usage.PrimaryResetAt).Minutes())
			if primaryReset < 0 {
				primaryReset = 0
			}
		}
		if !acc.Usage.SecondaryResetAt.IsZero() {
			secondaryReset = int(time.Until(acc.Usage.SecondaryResetAt).Minutes())
			if secondaryReset < 0 {
				secondaryReset = 0
			}
		}

		// Calculate score while we have the lock
		score := float64(0)
		if !acc.Dead && !acc.Disabled {
			score = scoreAccountLocked(acc, stats.GeneratedAt)
		}

		as := AccountStats{
			ID:                    hashAccountID(acc.ID),
			Type:                  accType,
			PlanType:              acc.PlanType,
			Status:                status,
			PrimaryWindowUsed:     acc.Usage.PrimaryUsedPercent * 100,
			SecondaryWindowUsed:   acc.Usage.SecondaryUsedPercent * 100,
			PrimaryResetMinutes:   primaryReset,
			SecondaryResetMinutes: secondaryReset,
			TotalInputTokens:      acc.Totals.TotalInputTokens,
			TotalCachedTokens:     acc.Totals.TotalCachedTokens,
			TotalOutputTokens:     acc.Totals.TotalOutputTokens,
			TotalReasoningTokens:  acc.Totals.TotalReasoningTokens,
			TotalBillableTokens:   acc.Totals.TotalBillableTokens,
			CacheHitRate:          cacheHitRate,
			HasCredits:            acc.Usage.HasCredits,
			CreditsBalance:        acc.Usage.CreditsBalance,
			Score:                 score,
		}

		totalInput += acc.Totals.TotalInputTokens
		totalCached += acc.Totals.TotalCachedTokens
		totalOutput += acc.Totals.TotalOutputTokens
		totalReasoning += acc.Totals.TotalReasoningTokens
		totalBillable += acc.Totals.TotalBillableTokens
		primarySum += acc.Usage.PrimaryUsedPercent
		secondarySum += acc.Usage.SecondaryUsedPercent

		acc.mu.Unlock()
		stats.Accounts = append(stats.Accounts, as)
	}

	// Mark the highest-scoring account per provider type as primary
	highestScore := make(map[string]float64)
	highestIdx := make(map[string]int)
	for i, as := range stats.Accounts {
		if as.Status != "dead" && as.Score > highestScore[as.Type] {
			highestScore[as.Type] = as.Score
			highestIdx[as.Type] = i
		}
	}
	for _, idx := range highestIdx {
		stats.Accounts[idx].IsPrimary = true
	}

	stats.ActiveAccounts = activeCount

	overallCacheRate := float64(0)
	if totalInput > 0 {
		overallCacheRate = float64(totalCached) / float64(totalInput) * 100
	}

	avgPrimary := float64(0)
	avgSecondary := float64(0)
	if len(accounts) > 0 {
		avgPrimary = (primarySum / float64(len(accounts))) * 100
		avgSecondary = (secondarySum / float64(len(accounts))) * 100
	}

	stats.AggregateUsage = AggregateStats{
		TotalInputTokens:     totalInput,
		TotalCachedTokens:    totalCached,
		TotalOutputTokens:    totalOutput,
		TotalReasoningTokens: totalReasoning,
		TotalBillableTokens:  totalBillable,
		AvgPrimaryUsed:       avgPrimary,
		AvgSecondaryUsed:     avgSecondary,
		OverallCacheHitRate:  overallCacheRate,
	}

	// Load capacity analysis from store
	if h.store != nil {
		caps, err := h.store.loadAllPlanCapacity()
		if err == nil && len(caps) > 0 {
			analysis := &CapacityAnalysis{
				Plans:        make(map[string]PlanCapacityInfo),
				ModelFormula: "effective = input + (cached × 0.1) + (output × mult) + (reasoning × mult)",
			}
			for planType, cap := range caps {
				analysis.TotalSamples += cap.SampleCount
				confidence := "low"
				if cap.SampleCount >= 20 {
					confidence = "high"
				} else if cap.SampleCount >= 5 {
					confidence = "medium"
				}
				mult := cap.OutputMultiplier
				if mult == 0 {
					mult = 4.0
				}
				var estPrimary, estSecondary int64
				if cap.EffectivePerPrimaryPct > 0 {
					estPrimary = int64(cap.EffectivePerPrimaryPct * 100)
				}
				if cap.EffectivePerSecondaryPct > 0 {
					estSecondary = int64(cap.EffectivePerSecondaryPct * 100)
				}
				analysis.Plans[planType] = PlanCapacityInfo{
					SampleCount:                cap.SampleCount,
					Confidence:                 confidence,
					TotalInputTokens:           cap.TotalInputTokens,
					TotalOutputTokens:          cap.TotalOutputTokens,
					TotalCachedTokens:          cap.TotalCachedTokens,
					TotalReasoningTokens:       cap.TotalReasoningTokens,
					OutputMultiplier:           mult,
					EstimatedPrimaryCapacity:   estPrimary,
					EstimatedSecondaryCapacity: estSecondary,
				}
			}
			stats.CapacityAnalysis = analysis
		}
	}

	// Include last 24h tokens aggregate from hourly buckets
	if h.store != nil {
		if hourly, err := h.store.getGlobalHourlyUsage(24); err == nil {
			for _, hu := range hourly {
				stats.Last24hTokens += hu.BillableTokens
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

// handleWhoami returns the current user's ID based on their JWT, Claude pool token, or hashed IP.
func (h *proxyHandler) handleWhoami(w http.ResponseWriter, r *http.Request) {
	var userID string
	var userType string
	authHeader := r.Header.Get("Authorization")
	secret := getPoolJWTSecret()

	// Check for Claude pool tokens first (sk-ant-oat01-pool-* or legacy sk-ant-api-pool-*)
	if secret != "" {
		if isClaudePool, uid := isClaudePoolToken(secret, authHeader); isClaudePool {
			userID = uid
			userType = "pool_user"
		}
	}

	// Check for JWT-based pool tokens (Codex, Gemini)
	if userID == "" && secret != "" {
		if isPoolUser, uid, _ := isPoolUserToken(secret, authHeader); isPoolUser {
			userID = uid
			userType = "pool_user"
		}
	}

	// Check for Gemini OAuth pool tokens (ya29.pool-*)
	if userID == "" && secret != "" && strings.HasPrefix(authHeader, "Bearer ") {
		token := strings.TrimPrefix(authHeader, "Bearer ")
		if isPoolToken, uid := isGeminiOAuthPoolToken(secret, token); isPoolToken {
			userID = uid
			userType = "pool_user"
		}
	}

	if userID == "" {
		ip := getClientIP(r)
		salt := h.cfg.friendCode
		if salt == "" {
			salt = "codex-pool"
		}
		userID = hashUserIP(ip, salt)
		userType = "anonymous"
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"user_id": userID,
		"type":    userType,
	})
}

// PoolUserStats represents a user's usage for the leaderboard.
type PoolUserStats struct {
	UserID              string    `json:"user_id"`
	TotalBillableTokens int64     `json:"total_billable_tokens"`
	TotalInputTokens    int64     `json:"total_input_tokens"`
	TotalOutputTokens   int64     `json:"total_output_tokens"`
	RequestCount        int64     `json:"request_count"`
	FirstSeen           time.Time `json:"first_seen"`
	LastSeen            time.Time `json:"last_seen"`
}

// handlePoolUsers returns the public leaderboard of all users' usage.
func (h *proxyHandler) handlePoolUsers(w http.ResponseWriter, r *http.Request) {
	users, err := h.store.getAllUserUsage()
	if err != nil {
		http.Error(w, "failed to fetch user usage", http.StatusInternalServerError)
		return
	}

	// Convert to API format
	stats := make([]PoolUserStats, len(users))
	for i, u := range users {
		stats[i] = PoolUserStats{
			UserID:              u.UserID,
			TotalBillableTokens: u.TotalBillableTokens,
			TotalInputTokens:    u.TotalInputTokens,
			TotalOutputTokens:   u.TotalOutputTokens,
			RequestCount:        u.RequestCount,
			FirstSeen:           u.FirstSeen,
			LastSeen:            u.LastSeen,
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"users":       stats,
		"total_users": len(stats),
	})
}

// handleDailyBreakdown returns combined daily token usage from all accounts.
func (h *proxyHandler) handleDailyBreakdown(w http.ResponseWriter, r *http.Request) {
	type DayUsage struct {
		Date     string             `json:"date"`
		Surfaces map[string]float64 `json:"surfaces"`
		Total    float64            `json:"total"`
	}

	// Aggregate daily data from all accounts
	combined := make(map[string]*DayUsage) // date -> usage

	accounts := h.pool.allAccounts()
	for _, acc := range accounts {
		if acc.Type != AccountTypeCodex || acc.Dead {
			continue
		}

		data, err := h.fetchDailyBreakdownData(acc)
		if err != nil {
			continue
		}

		for _, day := range data {
			if combined[day.Date] == nil {
				combined[day.Date] = &DayUsage{
					Date:     day.Date,
					Surfaces: make(map[string]float64),
				}
			}
			for surface, val := range day.Surfaces {
				combined[day.Date].Surfaces[surface] += val
				combined[day.Date].Total += val
			}
		}
	}

	// Convert to sorted slice
	var result []DayUsage
	for _, v := range combined {
		result = append(result, *v)
	}
	// Sort by date
	for i := 0; i < len(result); i++ {
		for j := i + 1; j < len(result); j++ {
			if result[i].Date > result[j].Date {
				result[i], result[j] = result[j], result[i]
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"days":          result,
		"account_count": len(accounts),
	})
}

// handleUserDaily returns a user's daily usage over the last N days.
func (h *proxyHandler) handleUserDaily(w http.ResponseWriter, r *http.Request) {
	// Extract user ID from path: /api/pool/users/:id/daily
	path := r.URL.Path
	path = strings.TrimPrefix(path, "/api/pool/users/")
	path = strings.TrimSuffix(path, "/daily")
	userID := path

	if userID == "" {
		http.Error(w, "user ID required", http.StatusBadRequest)
		return
	}

	// Get days parameter (default 30)
	days := 30
	if d := r.URL.Query().Get("days"); d != "" {
		if n, err := strconv.Atoi(d); err == nil && n > 0 && n <= 90 {
			days = n
		}
	}

	daily, err := h.store.getUserDailyUsage(userID, days)
	if err != nil {
		http.Error(w, "failed to fetch daily usage", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"user_id": userID,
		"days":    days,
		"daily":   daily,
	})
}

// handleUserHourly returns a user's hourly usage over the last N hours.
func (h *proxyHandler) handleUserHourly(w http.ResponseWriter, r *http.Request) {
	// Extract user ID from path: /api/pool/users/:id/hourly
	path := r.URL.Path
	path = strings.TrimPrefix(path, "/api/pool/users/")
	path = strings.TrimSuffix(path, "/hourly")
	userID := path

	if userID == "" {
		http.Error(w, "user ID required", http.StatusBadRequest)
		return
	}

	hours := 24
	if h := r.URL.Query().Get("hours"); h != "" {
		if n, err := strconv.Atoi(h); err == nil && n > 0 && n <= 168 {
			hours = n
		}
	}

	hourly, err := h.store.getUserHourlyUsage(userID, hours)
	if err != nil {
		http.Error(w, "failed to fetch hourly usage", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"user_id": userID,
		"hours":   hours,
		"hourly":  hourly,
	})
}

// handleGlobalHourly returns global hourly usage (all users combined) over the last N hours.
func (h *proxyHandler) handleGlobalHourly(w http.ResponseWriter, r *http.Request) {
	hours := 24
	if hParam := r.URL.Query().Get("hours"); hParam != "" {
		if n, err := strconv.Atoi(hParam); err == nil && n > 0 && n <= 168 {
			hours = n
		}
	}

	hourly, err := h.store.getGlobalHourlyUsage(hours)
	if err != nil {
		http.Error(w, "failed to fetch hourly usage", http.StatusInternalServerError)
		return
	}

	// Calculate aggregate totals for the period
	var totalBillable, totalInput, totalOutput, totalCached, totalReasoning, totalRequests int64
	for _, h := range hourly {
		totalBillable += h.BillableTokens
		totalInput += h.InputTokens
		totalOutput += h.OutputTokens
		totalCached += h.CachedTokens
		totalReasoning += h.ReasoningTokens
		totalRequests += h.RequestCount
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"hours":  hours,
		"hourly": hourly,
		"totals": map[string]int64{
			"billable_tokens":  totalBillable,
			"input_tokens":     totalInput,
			"output_tokens":    totalOutput,
			"cached_tokens":    totalCached,
			"reasoning_tokens": totalReasoning,
			"request_count":    totalRequests,
		},
	})
}

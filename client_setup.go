package main

import (
	"fmt"
	"net/http"
	"strings"
)

func (h *proxyHandler) serveGrokSetupScript(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimPrefix(r.URL.Path, "/setup/grok/")
	if token == "" || strings.Contains(token, "/") {
		http.Error(w, "invalid token", http.StatusBadRequest)
		return
	}
	baseURL := strings.TrimRight(h.getEffectivePublicURL(r), "/")
	setupModels := grokSetupModels()

	if wantsPowerShell(r) {
		powerShellModels := make([]string, 0, len(setupModels))
		for _, model := range setupModels {
			modelID := strings.ReplaceAll(model.ID, "'", "''")
			backend := strings.ReplaceAll(model.APIBackend, "'", "''")
			powerShellModels = append(powerShellModels, "@{ Id = '"+modelID+"'; Backend = '"+backend+"' }")
		}
		script := fmt.Sprintf(`#requires -Version 5.1
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$Token = '%s'
$BaseUrl = '%s'
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
$Models = @(%s)
foreach ($Model in $Models) {
  $Output.Add('[model."' + $Model.Id + '"]')
  $Output.Add('api_key = "' + ($ApiKey -replace '"', '\"') + '"')
  $Output.Add('api_backend = "' + $Model.Backend + '"')
}
$Output.Add('# END CODEX-POOL GROK')

$Utf8 = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText($ConfigFile, (($Output -join [Environment]::NewLine).Trim() + [Environment]::NewLine), $Utf8)
Write-Host "Grok Build model discovery and inference now use codex-pool. Config saved to $ConfigFile"
`, token, baseURL, strings.Join(powerShellModels, ", "))
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write([]byte(script))
		return
	}

	modelSpecs := make([]string, 0, len(setupModels))
	for _, model := range setupModels {
		modelSpecs = append(modelSpecs, model.ID+":"+model.APIBackend)
	}
	script := fmt.Sprintf(`#!/bin/bash
set -euo pipefail
TOKEN="%s"
BASE_URL="%s"
CONFIG_DIR="$HOME/.grok"
CONFIG_FILE="$CONFIG_DIR/config.toml"
AUTH_FILE="$CONFIG_DIR/auth.json"
AUTH_BACKUP="$CONFIG_DIR/auth.json.before-codex-pool"
TMP_FILE=$(mktemp "${TMPDIR:-/tmp}/codex-pool-grok.XXXXXX")
trap 'rm -f "$TMP_FILE"' EXIT

mkdir -p "$CONFIG_DIR"
if command -v grok >/dev/null 2>&1; then
  grok leader kill >/dev/null 2>&1 || true
fi
if [ -f "$AUTH_FILE" ]; then
  if [ -e "$AUTH_BACKUP" ]; then
    rm -f "$AUTH_FILE"
  else
    mv "$AUTH_FILE" "$AUTH_BACKUP"
  fi
fi
API_KEY=$(curl -fsSL "$BASE_URL/config/grok/$TOKEN" | sed -n 's/.*"api_key"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n 1)
if [ -z "$API_KEY" ]; then
  echo "Pool credential response did not contain api_key" >&2
  exit 1
fi
touch "$CONFIG_FILE"

awk '
BEGIN { managed=0; in_endpoints=0; saw_endpoints=0; wrote_models_base=0 }
$0 == "# BEGIN CODEX-POOL GROK" { managed=1; next }
managed && $0 == "# END CODEX-POOL GROK" { managed=0; next }
managed { next }
/^[[:space:]]*\[/ {
  if (in_endpoints && !wrote_models_base) print "models_base_url = \"'"$BASE_URL"'/v1\""
  in_endpoints = ($0 ~ /^[[:space:]]*\[endpoints\][[:space:]]*$/)
  if (in_endpoints) { saw_endpoints=1; wrote_models_base=0 }
}
in_endpoints && /^[[:space:]]*models_base_url[[:space:]]*=/ {
  print "models_base_url = \"'"$BASE_URL"'/v1\""
  wrote_models_base=1
  next
}
{ print }
END {
  if (in_endpoints && !wrote_models_base) print "models_base_url = \"'"$BASE_URL"'/v1\""
  if (!saw_endpoints) print "\n[endpoints]\nmodels_base_url = \"'"$BASE_URL"'/v1\""
}
' "$CONFIG_FILE" > "$TMP_FILE"

{
  cat "$TMP_FILE"
  printf '\n# BEGIN CODEX-POOL GROK\n'
  for MODEL_SPEC in %s; do
    MODEL_ID="${MODEL_SPEC%%:*}"
    API_BACKEND="${MODEL_SPEC##*:}"
    printf '[model."%%s"]\n' "$MODEL_ID"
    printf 'api_key = "%%s"\n' "$API_KEY"
    printf 'api_backend = "%%s"\n' "$API_BACKEND"
  done
  printf '# END CODEX-POOL GROK\n'
} > "$CONFIG_FILE"
chmod 600 "$CONFIG_FILE"
printf 'Grok Build model discovery and inference now use codex-pool. Config saved to %%s\n' "$CONFIG_FILE"
`, token, baseURL, strings.Join(modelSpecs, " "))
	w.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
	w.Write([]byte(script))
}

func (h *proxyHandler) servePiSetupScript(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimPrefix(r.URL.Path, "/setup/pi/")
	if token == "" || strings.Contains(token, "/") {
		http.Error(w, "invalid token", http.StatusBadRequest)
		return
	}
	baseURL := strings.TrimRight(h.getEffectivePublicURL(r), "/")

	if wantsPowerShell(r) {
		script := fmt.Sprintf(`#requires -Version 5.1
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ConfigDir = Join-Path $HOME '.pi\agent'
$ModelsFile = Join-Path $ConfigDir 'models.json'
$Incoming = Invoke-RestMethod -Uri '%s/config/pi/%s'
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
`, baseURL, token)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write([]byte(script))
		return
	}

	script := fmt.Sprintf(`#!/bin/bash
set -euo pipefail
CONFIG_DIR="$HOME/.pi/agent"
MODELS_FILE="$CONFIG_DIR/models.json"
INCOMING_FILE=$(mktemp "${TMPDIR:-/tmp}/codex-pool-pi.XXXXXX")
trap 'rm -f "$INCOMING_FILE"' EXIT
mkdir -p "$CONFIG_DIR"
curl -fsSL "%s/config/pi/%s" -o "$INCOMING_FILE"
MODELS_FILE="$MODELS_FILE" INCOMING_FILE="$INCOMING_FILE" node <<'NODE'
const fs = require('fs');
const modelsFile = process.env.MODELS_FILE;
const incoming = JSON.parse(fs.readFileSync(process.env.INCOMING_FILE, 'utf8'));
let existing = {};
try { existing = JSON.parse(fs.readFileSync(modelsFile, 'utf8')); } catch (_) {}
existing.providers = { ...(existing.providers || {}), ...(incoming.providers || {}) };
fs.writeFileSync(modelsFile, JSON.stringify(existing, null, 2) + '\n', { mode: 0o600 });
NODE
chmod 600 "$MODELS_FILE"
printf 'Pool providers merged into %%s. Open /model in Pi to reload them.\n' "$MODELS_FILE"
`, baseURL, token)
	w.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
	w.Write([]byte(script))
}

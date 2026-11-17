#!/bin/bash
set -euo pipefail
TOKEN="{{token}}"
BASE_URL="{{public_url}}"
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
  for MODEL_SPEC in {{models}}; do
    MODEL_ID="${MODEL_SPEC%:*}"
    API_BACKEND="${MODEL_SPEC##*:}"
    printf '[model."%s"]\n' "$MODEL_ID"
    printf 'api_key = "%s"\n' "$API_KEY"
    printf 'api_backend = "%s"\n' "$API_BACKEND"
  done
  printf '# END CODEX-POOL GROK\n'
} > "$CONFIG_FILE"
chmod 600 "$CONFIG_FILE"
printf 'Grok Build model discovery and inference now use codex-pool. Config saved to %s\n' "$CONFIG_FILE"

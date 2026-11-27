#!/bin/bash
set -euo pipefail
TOKEN="{{token}}"
BASE_URL="{{public_url}}"
AUTH_DIR="$HOME/.codex"
CONFIG_FILE="$AUTH_DIR/config.toml"
AUTH_FILE="$AUTH_DIR/auth.json"
MODEL_CATALOG="$AUTH_DIR/model_catalog.json"
MCP_SCRIPT="$AUTH_DIR/model_sync.sh"

# The catalog lists only models the requesting client version supports, so
# ask with the installed CLI's version. Without a CLI, use the current release.
codex_client_version() {
    local version
    version=$(codex --version 2>/dev/null | grep -Eo '[0-9]+\.[0-9]+\.[0-9]+' | head -n 1 || true)
    printf '%s' "${version:-{{codex_version}}}"
}

echo "Initializing Codex Pool setup..."
mkdir -p "$AUTH_DIR"

echo "1. Fetching credentials..."
curl -sL "$BASE_URL/config/codex/$TOKEN" -o "$AUTH_FILE"
chmod 600 "$AUTH_FILE"

echo "2. Fetching model catalog..."
ACCESS_TOKEN=$(sed -n 's/.*"access_token"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$AUTH_FILE" | head -n 1)
if [ -z "${ACCESS_TOKEN:-}" ]; then
    echo "Pool credentials are missing. Generate a new setup command from the pool page." >&2
    exit 1
fi
CATALOG_TMP=$(mktemp "${MODEL_CATALOG}.tmp.XXXXXX")
if ! curl --connect-timeout 5 --max-time 10 -fsSL \
    -H "Authorization: Bearer $ACCESS_TOKEN" \
    "$BASE_URL/backend-api/codex/models?client_version=$(codex_client_version)" \
    -o "$CATALOG_TMP"; then
    rm -f "$CATALOG_TMP"
    echo "Model catalog download failed. Check your connection and rerun setup." >&2
    exit 1
fi
chmod 600 "$CATALOG_TMP"
mv "$CATALOG_TMP" "$MODEL_CATALOG"

echo "3. Installing model sync MCP sidecar..."
cat <<'EOF' > "$MCP_SCRIPT"
#!/bin/bash
set -euo pipefail

BASE_URL="${1:-}"
AUTH_DIR="${HOME}/.codex"
AUTH_FILE="$AUTH_DIR/auth.json"
MODEL_CATALOG="$AUTH_DIR/model_catalog.json"

codex_client_version() {
    local version
    version=$(codex --version 2>/dev/null | grep -Eo '[0-9]+\.[0-9]+\.[0-9]+' | head -n 1 || true)
    printf '%s' "${version:-{{codex_version}}}"
}

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
        "${BASE_URL%/}/backend-api/codex/models?client_version=$(codex_client_version)" \
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
    line="${line%$'\r'}"

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
                content_length=$(printf '%s' "${line#*:}" | tr -d '[:space:]')
                ;;
        esac
        if ! IFS= read -r line; then
            return 1
        fi
        line="${line%$'\r'}"
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
        printf '%s\n' "$payload"
        return
    fi

    local length
    length=$(printf '%s' "$payload" | LC_ALL=C wc -c | tr -d '[:space:]')
    printf 'Content-Length: %s\r\n\r\n%s' "$length" "$payload"
}

handle_request() {
    local request="$1"
    local method id payload

    method=$(printf '%s' "$request" | sed -n 's/.*"method"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n 1)
    id=$(printf '%s' "$request" | sed -n 's/.*"id"[[:space:]]*:[[:space:]]*\([^,}]*\).*/\1/p' | head -n 1)
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

# Only a root model selects the default; profile models remain independent.
if ! awk '/^[[:space:]]*\[/ { exit } /^[[:space:]]*model[[:space:]]*=/ { found=1 } END { exit !found }' "$CONFIG_FILE"; then
    TEMP_FILE=$(mktemp)
    printf 'model = "gpt-6-astra"\n' > "$TEMP_FILE"
    cat "$CONFIG_FILE" >> "$TEMP_FILE"
    mv "$TEMP_FILE" "$CONFIG_FILE"
    chmod 600 "$CONFIG_FILE"
fi

# Check if config already exists to avoid duplication
if ! grep -q "codex-pool" "$CONFIG_FILE"; then
    # Create temp file with pool config at TOP, then append existing config
    TEMP_FILE=$(mktemp)
    cat <<EOF > "$TEMP_FILE"
# Codex Pool Proxy Config
model_provider = "codex-pool"
chatgpt_base_url = "$BASE_URL/backend-api"
experimental_realtime_webrtc_call_base_url = "$BASE_URL/v1"
experimental_realtime_ws_base_url = "$BASE_URL/v1"
realtime.version = "v3"
realtime.transport = "webrtc"
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

    if ! grep -Eq '^[[:space:]]*experimental_realtime_webrtc_call_base_url[[:space:]]*=' "$CONFIG_FILE"; then
        TEMP_FILE=$(mktemp)
        cat <<EOF > "$TEMP_FILE"
experimental_realtime_webrtc_call_base_url = "$BASE_URL/v1"
EOF
        cat "$CONFIG_FILE" >> "$TEMP_FILE"
        mv "$TEMP_FILE" "$CONFIG_FILE"
        UPDATED=1
    fi

    if ! grep -Eq '^[[:space:]]*experimental_realtime_ws_base_url[[:space:]]*=' "$CONFIG_FILE"; then
        TEMP_FILE=$(mktemp)
        cat <<EOF > "$TEMP_FILE"
experimental_realtime_ws_base_url = "$BASE_URL/v1"
EOF
        cat "$CONFIG_FILE" >> "$TEMP_FILE"
        mv "$TEMP_FILE" "$CONFIG_FILE"
        UPDATED=1
    fi

    if ! grep -Eq '^[[:space:]]*realtime\.version[[:space:]]*=' "$CONFIG_FILE" && ! grep -q '^\[realtime\]' "$CONFIG_FILE"; then
        TEMP_FILE=$(mktemp)
        cat <<EOF > "$TEMP_FILE"
realtime.version = "v3"
realtime.transport = "webrtc"
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

if command -v codex >/dev/null 2>&1; then
    codex features enable realtime_conversation >/dev/null 2>&1 || true
fi

echo "Setup complete! You are ready to use the pool."

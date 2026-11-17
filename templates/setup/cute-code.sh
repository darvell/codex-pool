#!/bin/bash
set -euo pipefail
CONFIG_URL="{{public_url}}/config/cute-code/{{token}}"
CLAUDE_DIR="${CLAUDE_CONFIG_DIR:-$HOME/.claude}"
SETTINGS_FILE="$CLAUDE_DIR/settings.json"
TMP_FILE="$(mktemp)"

mkdir -p "$CLAUDE_DIR"

printf 'Installing cute-code...\n'
if command -v curl >/dev/null 2>&1; then
    curl -fsSL https://git.irrigate.cc/pp/cute-code/raw/branch/main/install.sh | bash || true
fi

curl -fsSL "$CONFIG_URL" -o "$TMP_FILE"

if command -v node >/dev/null 2>&1; then
    SETTINGS_FILE="$SETTINGS_FILE" TMP_FILE="$TMP_FILE" node << 'NODE_SCRIPT'
const fs = require('fs');
const settingsFile = process.env.SETTINGS_FILE;
const tmpFile = process.env.TMP_FILE;
let settings = {};
let incoming = {};
try { settings = JSON.parse(fs.readFileSync(settingsFile, 'utf8')); } catch {}
incoming = JSON.parse(fs.readFileSync(tmpFile, 'utf8'));
settings = { ...settings, ...incoming };
fs.writeFileSync(settingsFile, JSON.stringify(settings, null, 2) + '\n');
NODE_SCRIPT
elif command -v python3 >/dev/null 2>&1; then
    SETTINGS_FILE="$SETTINGS_FILE" TMP_FILE="$TMP_FILE" python3 << 'PYTHON_SCRIPT'
import json, os
settings_file = os.environ['SETTINGS_FILE']
tmp_file = os.environ['TMP_FILE']
try:
    with open(settings_file) as f: settings = json.load(f)
except Exception:
    settings = {}
with open(tmp_file) as f: incoming = json.load(f)
settings.update(incoming)
with open(settings_file, 'w') as f:
    json.dump(settings, f, indent=2)
    f.write('\n')
PYTHON_SCRIPT
else
    cp "$SETTINGS_FILE" "$SETTINGS_FILE.bak" 2>/dev/null || true
    cp "$TMP_FILE" "$SETTINGS_FILE"
fi

rm -f "$TMP_FILE"
printf 'cute-code pool settings saved to %s\n' "$SETTINGS_FILE"
printf 'Run: cute-code --model gpt-6-astra\n'

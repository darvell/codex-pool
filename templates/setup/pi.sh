#!/bin/bash
set -euo pipefail
CONFIG_DIR="$HOME/.pi/agent"
MODELS_FILE="$CONFIG_DIR/models.json"
INCOMING_FILE=$(mktemp "${TMPDIR:-/tmp}/codex-pool-pi.XXXXXX")
trap 'rm -f "$INCOMING_FILE"' EXIT
mkdir -p "$CONFIG_DIR"
curl -fsSL "{{public_url}}/config/pi/{{token}}" -o "$INCOMING_FILE"
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
printf 'Pool providers merged into %s. Open /model in Pi to reload them.\n' "$MODELS_FILE"

#!/bin/bash
IS_SOURCED=0
if [ -n "$ZSH_VERSION" ]; then
    case $ZSH_EVAL_CONTEXT in *:file) IS_SOURCED=1 ;; esac
elif [ -n "$BASH_VERSION" ]; then
    if [ "${BASH_SOURCE[0]}" != "$0" ]; then IS_SOURCED=1; fi
fi
ERREXIT_WAS_SET=0
case $- in *e*) ERREXIT_WAS_SET=1 ;; esac
set -e
BASE_URL="{{public_url}}"
OAUTH_TOKEN="{{access_token}}"

echo "Configuring Claude Code for pool access..."
echo ""

CONFLICTING_ENV_VARS=(
    ANTHROPIC_AUTH_TOKEN
    ANTHROPIC_API_KEY
    CLAUDE_CODE_USE_BEDROCK
    CLAUDE_CODE_USE_VERTEX
    CLAUDE_CODE_USE_FOUNDRY
    CLAUDE_CODE_PROVIDER_MANAGED_BY_HOST
    ANTHROPIC_UNIX_SOCKET
    CLAUDE_CODE_SIMPLE
)

# Claude Code disables Claude.ai OAuth mode when these auth/provider vars are present.
for name in "${CONFLICTING_ENV_VARS[@]}"; do
    unset "$name"
done

# Set env vars in the current shell if this script is sourced
export ANTHROPIC_BASE_URL="$BASE_URL"
export CLAUDE_CODE_OAUTH_TOKEN="$OAUTH_TOKEN"

# Add env vars to shell profile (Claude Code reads tokens from process.env)
add_to_profile() {
    for profile in "$HOME/.zshrc" "$HOME/.bashrc" "$HOME/.bash_profile" "$HOME/.profile"; do
        if [ -f "$profile" ]; then
            tmp="$profile.tmp"
            cp "$profile" "$tmp"
            for name in ANTHROPIC_BASE_URL CLAUDE_CODE_OAUTH_TOKEN "${CONFLICTING_ENV_VARS[@]}"; do
                grep -v -E "^[[:space:]]*(export[[:space:]]+)?${name}=" "$tmp" > "$tmp.next" || true
                mv "$tmp.next" "$tmp"
            done
            mv "$tmp" "$profile"

            # Add pool configuration
            cat >> "$profile" << 'ENVEOF'

# Claude Code Pool Configuration
unset ANTHROPIC_AUTH_TOKEN
unset ANTHROPIC_API_KEY
unset CLAUDE_CODE_USE_BEDROCK
unset CLAUDE_CODE_USE_VERTEX
unset CLAUDE_CODE_USE_FOUNDRY
unset CLAUDE_CODE_PROVIDER_MANAGED_BY_HOST
unset ANTHROPIC_UNIX_SOCKET
unset CLAUDE_CODE_SIMPLE
export ANTHROPIC_BASE_URL="{{public_url}}"
export CLAUDE_CODE_OAUTH_TOKEN="{{access_token}}"
ENVEOF
            echo "✓ Added Claude Code pool config to $(basename $profile)"
            return
        fi
    done

    # Fallback: create .zshrc
    cat >> "$HOME/.zshrc" << 'ENVEOF'

# Claude Code Pool Configuration
unset ANTHROPIC_AUTH_TOKEN
unset ANTHROPIC_API_KEY
unset CLAUDE_CODE_USE_BEDROCK
unset CLAUDE_CODE_USE_VERTEX
unset CLAUDE_CODE_USE_FOUNDRY
unset CLAUDE_CODE_PROVIDER_MANAGED_BY_HOST
unset ANTHROPIC_UNIX_SOCKET
unset CLAUDE_CODE_SIMPLE
export ANTHROPIC_BASE_URL="{{public_url}}"
export CLAUDE_CODE_OAUTH_TOKEN="{{access_token}}"
ENVEOF
    echo "✓ Created ~/.zshrc with Claude Code pool config"
}

CLAUDE_DIR="${CLAUDE_CONFIG_DIR:-$HOME/.claude}"
mkdir -p "$CLAUDE_DIR"
SETTINGS_FILE="$CLAUDE_DIR/settings.json"
CLAUDE_JSON="$HOME/.claude.json"

# Update settings.json with env vars
update_settings() {
    if command -v node &> /dev/null; then
        node << 'NODE_SCRIPT'
const fs = require('fs');
const path = require('path');
const dir = process.env.CLAUDE_CONFIG_DIR || path.join(process.env.HOME, '.claude');
const file = path.join(dir, 'settings.json');
const conflictingEnvVars = [
  'ANTHROPIC_AUTH_TOKEN',
  'ANTHROPIC_API_KEY',
  'CLAUDE_CODE_USE_BEDROCK',
  'CLAUDE_CODE_USE_VERTEX',
  'CLAUDE_CODE_USE_FOUNDRY',
  'CLAUDE_CODE_PROVIDER_MANAGED_BY_HOST',
  'ANTHROPIC_UNIX_SOCKET',
  'CLAUDE_CODE_SIMPLE',
];
let settings = {};
try { settings = JSON.parse(fs.readFileSync(file, 'utf8')); } catch {}
delete settings.apiKeyHelper;
settings.env = settings.env || {};
for (const name of conflictingEnvVars) delete settings.env[name];
settings.env.ANTHROPIC_BASE_URL = '{{public_url}}';
settings.env.CLAUDE_CODE_OAUTH_TOKEN = '{{access_token}}';
fs.writeFileSync(file, JSON.stringify(settings, null, 2) + '\n');
console.log('✓ Updated settings.json (node)');
NODE_SCRIPT
    elif command -v python3 &> /dev/null; then
        python3 << 'PYTHON_SCRIPT'
import json, os
dir = os.environ.get('CLAUDE_CONFIG_DIR') or os.path.expanduser('~/.claude')
file = os.path.join(dir, 'settings.json')
conflicting_env_vars = [
    'ANTHROPIC_AUTH_TOKEN',
    'ANTHROPIC_API_KEY',
    'CLAUDE_CODE_USE_BEDROCK',
    'CLAUDE_CODE_USE_VERTEX',
    'CLAUDE_CODE_USE_FOUNDRY',
    'CLAUDE_CODE_PROVIDER_MANAGED_BY_HOST',
    'ANTHROPIC_UNIX_SOCKET',
    'CLAUDE_CODE_SIMPLE',
]
try:
    with open(file) as f: settings = json.load(f)
except: settings = {}
settings.pop('apiKeyHelper', None)
settings.setdefault('env', {})
for name in conflicting_env_vars:
    settings['env'].pop(name, None)
settings['env']['ANTHROPIC_BASE_URL'] = '{{public_url}}'
settings['env']['CLAUDE_CODE_OAUTH_TOKEN'] = '{{access_token}}'
with open(file, 'w') as f: json.dump(settings, f, indent=2); f.write('\n')
print("✓ Updated settings.json (python)")
PYTHON_SCRIPT
    else
        [ -f "$SETTINGS_FILE" ] && cp "$SETTINGS_FILE" "$SETTINGS_FILE.bak"
        cat > "$SETTINGS_FILE" << 'EOF'
{
  "env": {
    "ANTHROPIC_BASE_URL": "{{public_url}}",
    "CLAUDE_CODE_OAUTH_TOKEN": "{{access_token}}"
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

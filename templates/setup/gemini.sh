#!/bin/bash
set -e
BASE_URL="{{public_url}}"
POOL_TOKEN="{{access_token}}"

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
export CODE_ASSIST_ENDPOINT="{{public_url}}"
export GOOGLE_GENAI_USE_GCA=1
export GOOGLE_CLOUD_ACCESS_TOKEN="{{access_token}}"
ENVEOF
            echo "✓ Added Gemini pool config to $(basename $profile)"
            return
        fi
    done

    # Fallback: create .zshrc
    cat >> "$HOME/.zshrc" << 'ENVEOF'

# Gemini Pool Configuration
export CODE_ASSIST_ENDPOINT="{{public_url}}"
export GOOGLE_GENAI_USE_GCA=1
export GOOGLE_CLOUD_ACCESS_TOKEN="{{access_token}}"
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

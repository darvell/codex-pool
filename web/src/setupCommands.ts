type SetupTool = { name: string; install: string; oneliner: string; powershell: string; manual: { file: string; url: string }[] };

export function setupCommands(base: string, token: string): Record<string, SetupTool> {
  return {
    codex: {
      name: "Codex",
      install: "npm install -g @openai/codex    # or: brew install codex",
      oneliner: `curl -sL "${base}/setup/codex/${token}" | bash`,
      powershell: `irm "${base}/setup/codex/${token}?shell=powershell" | iex`,
      manual: [{ file: "~/.codex/auth.json", url: `${base}/config/codex/${token}` }],
    },
    claude: {
      name: "Claude Code",
      install: "npm install -g @anthropic-ai/claude-code",
      oneliner: `source <(curl -sL "${base}/setup/claude/${token}")`,
      powershell: `irm "${base}/setup/claude/${token}?shell=powershell" | iex`,
      manual: [{ file: "~/.claude/settings.json", url: `${base}/config/claude/${token}` }],
    },
    gemini: {
      name: "Gemini",
      install: "npm install -g @google/gemini-cli    # or: brew install gemini-cli",
      oneliner: `curl -sL "${base}/setup/gemini/${token}" | bash`,
      powershell: `irm "${base}/setup/gemini/${token}?shell=powershell" | iex`,
      manual: [{ file: "~/.gemini/oauth_creds.json", url: `${base}/config/gemini/${token}` }],
    },
    grok: {
      name: "Grok",
      install: "npm install -g @xai/grok-cli",
      oneliner: `curl -sL "${base}/setup/grok/${token}" | bash`,
      powershell: `irm "${base}/setup/grok/${token}?shell=powershell" | iex`,
      manual: [{ file: "grok auth", url: `${base}/config/grok/${token}` }],
    },
    "cute-code": {
      name: "Cute Code",
      install: "curl -fsSL https://git.irrigate.cc/pp/cute-code/raw/branch/main/install.sh | bash",
      oneliner: `curl -sL "${base}/setup/cute-code/${token}" | bash`,
      powershell: `irm "${base}/setup/cute-code/${token}?shell=powershell" | iex`,
      manual: [{ file: "~/.claude/settings.json", url: `${base}/config/cute-code/${token}` }],
    },
    pi: {
      name: "Pi",
      install: "npm install -g pi-cli",
      oneliner: `curl -sL "${base}/setup/pi/${token}" | bash`,
      powershell: `irm "${base}/setup/pi/${token}?shell=powershell" | iex`,
      manual: [{ file: "pi models.json", url: `${base}/config/pi/${token}` }],
    },
  };
}

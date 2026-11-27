package main

import (
	_ "embed"
	"strings"
)

type setupScriptData struct {
	token       string
	publicURL   string
	accessToken string
	models      string
	// codexVersion is the CLI version the pool currently presents upstream.
	// The Codex script falls back to it when the installed CLI cannot report
	// its own version.
	codexVersion string
}

func renderSetupScript(source string, data setupScriptData) string {
	return strings.NewReplacer(
		"{{token}}", data.token,
		"{{public_url}}", data.publicURL,
		"{{access_token}}", data.accessToken,
		"{{models}}", data.models,
		"{{codex_version}}", data.codexVersion,
	).Replace(source)
}

//go:embed templates/setup/cute-code.sh
var cuteCodeBash string

//go:embed templates/setup/cute-code.ps1
var cuteCodePowerShell string

//go:embed templates/setup/codex.sh
var codexBash string

//go:embed templates/setup/codex.ps1
var codexPowerShell string

//go:embed templates/setup/gemini.sh
var geminiBash string

//go:embed templates/setup/gemini.ps1
var geminiPowerShell string

//go:embed templates/setup/claude.sh
var claudeBash string

//go:embed templates/setup/claude.ps1
var claudePowerShell string

//go:embed templates/setup/grok.sh
var grokBash string

//go:embed templates/setup/grok.ps1
var grokPowerShell string

//go:embed templates/setup/pi.sh
var piBash string

//go:embed templates/setup/pi.ps1
var piPowerShell string

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
)

// ---------------------------------------------------------------------------
// Claude Code fingerprint constants
//
// These MUST be kept in sync with the real Claude Code CLI. When Claude Code
// ships a new version, update these values. The source of truth is:
//   - Version:     claude-code/package.json "version"
//   - SDK version: claude-code/package.json "@anthropic-ai/sdk"
//   - Betas:       claude-code/src/constants/betas.ts
//                  claude-code/src/utils/betas.ts (getAllModelBetas)
// ---------------------------------------------------------------------------

const (
	// ccVersion is the Claude Code CLI version embedded in User-Agent.
	ccVersion = "2.1.88"

	// ccSDKVersion is the @anthropic-ai/sdk package version for X-Stainless-Package-Version.
	ccSDKVersion = "0.74.0"

	// ccAnthropicVersion is the Anthropic API version header.
	ccAnthropicVersion = "2023-06-01"

	// ccNodeVersion is the Node.js version reported in X-Stainless-Runtime-Version.
	ccNodeVersion = "v22.22.0"
)

// Claude Code beta header constants — each maps to a constant in betas.ts.
const (
	betaClaudeCode        = "claude-code-20250219"
	betaOAuth             = "oauth-2025-04-20"
	betaContext1M         = "context-1m-2025-08-07"
	betaInterleavedThink  = "interleaved-thinking-2025-05-14"
	betaRedactThinking    = "redact-thinking-2026-02-12"
	betaContextManagement = "context-management-2025-06-27"
	betaEffort            = "effort-2025-11-24"
	betaCacheScope        = "prompt-caching-scope-2026-01-05"
	betaFastMode          = "fast-mode-2026-02-01"
	betaStructuredOutputs = "structured-outputs-2025-12-15"
	betaTaskBudgets       = "task-budgets-2026-03-13"
)

// ccUserAgent returns the User-Agent string matching Claude Code's format.
func ccUserAgent() string {
	return "claude-cli/" + ccVersion + " (external, cli)"
}

// ccBetaHeader builds the anthropic-beta header value that Claude Code would
// send for the given request context. The logic mirrors getAllModelBetas() in
// claude-code/src/utils/betas.ts for an external, first-party user.
func ccBetaHeader(model string, isOAuth bool, is1MContext bool, isFastMode bool) string {
	modelLower := strings.ToLower(model)
	isClaude3 := strings.Contains(modelLower, "claude-3-")

	betas := make([]string, 0, 12)

	// claude-code beta: always present for proxied requests (agentic queries).
	// CC skips this for non-agentic haiku calls (compaction, classifiers) but
	// the proxy only handles main-thread agentic queries, so always include it.
	betas = append(betas, betaClaudeCode)

	// OAuth beta: for subscriber (OAuth) accounts
	if isOAuth {
		betas = append(betas, betaOAuth)
	}

	// 1M context beta: only for models requesting extended context
	if is1MContext {
		betas = append(betas, betaContext1M)
	}

	// Interleaved thinking: all non-claude-3 models on first-party
	if !isClaude3 {
		betas = append(betas, betaInterleavedThink)
	}

	// Redact thinking: first-party, non-claude-3, interactive sessions
	if !isClaude3 {
		betas = append(betas, betaRedactThinking)
	}

	// Context management: non-claude-3 models
	if !isClaude3 {
		betas = append(betas, betaContextManagement)
	}

	// Structured outputs: non-claude-3 models (Sonnet 4.5+, Opus 4.1+, Haiku 4.5)
	// CC enables this when the model supports it and strict tools experiment is on.
	// We include it unconditionally for non-claude-3 since the API ignores it
	// when not relevant, and real CC sessions nearly always have it.
	if !isClaude3 {
		betas = append(betas, betaStructuredOutputs)
	}

	// Effort: always for first-party
	betas = append(betas, betaEffort)

	// Prompt caching scope: always for first-party
	betas = append(betas, betaCacheScope)

	// Fast mode: only when the request actually uses fast mode
	if isFastMode {
		betas = append(betas, betaFastMode)
	}

	return strings.Join(betas, ",")
}

// ccStainlessHeaders sets the X-Stainless-* SDK fingerprint headers on a request.
// These are injected by the Anthropic JS SDK and expected by the API.
func ccStainlessHeaders(set func(key, value string)) {
	set("X-Stainless-Lang", "js")
	set("X-Stainless-Runtime", "node")
	set("X-Stainless-Runtime-Version", ccNodeVersion)
	set("X-Stainless-Arch", "arm64")
	set("X-Stainless-Os", "Linux")
	set("X-Stainless-Package-Version", ccSDKVersion)
	set("X-Stainless-Retry-Count", "0")
	set("X-Stainless-Timeout", "600")
	set("X-Stainless-Helper-Method", "stream")
}

// ccMinimalBetaHeader returns a compact beta header suitable for non-model
// endpoints (usage polling, profile fetches) that only need auth betas.
func ccMinimalBetaHeader() string {
	return betaClaudeCode + "," + betaOAuth + "," + betaInterleavedThink + "," + betaContextManagement
}

// ccAttributionHeader builds the x-anthropic-billing-header that Claude Code
// prepends as the first system prompt block. The fingerprint is a short hash
// derived from the system prompt content + version, matching CC's behavior.
// See claude-code/src/constants/system.ts getAttributionHeader().
func ccAttributionHeader(systemText string) string {
	// CC computes a fingerprint from message chars + version. We approximate
	// with a truncated SHA-256 of whatever system text the client sent.
	h := sha256.Sum256([]byte(systemText + ccVersion))
	fp := hex.EncodeToString(h[:4])
	return "x-anthropic-billing-header: cc_version=" + ccVersion + "." + fp + "; cc_entrypoint=cli;"
}

// ccSystemPrefix is the default Claude Code identity prefix.
const ccSystemPrefix = "You are Claude Code, Anthropic's official CLI for Claude."

// ccInjectSystemBlocks converts the translated request body's "system" field
// into the block-array format that real Claude Code sends, prepending the
// attribution header and CC identity prefix. If the body already has a
// block-array system, it prepends to it. Modifies bodyObj in-place and
// returns the re-marshaled body bytes.
func ccInjectSystemBlocks(bodyObj map[string]any, bodyBytes []byte) []byte {
	// Build the system text for fingerprinting
	existingSystem := ""
	var existingBlocks []any

	switch sys := bodyObj["system"].(type) {
	case string:
		existingSystem = sys
	case []any:
		// Already block format — extract text for fingerprinting, keep blocks
		existingBlocks = sys
		for _, b := range sys {
			if block, ok := b.(map[string]any); ok {
				if t, ok := block["text"].(string); ok {
					existingSystem += t + "\n"
				}
			}
		}
	}

	// Build fingerprint from all system content
	allText := ccSystemPrefix + "\n" + existingSystem
	attrHeader := ccAttributionHeader(allText)

	// Construct the block array matching Claude Code's format:
	//   [attribution (no cache), prefix (cached), ...rest (cached)]
	blocks := []any{
		map[string]any{"type": "text", "text": attrHeader},
		map[string]any{"type": "text", "text": ccSystemPrefix, "cache_control": map[string]any{"type": "ephemeral"}},
	}

	if existingBlocks != nil {
		// Existing block array — append as-is
		blocks = append(blocks, existingBlocks...)
	} else if existingSystem != "" {
		// Plain string — wrap in a cached text block
		blocks = append(blocks, map[string]any{
			"type":          "text",
			"text":          existingSystem,
			"cache_control": map[string]any{"type": "ephemeral"},
		})
	}

	bodyObj["system"] = blocks
	out, err := json.Marshal(bodyObj)
	if err != nil {
		return bodyBytes // fallback to original on marshal error
	}
	return out
}

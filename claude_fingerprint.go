package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"github.com/OneOfOne/xxhash"
	"github.com/google/uuid"
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
	// ccVersion is the internal Claude Code version embedded in User-Agent.
	ccVersion = "2.1.87"

	// ccSDKVersion is the @anthropic-ai/sdk package version for X-Stainless-Package-Version.
	ccSDKVersion = "0.80.0"

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

var (
	ccSessionID = uuid.NewString()
	ccDeviceID  = uuid.NewString()
	ccMetaMu    sync.Mutex
)

// ccUserAgent returns the User-Agent string matching Claude Code's format.
func ccUserAgent() string {
	return "claude-cli/" + ccVersion + " (external, cli)"
}

func ccClaudeCodeUserAgent() string {
	return "claude-code/" + ccVersion
}

func ccCanonicalClaudeModel(model string) string {
	modelLower := strings.ToLower(strings.TrimSpace(model))
	modelLower = strings.ReplaceAll(modelLower, "[1m]", "")
	return strings.TrimSpace(modelLower)
}

func ccModelSupportsISP(model string) bool {
	return !strings.Contains(ccCanonicalClaudeModel(model), "claude-3-")
}

func ccModelSupportsContextManagement(model string) bool {
	return !strings.Contains(ccCanonicalClaudeModel(model), "claude-3-")
}

func ccModelSupportsEffort(model string) bool {
	m := ccCanonicalClaudeModel(model)
	return strings.Contains(m, "opus-4-6") || strings.Contains(m, "sonnet-4-6")
}

func ccModelSupportsStructuredOutputs(model string) bool {
	m := ccCanonicalClaudeModel(model)
	return strings.Contains(m, "claude-sonnet-4-6") ||
		strings.Contains(m, "claude-sonnet-4-5") ||
		strings.Contains(m, "claude-opus-4-1") ||
		strings.Contains(m, "claude-opus-4-5") ||
		strings.Contains(m, "claude-opus-4-6") ||
		strings.Contains(m, "claude-haiku-4-5")
}

func ccRequestHasStructuredOutputs(bodyObj map[string]any) bool {
	if bodyObj == nil {
		return false
	}
	if outputConfig, ok := bodyObj["output_config"].(map[string]any); ok {
		_, hasFormat := outputConfig["format"]
		return hasFormat
	}
	_, hasTopLevelOutputFormat := bodyObj["output_format"]
	return hasTopLevelOutputFormat
}

func ccRequestHasTaskBudget(bodyObj map[string]any) bool {
	if bodyObj == nil {
		return false
	}
	if outputConfig, ok := bodyObj["output_config"].(map[string]any); ok {
		_, hasTaskBudget := outputConfig["task_budget"]
		return hasTaskBudget
	}
	return false
}

func ccSessionHeader() string {
	return ccSessionID
}

func ccInjectMetadata(bodyObj map[string]any, accountUUID string) {
	if bodyObj == nil {
		return
	}
	if _, exists := bodyObj["metadata"]; exists {
		return
	}

	ccMetaMu.Lock()
	defer ccMetaMu.Unlock()

	payload := map[string]string{
		"device_id":    ccDeviceID,
		"account_uuid": accountUUID,
		"session_id":   ccSessionID,
	}
	userID, err := json.Marshal(payload)
	if err != nil {
		return
	}
	bodyObj["metadata"] = map[string]any{
		"user_id": string(userID),
	}
}

// ccBetaHeader builds the anthropic-beta header value that Claude Code would
// send for the given request context. The logic mirrors the external 1P path in
// free-code's getAllModelBetas(), plus per-request additions for output config.
func ccBetaHeader(model string, isOAuth bool, is1MContext bool, isFastMode bool, hasStructuredOutputs bool, hasTaskBudget bool) string {
	betas := make([]string, 0, 10)

	// Agentic queries always include claude-code beta, including Haiku.
	betas = append(betas, betaClaudeCode)

	if isOAuth {
		betas = append(betas, betaOAuth)
	}
	if is1MContext {
		betas = append(betas, betaContext1M)
	}
	if ccModelSupportsISP(model) {
		betas = append(betas, betaInterleavedThink)
	}
	if ccModelSupportsContextManagement(model) {
		betas = append(betas, betaContextManagement)
	}
	if ccModelSupportsEffort(model) {
		betas = append(betas, betaEffort)
	}
	if hasStructuredOutputs && ccModelSupportsStructuredOutputs(model) {
		betas = append(betas, betaStructuredOutputs)
	}
	if hasTaskBudget {
		betas = append(betas, betaTaskBudgets)
	}
	betas = append(betas, betaCacheScope)
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

// ccMinimalBetaHeader returns the compact beta header used by Claude Code's
// lightweight OAuth endpoints.
func ccMinimalBetaHeader() string {
	return betaOAuth
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
	return "x-anthropic-billing-header: cc_version=" + ccVersion + "." + fp + "; cc_entrypoint=cli; cch=00000;"
}

const ccCCHSeed uint64 = 0x6E52736AC806831E
const ccCCHMask uint64 = 0xFFFFF

func ccReplaceCCHPlaceholder(body []byte) []byte {
	const placeholder = "cch=00000"
	idx := bytes.Index(body, []byte(placeholder))
	if idx < 0 {
		return body
	}
	cch := fmt.Sprintf("%05x", xxhash.Checksum64S(body, ccCCHSeed)&ccCCHMask)
	out := make([]byte, 0, len(body))
	out = append(out, body[:idx]...)
	out = append(out, []byte("cch="+cch)...)
	out = append(out, body[idx+len(placeholder):]...)
	return out
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

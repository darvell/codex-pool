package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"sort"
	"strings"
)

func transformClaudeSDKRequest(body []byte) ([]byte, map[string]string) {
	if len(body) == 0 {
		return body, nil
	}
	var obj map[string]any
	if err := json.Unmarshal(body, &obj); err != nil {
		return body, nil
	}

	moveNonCoreSystemToFirstUser(obj)
	mapper := obfuscateClaudeToolNames(obj)
	ccInjectMetadata(obj, "")
	out := ccInjectSystemBlocks(obj, body)
	out = ccReplaceCCHPlaceholder(out)
	return out, mapper
}

func moveNonCoreSystemToFirstUser(obj map[string]any) {
	var moved []string
	switch sys := obj["system"].(type) {
	case string:
		if strings.TrimSpace(sys) != "" && !isCoreClaudeSystemText(sys) {
			moved = append(moved, sys)
		}
		delete(obj, "system")
	case []any:
		kept := make([]any, 0, len(sys))
		for _, raw := range sys {
			block, ok := raw.(map[string]any)
			if !ok {
				kept = append(kept, raw)
				continue
			}
			text, _ := block["text"].(string)
			if text == "" || isCoreClaudeSystemText(text) {
				kept = append(kept, raw)
				continue
			}
			moved = append(moved, text)
		}
		if len(kept) > 0 {
			obj["system"] = kept
		} else {
			delete(obj, "system")
		}
	}
	if len(moved) == 0 {
		return
	}
	prependTextToFirstUser(obj, strings.Join(moved, "\n\n"))
}

func isCoreClaudeSystemText(text string) bool {
	return strings.HasPrefix(text, "x-anthropic-billing-header:") || strings.Contains(text, ccSystemPrefix)
}

func prependTextToFirstUser(obj map[string]any, prefix string) {
	messages, ok := obj["messages"].([]any)
	if !ok || prefix == "" {
		return
	}
	for _, raw := range messages {
		msg, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		role, _ := msg["role"].(string)
		if role != "user" {
			continue
		}
		switch content := msg["content"].(type) {
		case string:
			if content == "" {
				msg["content"] = prefix
			} else {
				msg["content"] = prefix + "\n\n" + content
			}
		case []any:
			block := map[string]any{"type": "text", "text": prefix}
			msg["content"] = append([]any{block}, content...)
		default:
			msg["content"] = prefix
		}
		return
	}
}

func obfuscateClaudeToolNames(obj map[string]any) map[string]string {
	originalToObfuscated := map[string]string{}
	obfuscatedToOriginal := map[string]string{}
	obfuscate := func(name string) string {
		if name == "" {
			return name
		}
		if existing := originalToObfuscated[name]; existing != "" {
			return existing
		}
		for salt := 0; ; salt++ {
			candidate := hashedClaudeToolName(name, salt)
			if existing, used := obfuscatedToOriginal[candidate]; !used || existing == name {
				originalToObfuscated[name] = candidate
				obfuscatedToOriginal[candidate] = name
				return candidate
			}
		}
	}

	if tools, ok := obj["tools"].([]any); ok {
		for _, raw := range tools {
			tool, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			if name, _ := tool["name"].(string); name != "" {
				tool["name"] = obfuscate(name)
			}
		}
	}
	if choice, ok := obj["tool_choice"].(map[string]any); ok {
		if name, _ := choice["name"].(string); name != "" {
			choice["name"] = obfuscate(name)
		}
	}
	if messages, ok := obj["messages"].([]any); ok {
		for _, rawMsg := range messages {
			msg, ok := rawMsg.(map[string]any)
			if !ok {
				continue
			}
			blocks, ok := msg["content"].([]any)
			if !ok {
				continue
			}
			for _, rawBlock := range blocks {
				block, ok := rawBlock.(map[string]any)
				if !ok {
					continue
				}
				if typ, _ := block["type"].(string); typ != "tool_use" {
					continue
				}
				if name, _ := block["name"].(string); name != "" {
					block["name"] = obfuscate(name)
				}
			}
		}
	}
	repairClaudeToolPairs(obj)
	if len(obfuscatedToOriginal) == 0 {
		return nil
	}
	return obfuscatedToOriginal
}

func hashedClaudeToolName(name string, salt int) string {
	h := sha256.New()
	h.Write([]byte(name))
	h.Write([]byte{0})
	h.Write([]byte{byte(salt >> 24), byte(salt >> 16), byte(salt >> 8), byte(salt)})
	sum := hex.EncodeToString(h.Sum(nil))
	return "t_" + sum[:8]
}

func repairClaudeToolPairs(obj map[string]any) {
	messages, ok := obj["messages"].([]any)
	if !ok {
		return
	}
	toolUseIDs := map[string]bool{}
	toolResultIDs := map[string]bool{}
	for _, rawMsg := range messages {
		msg, ok := rawMsg.(map[string]any)
		if !ok {
			continue
		}
		blocks, ok := msg["content"].([]any)
		if !ok {
			continue
		}
		for _, rawBlock := range blocks {
			block, ok := rawBlock.(map[string]any)
			if !ok {
				continue
			}
			typ, _ := block["type"].(string)
			switch typ {
			case "tool_use":
				if id, _ := block["id"].(string); id != "" {
					toolUseIDs[id] = true
				}
			case "tool_result":
				if id, _ := block["tool_use_id"].(string); id != "" {
					toolResultIDs[id] = true
				}
			}
		}
	}
	if len(toolUseIDs) == 0 && len(toolResultIDs) == 0 {
		return
	}
	orphanUse := map[string]bool{}
	orphanResult := map[string]bool{}
	for id := range toolUseIDs {
		if !toolResultIDs[id] {
			orphanUse[id] = true
		}
	}
	for id := range toolResultIDs {
		if !toolUseIDs[id] {
			orphanResult[id] = true
		}
	}
	if len(orphanUse) == 0 && len(orphanResult) == 0 {
		return
	}
	filteredMessages := messages[:0]
	for _, rawMsg := range messages {
		msg, ok := rawMsg.(map[string]any)
		if !ok {
			filteredMessages = append(filteredMessages, rawMsg)
			continue
		}
		blocks, ok := msg["content"].([]any)
		if !ok {
			filteredMessages = append(filteredMessages, rawMsg)
			continue
		}
		kept := blocks[:0]
		for _, rawBlock := range blocks {
			block, ok := rawBlock.(map[string]any)
			if !ok {
				kept = append(kept, rawBlock)
				continue
			}
			if id, _ := block["id"].(string); id != "" && orphanUse[id] {
				continue
			}
			if id, _ := block["tool_use_id"].(string); id != "" && orphanResult[id] {
				continue
			}
			kept = append(kept, rawBlock)
		}
		if len(kept) == 0 {
			continue
		}
		msg["content"] = kept
		filteredMessages = append(filteredMessages, msg)
	}
	obj["messages"] = filteredMessages
}

type claudeToolNameReadCloser struct {
	body         io.ReadCloser
	replacements []string
	needles      []string
	pending      []byte
	carry        []byte
	readErr      error
}

func newClaudeToolNameReadCloser(body io.ReadCloser, mapper map[string]string) io.ReadCloser {
	if len(mapper) == 0 {
		return body
	}
	keys := make([]string, 0, len(mapper))
	for k := range mapper {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return len(keys[i]) > len(keys[j]) })
	replacements := make([]string, 0, len(keys)*2)
	for _, key := range keys {
		replacements = append(replacements, key, mapper[key])
	}
	return &claudeToolNameReadCloser{body: body, replacements: replacements, needles: keys}
}

func (r *claudeToolNameReadCloser) Read(p []byte) (int, error) {
	if len(r.pending) == 0 {
		r.fillPending()
	}
	if len(r.pending) == 0 {
		return 0, r.readErr
	}
	n := copy(p, r.pending)
	r.pending = r.pending[n:]
	if len(r.pending) == 0 && r.readErr != nil {
		return n, r.readErr
	}
	return n, nil
}

func (r *claudeToolNameReadCloser) fillPending() {
	if r.readErr != nil {
		return
	}
	buf := make([]byte, 4096)
	for len(r.pending) == 0 && r.readErr == nil {
		n, err := r.body.Read(buf)
		if n > 0 {
			chunk := append(r.carry, buf[:n]...)
			r.carry = nil
			if err == nil {
				keep := r.trailingNeedlePrefixLen(chunk)
				if keep > 0 {
					r.carry = append(r.carry, chunk[len(chunk)-keep:]...)
					chunk = chunk[:len(chunk)-keep]
				}
			}
			if len(chunk) > 0 {
				r.pending = []byte(strings.NewReplacer(r.replacements...).Replace(string(chunk)))
			}
		}
		if err != nil {
			if len(r.carry) > 0 {
				r.pending = append(r.pending, []byte(strings.NewReplacer(r.replacements...).Replace(string(r.carry)))...)
				r.carry = nil
			}
			r.readErr = err
		}
	}
}

func (r *claudeToolNameReadCloser) trailingNeedlePrefixLen(chunk []byte) int {
	text := string(chunk)
	best := 0
	for _, needle := range r.needles {
		maxLen := len(needle) - 1
		if maxLen > len(text) {
			maxLen = len(text)
		}
		for n := maxLen; n > best; n-- {
			if strings.HasSuffix(text, needle[:n]) {
				best = n
				break
			}
		}
	}
	return best
}

func (r *claudeToolNameReadCloser) Close() error {
	return r.body.Close()
}

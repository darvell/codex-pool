package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
)

// Mistral emits structured thinking blocks inside Chat Completions deltas.
// OpenAI clients treat delta.content as a string; handing them a block object
// renders literal "[object Object]". Surface text as content and nested
// reasoning text as reasoning_content; discard provider-specific metadata.
func normalizeMistralChunk(data []byte) []byte {
	var chunk map[string]any
	if json.Unmarshal(data, &chunk) != nil {
		return data
	}
	choices, _ := chunk["choices"].([]any)
	changed := false
	for _, raw := range choices {
		choice, _ := raw.(map[string]any)
		delta, _ := choice["delta"].(map[string]any)
		blocks, ok := delta["content"].([]any)
		if !ok {
			continue
		}
		var text, thinking bytes.Buffer
		for _, rawBlock := range blocks {
			block, _ := rawBlock.(map[string]any)
			switch block["type"] {
			case "text":
				if value, ok := block["text"].(string); ok {
					text.WriteString(value)
				}
			case "thinking":
				thinking.WriteString(mistralThinkingText(block["thinking"]))
			}
		}
		delta["content"] = text.String()
		if thinking.Len() > 0 {
			delta["reasoning_content"] = thinking.String()
		}
		changed = true
	}
	if !changed {
		return data
	}
	out, err := json.Marshal(chunk)
	if err != nil {
		return data
	}
	return out
}

// Mistral nests reasoning under thinking:[{type:"text",text:"..."}].
func mistralThinkingText(value any) string {
	if text, ok := value.(string); ok {
		return text
	}
	items, ok := value.([]any)
	if !ok {
		return ""
	}
	var out bytes.Buffer
	for _, item := range items {
		block, _ := item.(map[string]any)
		if block["type"] == "text" {
			if text, ok := block["text"].(string); ok {
				out.WriteString(text)
			}
		}
	}
	return out.String()
}

type mistralSSEWriter struct {
	w      io.Writer
	framer sseFramer
	buf    []byte
	err    error
}

func (mw *mistralSSEWriter) Write(p []byte) (int, error) {
	if mw.err != nil {
		return 0, mw.err
	}
	mw.buf = append(mw.buf, p...)
	for {
		event, advance, ok := mw.framer.next(mw.buf)
		if !ok {
			break
		}
		mw.buf = mw.buf[advance:]
		eventType, data := parseSSEEvent(event)
		if len(data) == 0 || bytes.Equal(data, []byte("[DONE]")) {
			writeSSE(mw.w, event, &mw.err)
		} else {
			var output bytes.Buffer
			if eventType != "" {
				fmt.Fprintf(&output, "event: %s\n", eventType)
			}
			fmt.Fprintf(&output, "data: %s\n\n", normalizeMistralChunk(data))
			writeSSE(mw.w, output.Bytes(), &mw.err)
		}
		if mw.err != nil {
			return len(p), mw.err
		}
	}
	if len(mw.buf) > sseInterceptMaxBufferedBytes {
		mw.err = fmt.Errorf("Mistral SSE event exceeded %d bytes", sseInterceptMaxBufferedBytes)
		return len(p), mw.err
	}
	return len(p), nil
}

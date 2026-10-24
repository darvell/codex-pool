package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/google/uuid"
)

const chatGPTEventLimit = 4 << 20

func translateChatGPTRequest(body []byte, model, parentID string) ([]byte, error) {
	var req map[string]any
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, errors.New("invalid Responses request")
	}
	if model == "" || parentID == "" {
		return nil, errors.New("model and parent message ID required")
	}
	if v, ok := req["previous_response_id"]; ok && v != nil && v != "" {
		return nil, errors.New("previous_response_id requires explicit history")
	}
	signatures := []any{}
	names := []string{}
	known := map[string]bool{}
	custom := map[string]bool{}
	if raw, exists := req["tools"]; exists {
		tools, ok := raw.([]any)
		if !ok {
			return nil, errors.New("tools must be an array")
		}
		for _, rawTool := range tools {
			tool, ok := rawTool.(map[string]any)
			if !ok || (tool["type"] != "function" && tool["type"] != "custom") {
				return nil, errors.New("only function and custom tools are supported")
			}
			name, _ := tool["name"].(string)
			if name == "" || strings.ContainsAny(name, ". /\t\n") || known[name] {
				return nil, errors.New("invalid or duplicate function name")
			}
			description, _ := tool["description"].(string)
			isCustom := tool["type"] == "custom"
			schema, ok := tool["parameters"].(map[string]any)
			if isCustom {
				if raw, exists := tool["format"]; exists {
					format, valid := raw.(map[string]any)
					if !valid {
						return nil, errors.New("invalid custom tool format")
					}
					switch format["type"] {
					case "text":
					case "grammar":
						definition, valid := format["definition"].(string)
						syntax, _ := format["syntax"].(string)
						if !valid || definition == "" || (syntax != "lark" && syntax != "regex") {
							return nil, errors.New("invalid custom tool grammar")
						}
						description += "\n\nThe input string must follow this " + syntax + " grammar:\n" + definition
					default:
						return nil, errors.New("unsupported custom tool format")
					}
				}
				schema = map[string]any{"type": "object", "properties": map[string]any{"input": map[string]any{"type": "string"}}, "required": []any{"input"}, "additionalProperties": false}
				ok = true
			}
			if !ok || schema["type"] != "object" {
				return nil, errors.New("function parameters must be an object schema")
			}
			for key := range schema {
				if key != "type" && key != "properties" && key != "required" && key != "additionalProperties" {
					return nil, errors.New("unsupported root function schema constraint")
				}
			}
			if v, ok := schema["additionalProperties"]; ok && v != false {
				return nil, errors.New("additional function properties are unsupported")
			}
			props, ok := schema["properties"].(map[string]any)
			if !ok {
				return nil, errors.New("function schema properties required")
			}
			required := map[string]bool{}
			if raw, exists := schema["required"]; exists {
				list, ok := raw.([]any)
				if !ok {
					return nil, errors.New("invalid required properties")
				}
				for _, v := range list {
					key, ok := v.(string)
					if !ok || props[key] == nil || required[key] {
						return nil, errors.New("required property missing or duplicated")
					}
					required[key] = true
				}
			}
			params := []any{}
			// JSON property order is not semantic; sort to make the native signature deterministic.
			keys := make([]string, 0, len(props))
			for key := range props {
				keys = append(keys, key)
			}
			sort.Strings(keys)
			for _, key := range keys {
				typ, ok := props[key].(map[string]any)
				if !ok {
					return nil, errors.New("parameter type must be a schema object")
				}
				params = append(params, map[string]any{"name": key, "required": required[key], "type": typ})
			}
			signatures = append(signatures, map[string]any{"name": name, "description": description, "params": params, "type": "kwargs"})
			names = append(names, name)
			known[name] = true
			custom[name] = isCustom
		}
	}
	if choice, exists := req["tool_choice"]; exists && choice != "auto" {
		if choice != "none" {
			return nil, errors.New("forced tool choice is unsupported by ChatGPT")
		}
		signatures = []any{}
		names = []string{}
	}
	if v, exists := req["parallel_tool_calls"]; exists && v != true {
		return nil, errors.New("disabling parallel tool calls is unsupported")
	}
	messages := []any{}
	addText := func(role, text string) {
		messages = append(messages, map[string]any{"id": uuid.NewString(), "author": map[string]any{"role": role}, "content": map[string]any{"content_type": "text", "parts": []string{text}}, "metadata": map[string]any{}, "recipient": "all"})
	}
	if raw, exists := req["instructions"]; exists && raw != nil {
		text, ok := raw.(string)
		if !ok {
			return nil, errors.New("instructions must be text")
		}
		if text != "" {
			addText("system", text)
		}
	}
	calls := map[string]string{}
	used := map[string]bool{}
	switch input := req["input"].(type) {
	case string:
		addText("user", input)
	case []any:
		for _, raw := range input {
			item, ok := raw.(map[string]any)
			if !ok {
				return nil, errors.New("invalid input item")
			}
			typ, _ := item["type"].(string)
			switch typ {
			case "reasoning":
				// Encrypted reasoning is opaque state, never user-visible conversation text.
				continue
			case "function_call", "custom_tool_call":
				id, _ := item["call_id"].(string)
				name, _ := item["name"].(string)
				args, _ := item["arguments"].(string)
				if typ == "custom_tool_call" {
					input, ok := item["input"].(string)
					if !ok {
						return nil, errors.New("custom call input must be text")
					}
					encoded, _ := json.Marshal(map[string]any{"input": input})
					args = string(encoded)
				}
				var object map[string]any
				if id == "" || calls[id] != "" || !known[name] || custom[name] != (typ == "custom_tool_call") || json.Unmarshal([]byte(args), &object) != nil || object == nil {
					return nil, errors.New("invalid function call history")
				}
				calls[id] = name
				messages = append(messages, map[string]any{"id": id, "author": map[string]any{"role": "assistant"}, "recipient": "local." + name, "channel": "commentary", "content": map[string]any{"content_type": "code", "text": args}, "status": "finished_successfully", "end_turn": false, "metadata": map[string]any{}})
			case "function_call_output", "custom_tool_call_output":
				id, _ := item["call_id"].(string)
				result, ok := item["output"].(string)
				if !ok || calls[id] == "" || used[id] || custom[calls[id]] != (typ == "custom_tool_call_output") {
					return nil, errors.New("function output requires a matching prior call and text output")
				}
				used[id] = true
				text, _ := json.Marshal(map[string]any{"call_id": id, "result": result, "tool": calls[id]})
				messages = append(messages, map[string]any{"id": uuid.NewString(), "author": map[string]any{"role": "tool", "name": calls[id], "metadata": map[string]any{}}, "channel": "commentary", "content": map[string]any{"content_type": "code", "text": string(text)}, "recipient": "all", "status": "finished_successfully", "end_turn": nil, "metadata": map[string]any{"is_visually_hidden_from_conversation": true}})
			case "", "message":
				role, _ := item["role"].(string)
				if role != "user" && role != "assistant" && role != "system" && role != "developer" {
					return nil, errors.New("unsupported input role")
				}
				text, err := chatGPTInputText(item["content"])
				if err != nil {
					return nil, err
				}
				if role == "developer" {
					role = "system"
				}
				addText(role, text)
			default:
				return nil, errors.New("unsupported Responses input item")
			}
		}
	case nil:
	default:
		return nil, errors.New("input must be text or an array")
	}
	for id := range calls {
		if !used[id] {
			return nil, errors.New("function history contains an unresolved call")
		}
	}
	return json.Marshal(map[string]any{"action": "next", "model": model, "parent_message_id": parentID, "messages": messages, "local_function_signatures": signatures, "local_function_names": names, "history_and_training_disabled": true, "is_do_not_remember": true, "temporary_chat_requests_personalization": false})
}

func chatGPTInputText(raw any) (string, error) {
	if text, ok := raw.(string); ok {
		return text, nil
	}
	parts, ok := raw.([]any)
	if !ok {
		return "", errors.New("message content must be text")
	}
	var b strings.Builder
	for _, raw := range parts {
		part, ok := raw.(map[string]any)
		if !ok || (part["type"] != "input_text" && part["type"] != "output_text") {
			return "", errors.New("unsupported message content")
		}
		text, ok := part["text"].(string)
		if !ok {
			return "", errors.New("content text required")
		}
		b.WriteString(text)
	}
	return b.String(), nil
}

type chatGPTStreamState struct {
	ConversationID string
	LastEventID    string
	Offset         int64
	ResumeToken    string `json:"-"`
	Handoff        bool
	Completed      bool
	Output         []map[string]any
	Response       map[string]any
}

type chatGPTStreamItem struct {
	id, name, text, channel     string
	index                       int
	tool, custom, done, endTurn bool
	input                       string
}

type chatGPTStream struct {
	responseID, model string
	emit              func(map[string]any) error
	pending           []byte
	data              []string
	event             string
	eventBytes        int
	started, ended    bool
	err               error
	state             chatGPTStreamState
	items             []*chatGPTStreamItem
	byID              map[string]*chatGPTStreamItem
	sequence          int
	tools             map[string]bool
}

func newChatGPTStream(responseID, model string, emit func(map[string]any) error, definitions ...map[string]bool) *chatGPTStream {
	tools := map[string]bool{}
	if len(definitions) > 0 {
		for name, custom := range definitions[0] {
			tools[name] = custom
		}
	}
	return &chatGPTStream{responseID: responseID, model: model, emit: emit, byID: map[string]*chatGPTStreamItem{}, tools: tools}
}

func (s *chatGPTStream) send(kind string, fields map[string]any) error {
	fields["type"] = kind
	fields["sequence_number"] = s.sequence
	s.sequence++
	if s.emit == nil {
		return nil
	}
	return s.emit(fields)
}
func (s *chatGPTStream) response(status string) map[string]any {
	output := []map[string]any{}
	for _, item := range s.items {
		output = append(output, s.output(item))
	}
	return map[string]any{"id": s.responseID, "object": "response", "model": s.model, "status": status, "output": output, "error": nil, "incomplete_details": nil}
}
func (s *chatGPTStream) output(item *chatGPTStreamItem) map[string]any {
	status := "in_progress"
	if item.done {
		status = "completed"
	}
	if item.custom {
		return map[string]any{"id": "ct_" + item.id, "type": "custom_tool_call", "call_id": item.id, "name": item.name, "input": item.input, "status": status}
	}
	if item.tool {
		return map[string]any{"id": "fc_" + item.id, "type": "function_call", "call_id": item.id, "name": item.name, "arguments": item.text, "status": status}
	}
	return map[string]any{"id": "msg_" + item.id, "type": "message", "role": "assistant", "status": status, "content": []any{map[string]any{"type": "output_text", "text": item.text, "annotations": []any{}}}}
}
func (s *chatGPTStream) start() error {
	if s.started {
		return nil
	}
	s.started = true
	if err := s.send("response.created", map[string]any{"response": s.response("in_progress")}); err != nil {
		return err
	}
	return s.send("response.in_progress", map[string]any{"response": s.response("in_progress")})
}

// Feed accepts arbitrary transport chunks, including split UTF-8 and CRLF boundaries.
func (s *chatGPTStream) Feed(chunk []byte) error {
	if s.err != nil {
		return s.err
	}
	for len(chunk) > 0 {
		n := bytes.IndexByte(chunk, '\n')
		if n < 0 {
			n = len(chunk)
		} else {
			n++
		}
		if len(s.pending)+n+s.eventBytes > chatGPTEventLimit {
			s.err = errors.New("ChatGPT SSE event exceeds limit")
			return s.err
		}
		s.pending = append(s.pending, chunk[:n]...)
		chunk = chunk[n:]
		if len(s.pending) == 0 || s.pending[len(s.pending)-1] != '\n' {
			continue
		}
		line := strings.TrimSuffix(strings.TrimSuffix(string(s.pending), "\n"), "\r")
		s.pending = nil
		if err := s.line(line); err != nil {
			s.err = err
			return err
		}
	}
	return nil
}
func (s *chatGPTStream) line(line string) error {
	if line == "" {
		data, event := strings.Join(s.data, "\n"), s.event
		s.data = nil
		s.event = ""
		s.eventBytes = 0
		if data == "" && event == "" {
			return nil
		}
		return s.frame(event, data)
	}
	s.eventBytes += len(line) + 1
	if strings.HasPrefix(line, ":") {
		return nil
	}
	key, value, ok := strings.Cut(line, ":")
	if !ok {
		return nil
	}
	value = strings.TrimPrefix(value, " ")
	if key == "data" {
		s.data = append(s.data, value)
	}
	if key == "event" {
		s.event = value
	}
	if key == "id" && !strings.ContainsRune(value, '\x00') {
		s.state.LastEventID = value
		if offset, err := strconv.ParseInt(value, 10, 64); err == nil && offset >= 0 {
			s.state.Offset = offset
		}
	}
	return nil
}
func (s *chatGPTStream) frame(event, data string) error {
	if s.ended {
		return errors.New("ChatGPT stream contains data after completion")
	}
	if data == "[DONE]" {
		s.ended = true
		return s.complete()
	}
	var frame map[string]any
	if data != "" {
		if json.Unmarshal([]byte(data), &frame) != nil {
			return errors.New("invalid ChatGPT SSE JSON")
		}
	}
	typ, _ := frame["type"].(string)
	if event == "error" || typ == "error" || frame["error"] != nil {
		return errors.New("ChatGPT upstream stream error")
	}
	if event == "delta" || event == "delta_encoding" || typ == "delta" || typ == "delta_encoding" || frame["delta_encoding"] != nil {
		return errors.New("ChatGPT delta encoding is unsupported")
	}
	if token, ok := frame["resume_conversation_token"].(string); ok {
		s.state.ResumeToken = token
	}
	if typ == "resume_conversation_token" || event == "resume_conversation_token" {
		if token, ok := frame["token"].(string); ok {
			s.state.ResumeToken = token
		}
	}
	if id, ok := frame["conversation_id"].(string); ok {
		if s.state.ConversationID != "" && s.state.ConversationID != id {
			return errors.New("ChatGPT conversation ID changed")
		}
		s.state.ConversationID = id
	}
	if event == "async_stream_handoff" || typ == "async_stream_handoff" || event == "stream_handoff" || typ == "stream_handoff" {
		s.state.Handoff = true
		return nil
	}
	message, ok := frame["message"].(map[string]any)
	if !ok {
		return nil
	}
	author, _ := message["author"].(map[string]any)
	if author["role"] != "assistant" {
		return nil
	}
	metadata, _ := message["metadata"].(map[string]any)
	if metadata["is_visually_hidden_from_conversation"] == true {
		return nil
	}
	channel, _ := message["channel"].(string)
	if channel == "analysis" {
		return nil
	}
	recipient := "all"
	if raw := message["recipient"]; raw != nil {
		var ok bool
		recipient, ok = raw.(string)
		if !ok {
			return errors.New("invalid ChatGPT recipient")
		}
	}
	tool := strings.HasPrefix(recipient, "local.") || strings.HasPrefix(recipient, "functions.") || strings.HasPrefix(recipient, "function.")
	if !tool && recipient != "all" {
		return errors.New("ChatGPT called an unsupported recipient")
	}
	if !tool && channel != "final" && channel != "commentary" && channel != "" {
		return nil
	}
	id, _ := message["id"].(string)
	if id == "" {
		return errors.New("ChatGPT assistant message ID required")
	}
	content, _ := message["content"].(map[string]any)
	text := ""
	switch content["content_type"] {
	case "code":
		var ok bool
		text, ok = content["text"].(string)
		if !ok {
			return errors.New("invalid ChatGPT code content")
		}
	case "text":
		parts, ok := content["parts"].([]any)
		if !ok {
			return errors.New("invalid ChatGPT text parts")
		}
		for _, part := range parts {
			value, ok := part.(string)
			if !ok {
				return errors.New("unsupported ChatGPT output content")
			}
			text += value
		}
	default:
		return errors.New("unsupported ChatGPT output content")
	}
	status, _ := message["status"].(string)
	if status != "in_progress" && status != "finished_successfully" {
		return errors.New("ChatGPT message did not finish successfully")
	}
	name := ""
	if tool {
		_, name, _ = strings.Cut(recipient, ".")
		if _, declared := s.tools[name]; !declared {
			return errors.New("ChatGPT called an undeclared tool")
		}
		if content["content_type"] != "code" {
			return errors.New("ChatGPT tool arguments must be code content")
		}
	}
	item := s.byID[id]
	if item != nil && (item.tool != tool || item.name != name || item.channel != channel || !strings.HasPrefix(text, item.text) || (item.done && text != item.text)) {
		return errors.New("ChatGPT rewrote streamed content")
	}
	if err := s.start(); err != nil {
		return err
	}
	if item == nil {
		item = &chatGPTStreamItem{id: id, name: name, channel: channel, index: len(s.items), tool: tool, custom: tool && s.tools[name]}
		s.items = append(s.items, item)
		s.byID[id] = item
		added := s.output(item)
		if !tool {
			added["content"] = []any{}
		}
		if err := s.send("response.output_item.added", map[string]any{"output_index": item.index, "item": added}); err != nil {
			return err
		}
		if !tool {
			if err := s.send("response.content_part.added", map[string]any{"output_index": item.index, "item_id": "msg_" + id, "content_index": 0, "part": map[string]any{"type": "output_text", "text": "", "annotations": []any{}}}); err != nil {
				return err
			}
		}
	}
	if item.done {
		return nil
	}
	delta := text[len(item.text):]
	item.text = text
	prefix, kind := "msg_", "response.output_text.delta"
	if tool {
		prefix, kind = "fc_", "response.function_call_arguments.delta"
	}
	if item.custom {
		prefix, kind = "ct_", "response.custom_tool_call_input.delta"
		// Native JSON snapshots may end inside an escape. Publish only validated input,
		// never fragments of the transport wrapper or a syntactically invalid call.
		delta = ""
		if status == "finished_successfully" {
			var args map[string]any
			if json.Unmarshal([]byte(text), &args) != nil || args == nil || len(args) != 1 {
				return errors.New("ChatGPT custom arguments must contain only input")
			}
			input, ok := args["input"].(string)
			if !ok {
				return errors.New("ChatGPT custom input must be a string")
			}
			item.input = input
			delta = input
		}
	}
	fields := map[string]any{"output_index": item.index, "item_id": prefix + id, "delta": delta}
	if !tool {
		fields["content_index"] = 0
	}
	if delta != "" {
		if err := s.send(kind, fields); err != nil {
			return err
		}
	}
	if status != "finished_successfully" {
		return nil
	}
	if tool {
		var args map[string]any
		if json.Unmarshal([]byte(text), &args) != nil || args == nil {
			return errors.New("ChatGPT function arguments are not a JSON object")
		}
	}
	item.done = true
	item.endTurn = message["end_turn"] == true
	done := map[string]any{"output_index": item.index, "item_id": prefix + id}
	if item.custom {
		done["input"] = item.input
		if err := s.send("response.custom_tool_call_input.done", done); err != nil {
			return err
		}
	} else if tool {
		done["arguments"] = text
		if err := s.send("response.function_call_arguments.done", done); err != nil {
			return err
		}
	} else {
		done["text"] = text
		done["content_index"] = 0
		if err := s.send("response.output_text.done", done); err != nil {
			return err
		}
		if err := s.send("response.content_part.done", map[string]any{"output_index": item.index, "item_id": prefix + id, "content_index": 0, "part": map[string]any{"type": "output_text", "text": text, "annotations": []any{}}}); err != nil {
			return err
		}
	}
	return s.send("response.output_item.done", map[string]any{"output_index": item.index, "item": s.output(item)})
}
func (s *chatGPTStream) complete() error {
	if s.state.Handoff {
		return nil
	}
	terminal := false
	for _, item := range s.items {
		if !item.done {
			return errors.New("ChatGPT stream ended with unfinished output")
		}
		if item.tool || (item.endTurn && (item.channel == "final" || item.channel == "")) {
			terminal = true
		}
	}
	if !terminal {
		return errors.New("ChatGPT stream ended without a final answer or tool call")
	}
	if err := s.send("response.completed", map[string]any{"response": s.response("completed")}); err != nil {
		return err
	}
	s.state.Completed = true
	return nil
}

// Resume keeps output IDs, cumulative text, and event sequence across a native handoff.
func (s *chatGPTStream) Resume() error {
	if s.err != nil {
		return s.err
	}
	if !s.ended || !s.state.Handoff || s.state.Completed {
		return errors.New("ChatGPT stream is not awaiting resume")
	}
	s.ended = false
	s.state.Handoff = false
	return nil
}

func (s *chatGPTStream) Finish() (chatGPTStreamState, error) {
	if s.err == nil && len(s.pending) > 0 {
		s.err = s.line(strings.TrimSuffix(string(s.pending), "\r"))
		s.pending = nil
	}
	if s.err == nil && (len(s.data) > 0 || s.event != "") {
		s.err = s.line("")
	}
	status := "in_progress"
	if s.state.Completed {
		status = "completed"
	}
	s.state.Response = s.response(status)
	s.state.Output = []map[string]any{}
	for _, item := range s.items {
		s.state.Output = append(s.state.Output, s.output(item))
	}
	if s.err != nil {
		return s.state, s.err
	}
	if !s.ended {
		return s.state, fmt.Errorf("ChatGPT stream closed before [DONE]")
	}
	return s.state, nil
}

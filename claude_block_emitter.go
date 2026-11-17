package main

import "fmt"

type claudeBlockEmitter struct {
	emit func(string, string)
}

func (e claudeBlockEmitter) messageStart(id, model string, inputTokens int64) {
	if id == "" {
		id = "msg_translated"
	}
	if model == "" {
		model = "unknown"
	}
	e.emit("message_start", fmt.Sprintf(`{"type":"message_start","message":{"id":%s,"type":"message","role":"assistant","model":%s,"content":[],"stop_reason":null,"stop_sequence":null,"usage":{"input_tokens":%d,"output_tokens":0}}}`,
		mustMarshalString(id), mustMarshalString(model), inputTokens))
}

func (e claudeBlockEmitter) textStart(index int) {
	e.start(index, `{"type":"text","text":""}`)
}

func (e claudeBlockEmitter) thinkingStart(index int) {
	e.start(index, `{"type":"thinking","thinking":""}`)
}

func (e claudeBlockEmitter) toolStart(index int, id, name string) {
	e.start(index, fmt.Sprintf(`{"type":"tool_use","id":%s,"name":%s,"input":{}}`, mustMarshalString(id), mustMarshalString(name)))
}

func (e claudeBlockEmitter) start(index int, block string) {
	e.emit("content_block_start", fmt.Sprintf(`{"type":"content_block_start","index":%d,"content_block":%s}`, index, block))
}

func (e claudeBlockEmitter) text(index int, text string) {
	e.delta(index, fmt.Sprintf(`{"type":"text_delta","text":%s}`, mustMarshalString(text)))
}

func (e claudeBlockEmitter) thinking(index int, text string) {
	e.delta(index, fmt.Sprintf(`{"type":"thinking_delta","thinking":%s}`, mustMarshalString(text)))
}

func (e claudeBlockEmitter) arguments(index int, arguments string) {
	e.delta(index, fmt.Sprintf(`{"type":"input_json_delta","partial_json":%s}`, mustMarshalString(arguments)))
}

func (e claudeBlockEmitter) delta(index int, delta string) {
	e.emit("content_block_delta", fmt.Sprintf(`{"type":"content_block_delta","index":%d,"delta":%s}`, index, delta))
}

func (e claudeBlockEmitter) stop(index int) {
	e.emit("content_block_stop", fmt.Sprintf(`{"type":"content_block_stop","index":%d}`, index))
}

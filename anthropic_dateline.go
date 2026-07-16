package main

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

var (
	anthropicDatelineHyphen = regexp.MustCompile(`Today(['’ʼʹ])s date is (\d{4})-(\d{2})-(\d{2})\.`)
	anthropicDatelineSlash  = regexp.MustCompile(`Today(['’ʼʹ])s date is (\d{4})/(\d{2})/(\d{2})\.`)
	anthropicSystemReminder = regexp.MustCompile(`(?s)<system-reminder>.*?</system-reminder>`)
)

type anthropicDatelineHit struct {
	ApostropheVariant string
	DateSeparator     string
}

type anthropicDatelineMatch struct {
	start, end       int
	apostrophe       rune
	separator        string
	year, month, day string
}

func anthropicDatelineMatches(text string, re *regexp.Regexp, separator string) []anthropicDatelineMatch {
	indexes := re.FindAllStringSubmatchIndex(text, -1)
	matches := make([]anthropicDatelineMatch, 0, len(indexes))
	for _, index := range indexes {
		apostrophe, _ := utf8FirstRune(text[index[2]:index[3]])
		matches = append(matches, anthropicDatelineMatch{
			start:      index[0],
			end:        index[1],
			apostrophe: apostrophe,
			separator:  separator,
			year:       text[index[4]:index[5]],
			month:      text[index[6]:index[7]],
			day:        text[index[8]:index[9]],
		})
	}
	return matches
}

func utf8FirstRune(text string) (rune, bool) {
	for _, value := range text {
		return value, true
	}
	return 0, false
}

func anthropicApostropheVariant(value rune) string {
	switch value {
	case '’':
		return "u2019"
	case 'ʼ':
		return "u02bc"
	case 'ʹ':
		return "u02b9"
	default:
		return "ascii"
	}
}

func normalizeAnthropicDatelineText(text string) (string, []anthropicDatelineHit) {
	if !strings.Contains(text, "date is ") {
		return text, nil
	}

	matches := anthropicDatelineMatches(text, anthropicDatelineHyphen, "-")
	matches = append(matches, anthropicDatelineMatches(text, anthropicDatelineSlash, "/")...)
	if len(matches) == 0 {
		return text, nil
	}
	sort.Slice(matches, func(i, j int) bool {
		return matches[i].start < matches[j].start
	})

	var output strings.Builder
	output.Grow(len(text))
	previous := 0
	hits := make([]anthropicDatelineHit, 0, len(matches))
	for _, match := range matches {
		canonical := fmt.Sprintf("Today's date is %s-%s-%s.", match.year, match.month, match.day)
		if text[match.start:match.end] == canonical {
			continue
		}
		_, _ = output.WriteString(text[previous:match.start])
		_, _ = output.WriteString(canonical)
		previous = match.end
		hits = append(hits, anthropicDatelineHit{
			ApostropheVariant: anthropicApostropheVariant(match.apostrophe),
			DateSeparator:     match.separator,
		})
	}
	if len(hits) == 0 {
		return text, nil
	}
	_, _ = output.WriteString(text[previous:])
	return output.String(), hits
}

func normalizeAnthropicSystemReminderText(text string) (string, []anthropicDatelineHit) {
	if !strings.Contains(text, "<system-reminder>") {
		return text, nil
	}

	locations := anthropicSystemReminder.FindAllStringIndex(text, -1)
	if len(locations) == 0 {
		return text, nil
	}

	var output strings.Builder
	output.Grow(len(text))
	previous := 0
	var hits []anthropicDatelineHit
	for _, location := range locations {
		_, _ = output.WriteString(text[previous:location[0]])
		block := text[location[0]:location[1]]
		normalized, blockHits := normalizeAnthropicDatelineText(block)
		_, _ = output.WriteString(normalized)
		hits = append(hits, blockHits...)
		previous = location[1]
	}
	if len(hits) == 0 {
		return text, nil
	}
	_, _ = output.WriteString(text[previous:])
	return output.String(), hits
}

func normalizeAnthropicJSONString(raw json.RawMessage, normalize func(string) (string, []anthropicDatelineHit)) (json.RawMessage, []anthropicDatelineHit, bool) {
	var text string
	if err := json.Unmarshal(raw, &text); err != nil {
		return raw, nil, false
	}
	normalized, hits := normalize(text)
	if len(hits) == 0 {
		return raw, nil, false
	}
	encoded, err := json.Marshal(normalized)
	if err != nil {
		return raw, nil, false
	}
	return encoded, hits, true
}

func normalizeAnthropicBlocks(raw json.RawMessage, normalize func(string) (string, []anthropicDatelineHit)) (json.RawMessage, []anthropicDatelineHit, bool) {
	var blocks []map[string]json.RawMessage
	if err := json.Unmarshal(raw, &blocks); err != nil {
		return raw, nil, false
	}

	var hits []anthropicDatelineHit
	changed := false
	for index := range blocks {
		var blockType string
		if err := json.Unmarshal(blocks[index]["type"], &blockType); err != nil || blockType != "text" {
			continue
		}
		text := blocks[index]["text"]
		if len(text) == 0 {
			continue
		}
		normalized, blockHits, blockChanged := normalizeAnthropicJSONString(text, normalize)
		if blockChanged {
			blocks[index]["text"] = normalized
			hits = append(hits, blockHits...)
			changed = true
		}
	}
	if !changed {
		return raw, nil, false
	}
	encoded, err := json.Marshal(blocks)
	if err != nil {
		return raw, nil, false
	}
	return encoded, hits, true
}

func normalizeAnthropicDateline(body []byte) ([]byte, []anthropicDatelineHit, bool) {
	if len(body) == 0 {
		return body, nil, false
	}

	var request map[string]json.RawMessage
	if err := json.Unmarshal(body, &request); err != nil {
		return body, nil, false
	}

	var hits []anthropicDatelineHit
	changed := false
	system := request["system"]
	if len(system) != 0 {
		normalized, systemHits, systemChanged := normalizeAnthropicJSONString(system, normalizeAnthropicDatelineText)
		if !systemChanged {
			normalized, systemHits, systemChanged = normalizeAnthropicBlocks(system, normalizeAnthropicDatelineText)
		}
		if systemChanged {
			request["system"] = normalized
			hits = append(hits, systemHits...)
			changed = true
		}
	}

	var messages []map[string]json.RawMessage
	if err := json.Unmarshal(request["messages"], &messages); err != nil {
		messages = nil
	}
	messagesChanged := false
	for index := range messages {
		content := messages[index]["content"]
		if len(content) == 0 {
			continue
		}
		normalized, contentHits, contentChanged := normalizeAnthropicJSONString(content, normalizeAnthropicSystemReminderText)
		if !contentChanged {
			normalized, contentHits, contentChanged = normalizeAnthropicBlocks(content, normalizeAnthropicSystemReminderText)
		}
		if contentChanged {
			messages[index]["content"] = normalized
			hits = append(hits, contentHits...)
			changed = true
			messagesChanged = true
		}
	}
	if messagesChanged {
		encoded, err := json.Marshal(messages)
		if err != nil {
			return body, nil, false
		}
		request["messages"] = encoded
	}

	if !changed {
		return body, nil, false
	}
	output, err := json.Marshal(request)
	if err != nil {
		return body, nil, false
	}
	return output, hits, true
}

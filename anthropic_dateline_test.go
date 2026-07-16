package main

import (
	"bytes"
	"testing"
)

func TestNormalizeAnthropicDatelineTextVariants(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		want       string
		apostrophe string
		separator  string
	}{
		{"slash", "Today's date is 2026/07/01.", "Today's date is 2026-07-01.", "ascii", "/"},
		{"u2019", "Today’s date is 2026-07-01.", "Today's date is 2026-07-01.", "u2019", "-"},
		{"u02bc", "Todayʼs date is 2026/07/01.", "Today's date is 2026-07-01.", "u02bc", "/"},
		{"u02b9", "Todayʹs date is 2026/07/01.", "Today's date is 2026-07-01.", "u02b9", "/"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, hits := normalizeAnthropicDatelineText(test.input)
			if got != test.want {
				t.Fatalf("normalizeAnthropicDatelineText() = %q, want %q", got, test.want)
			}
			if len(hits) != 1 || hits[0].ApostropheVariant != test.apostrophe || hits[0].DateSeparator != test.separator {
				t.Fatalf("unexpected hits: %+v", hits)
			}
		})
	}
}

func TestNormalizeAnthropicDatelineTextLeavesCanonicalAndLookalikesAlone(t *testing.T) {
	inputs := []string{
		"Today's date is 2026-07-01.",
		"Today's date is 2026-07/01.",
		"Today is a great day.",
		"His date is 2026/07/01.",
	}
	for _, input := range inputs {
		got, hits := normalizeAnthropicDatelineText(input)
		if got != input || hits != nil {
			t.Fatalf("input %q changed to %q with hits %+v", input, got, hits)
		}
	}
}

func TestNormalizeAnthropicDatelineScopesChanges(t *testing.T) {
	body := []byte(`{
		"system": [
			{"type":"text","text":"Todayʼs date is 2026/07/01."},
			{"type":"custom","text":"Today’s date is 2026/07/01."}
		],
		"messages": [
			{"role":"user","content":"Today’s date is 2026/07/01."},
			{"role":"user","content":"<system-reminder>Today’s date is 2026/07/01.</system-reminder> outside Todayʼs date is 2026/07/01."},
			{"role":"user","content":[
				{"type":"text","text":"<system-reminder>Todayʹs date is 2026/07/01.</system-reminder>"},
				{"type":"tool_result","content":"<system-reminder>Today’s date is 2026/07/01.</system-reminder>"}
			]}
		]
	}`)

	out, hits, changed := normalizeAnthropicDateline(body)
	if !changed {
		t.Fatal("expected a change")
	}
	if len(hits) != 3 {
		t.Fatalf("got %d hits, want 3: %+v", len(hits), hits)
	}
	if bytes.Count(out, []byte("Today's date is 2026-07-01.")) != 3 {
		t.Fatalf("expected three canonical datelines: %s", out)
	}
	if bytes.Count(out, []byte("Today’s date is 2026/07/01.")) != 3 {
		t.Fatalf("out-of-scope U+2019 variants changed: %s", out)
	}
	if bytes.Count(out, []byte("Todayʼs date is 2026/07/01.")) != 1 {
		t.Fatalf("outside-reminder U+02BC variant changed: %s", out)
	}
}

func TestNormalizeAnthropicDatelineTopLevelSystemString(t *testing.T) {
	body := []byte(`{"system":"prefix Today’s date is 2026/07/01. suffix","messages":[]}`)
	out, hits, changed := normalizeAnthropicDateline(body)
	if !changed || len(hits) != 1 {
		t.Fatalf("changed=%v hits=%+v", changed, hits)
	}
	if !bytes.Contains(out, []byte("Today's date is 2026-07-01.")) {
		t.Fatalf("canonical dateline missing: %s", out)
	}
}

func TestNormalizeAnthropicDatelinePreservesUnchangedBytes(t *testing.T) {
	body := []byte("{ \n \"messages\" : [{\"content\":\"Today’s date is 2026/07/01.\"}], \"extra\": 1e3 }\n")
	out, hits, changed := normalizeAnthropicDateline(body)
	if changed || hits != nil {
		t.Fatalf("changed=%v hits=%+v", changed, hits)
	}
	if len(out) != len(body) || &out[0] != &body[0] || !bytes.Equal(out, body) {
		t.Fatal("unchanged input was not returned byte-for-byte")
	}
}

func TestNormalizeAnthropicDatelineInvalidAndEmptyBodies(t *testing.T) {
	invalid := []byte(`{"system":`)
	out, hits, changed := normalizeAnthropicDateline(invalid)
	if changed || hits != nil || !bytes.Equal(out, invalid) {
		t.Fatalf("invalid JSON changed: changed=%v hits=%+v out=%q", changed, hits, out)
	}

	out, hits, changed = normalizeAnthropicDateline(nil)
	if changed || hits != nil || out != nil {
		t.Fatalf("nil body changed: changed=%v hits=%+v out=%q", changed, hits, out)
	}
}

func TestNormalizeAnthropicDatelineIsIdempotent(t *testing.T) {
	body := []byte(`{"messages":[{"content":"<system-reminder>Today’s date is 2026/07/01.</system-reminder>"}]}`)
	first, _, changed := normalizeAnthropicDateline(body)
	if !changed {
		t.Fatal("first pass did not change")
	}
	second, hits, changed := normalizeAnthropicDateline(first)
	if changed || hits != nil || !bytes.Equal(second, first) {
		t.Fatalf("second pass changed: changed=%v hits=%+v first=%s second=%s", changed, hits, first, second)
	}
}

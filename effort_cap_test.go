package main

import (
	"encoding/json"
	"testing"
)

func TestEffortCapLimitFor(t *testing.T) {
	cap := newEffortCap(
		map[string]string{
			"1f85c8154331cf17": "medium",
			"other-user":       "high",
		},
		map[string]string{"255.215.215.73": "low"},
	)

	for _, tc := range []struct {
		name, userID, clientIP, want string
	}{
		{name: "principal match", userID: "1f85c8154331cf17", want: "medium"},
		{name: "client-scoped identity inherits principal rule", userID: "1f85c8154331cf17-c-d2c9f43d112015628a", want: "medium"},
		{name: "case insensitive", userID: "1F85C8154331CF17", want: "medium"},
		{name: "origin match", clientIP: "255.215.215.73", want: "low"},
		{name: "strictest of user and origin wins", userID: "1f85c8154331cf17", clientIP: "255.215.215.73", want: "low"},
		{name: "unrelated user untouched", userID: "921c8fcc0ad0d07f", want: ""},
		{name: "unrelated origin untouched", clientIP: "37.27.100.26", want: ""},
		{name: "empty identity", want: ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := cap.limitFor(tc.userID, tc.clientIP); got != tc.want {
				t.Fatalf("limitFor(%q, %q) = %q, want %q", tc.userID, tc.clientIP, got, tc.want)
			}
		})
	}
}

func TestEffortCapIgnoresInvalidConfig(t *testing.T) {
	cap := newEffortCap(map[string]string{
		"user-a": "ludicrous",
		"user-b": "",
		"":       "medium",
		"user-c": "  MEDIUM  ",
	}, nil)

	if got := cap.limitFor("user-a", ""); got != "" {
		t.Errorf("unknown effort should be ignored, got %q", got)
	}
	if got := cap.limitFor("user-b", ""); got != "" {
		t.Errorf("empty effort should be ignored, got %q", got)
	}
	if got := cap.limitFor("user-c", ""); got != "medium" {
		t.Errorf("whitespace/case should normalize, got %q", got)
	}
}

func TestCapCodexEffortInBodyFlatShape(t *testing.T) {
	body := []byte(`{"model":"gpt-6-astra","reasoning":{"context":"all_turns","effort":"xhigh","mode":"standard","summary":"detailed"},"input":[]}`)

	out, previous, changed := capCodexEffortInBody(body, "medium")
	if !changed || previous != "xhigh" {
		t.Fatalf("changed=%v previous=%q, want true/xhigh", changed, previous)
	}

	var got map[string]any
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	reasoning := got["reasoning"].(map[string]any)
	if reasoning["effort"] != "medium" {
		t.Fatalf("effort = %v, want medium", reasoning["effort"])
	}
	// Sibling reasoning fields carry conversation semantics and must survive.
	if reasoning["context"] != "all_turns" || reasoning["summary"] != "detailed" || reasoning["mode"] != "standard" {
		t.Fatalf("effort cap altered unrelated reasoning fields: %#v", reasoning)
	}
	if got["model"] != "gpt-6-astra" {
		t.Fatalf("model = %v, want gpt-6-astra", got["model"])
	}
}

func TestCapCodexEffortInBodyNestedResponseCreate(t *testing.T) {
	body := []byte(`{"type":"response.create","response":{"model":"gpt-6-astra","reasoning":{"context":"all_turns","effort":"xhigh"}}}`)

	out, previous, changed := capCodexEffortInBody(body, "medium")
	if !changed || previous != "xhigh" {
		t.Fatalf("changed=%v previous=%q, want true/xhigh", changed, previous)
	}

	var got map[string]any
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got["type"] != "response.create" {
		t.Fatalf("envelope type lost: %#v", got)
	}
	response := got["response"].(map[string]any)
	reasoning := response["reasoning"].(map[string]any)
	if reasoning["effort"] != "medium" {
		t.Fatalf("nested effort = %v, want medium", reasoning["effort"])
	}
}

// Every effort above the ceiling must be clamped, not just the xhigh that
// prompted this cap.
func TestCapCodexEffortInBodyLowersEveryEffortAboveCap(t *testing.T) {
	for _, effort := range []string{"high", "xhigh", "max"} {
		t.Run(effort, func(t *testing.T) {
			body := []byte(`{"reasoning":{"effort":"` + effort + `"}}`)
			out, previous, changed := capCodexEffortInBody(body, "medium")
			if !changed {
				t.Fatalf("effort %q above the medium cap was not clamped", effort)
			}
			if previous != effort {
				t.Errorf("previous = %q, want %q", previous, effort)
			}
			if got := string(out); got != `{"reasoning":{"effort":"medium"}}` {
				t.Errorf("clamped body = %s", got)
			}
		})
	}
}

// Anthropic sends output_config.effort, which passes the cheap
// strings.Contains prefilter. The Codex cap only owns reasoning.effort and
// must leave other providers' bodies byte-identical.
func TestCapCodexEffortIgnoresNonCodexEffortFields(t *testing.T) {
	for _, tc := range []struct{ name, body string }{
		{name: "claude output_config", body: `{"model":"claude-opus-5","output_config":{"effort":"high"},"stream":true}`},
		{name: "unrelated nested effort", body: `{"metadata":{"effort":"xhigh"}}`},
		{name: "effort on a tool schema", body: `{"tools":[{"name":"x","input_schema":{"properties":{"effort":"high"}}}]}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, previous, changed := capCodexEffortInBody([]byte(tc.body), "medium")
			if changed || previous != "" {
				t.Fatalf("non-Codex effort field rewritten: changed=%v previous=%q", changed, previous)
			}
			if string(out) != tc.body {
				t.Fatalf("body mutated:\n got %s\nwant %s", out, tc.body)
			}
		})
	}
}

func TestCapCodexEffortInBodyOnlyLowersEffort(t *testing.T) {
	for _, tc := range []struct {
		name, effort string
	}{
		{name: "already at cap", effort: "medium"},
		{name: "below cap", effort: "low"},
		{name: "minimal", effort: "minimal"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := []byte(`{"reasoning":{"effort":"` + tc.effort + `"}}`)
			out, _, changed := capCodexEffortInBody(body, "medium")
			if changed {
				t.Fatalf("effort %q should not be raised to the cap", tc.effort)
			}
			if string(out) != string(body) {
				t.Fatalf("body mutated: %s", out)
			}
		})
	}
}

func TestCapCodexEffortInBodyNoOpCases(t *testing.T) {
	for _, tc := range []struct {
		name, body, limit string
	}{
		{name: "no cap configured", body: `{"reasoning":{"effort":"xhigh"}}`, limit: ""},
		{name: "no reasoning block", body: `{"model":"gpt-6-astra"}`, limit: "medium"},
		{name: "no effort field", body: `{"reasoning":{"context":"all_turns"}}`, limit: "medium"},
		{name: "unknown effort value", body: `{"reasoning":{"effort":"experimental"}}`, limit: "medium"},
		{name: "malformed json with effort token", body: `{"reasoning":{"effort":`, limit: "medium"},
		{name: "empty body", body: ``, limit: "medium"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, previous, changed := capCodexEffortInBody([]byte(tc.body), tc.limit)
			if changed || previous != "" {
				t.Fatalf("changed=%v previous=%q, want no-op", changed, previous)
			}
			if string(out) != tc.body {
				t.Fatalf("body mutated: %s", out)
			}
		})
	}
}

func TestCapCodexEffortNilSafety(t *testing.T) {
	var cap *effortCap
	if got := cap.limitFor("user", "ip"); got != "" {
		t.Fatalf("nil cap should not match, got %q", got)
	}
	if cap.configured() {
		t.Fatal("nil cap should not report configured")
	}
}

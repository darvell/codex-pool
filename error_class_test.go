package main

import "testing"

func TestClassifyAnthropicOverloadedAsTransient(t *testing.T) {
	t.Parallel()

	if got := classifyStatus(529); got != ErrorClassTransient {
		t.Fatalf("classifyStatus(529) = %s, want %s", got, ErrorClassTransient)
	}
}

func TestIsClaudeOrganizationDisabled(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		body string
		want bool
	}{
		{
			name: "direct phrase",
			body: `{"error":{"message":"Your organization has been disabled"}}`,
			want: true,
		},
		{
			name: "snake_case code",
			body: `{"error":{"type":"organization_disabled"}}`,
			want: true,
		},
		{
			name: "underscore phrase",
			body: `{"error":{"code":"organization_has_been_disabled"}}`,
			want: true,
		},
		{
			name: "other auth issue",
			body: `{"error":{"type":"authentication_error","message":"invalid token"}}`,
			want: false,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := isClaudeOrganizationDisabled([]byte(tc.body))
			if got != tc.want {
				t.Fatalf("isClaudeOrganizationDisabled()=%v want %v", got, tc.want)
			}
		})
	}
}

func TestIsCyberPolicyError(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		body string
		want bool
	}{
		{"error envelope code", `{"error":{"code":"cyber_policy"}}`, true},
		{"error envelope type", `{"error":{"type":"cyber_policy"}}`, true},
		{"top-level type", `{"type":"cyber_policy","message":"x"}`, true},
		{"unrelated invalid_request", `{"error":{"code":"invalid_request"}}`, false},

		// Assistant output that mentions the phrase must NOT trip
		// suppression — that's the regression that caused every reply
		// containing the literal string "cyber_policy" to be replaced
		// with a synthetic refusal.
		{
			"assistant prose mentioning cyber_policy",
			`{"type":"response.output_text.delta","delta":"the function isCyberPolicyError matches cyber_policy in the body"}`,
			false,
		},
		{
			"assistant prose with quoted cyber_policy",
			`{"type":"response.output_text.delta","delta":"the upstream emits \"cyber_policy\" as the error code"}`,
			false,
		},
		{
			"unrelated json string field",
			`{"comment":"see cyber_policy handling docs"}`,
			false,
		},
		{"empty", ``, false},
		{"non-json blob", `cyber_policy somewhere in plain text`, false},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := isCyberPolicyError([]byte(tc.body)); got != tc.want {
				t.Fatalf("isCyberPolicyError(%q) = %v, want %v", tc.body, got, tc.want)
			}
		})
	}
}

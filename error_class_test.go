package main

import "testing"

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

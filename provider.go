package main

import (
	"context"
	"net/http"
	"net/url"
)

// Provider defines the contract for LLM API providers (Codex, Claude, Gemini).
// Each provider implementation encapsulates all provider-specific behavior.
type Provider interface {
	// Type returns the provider type identifier.
	Type() AccountType

	// LoadAccount parses provider-specific JSON into an Account.
	// Returns nil, nil if the file doesn't match this provider's format.
	LoadAccount(name, path string, data []byte) (*Account, error)

	// SetAuthHeaders adds provider-specific auth headers to a request.
	SetAuthHeaders(req *http.Request, acc *Account)

	// RefreshToken refreshes the access token.
	// Returns nil if refresh is not supported or not needed.
	RefreshToken(ctx context.Context, acc *Account, transport *http.Transport) error

	// ParseUsage extracts usage from an SSE event (provider-specific format).
	// Returns nil if the event doesn't contain usage data.
	ParseUsage(obj map[string]any) *RequestUsage

	// ParseUsageHeaders extracts usage/rate-limit info from response headers.
	ParseUsageHeaders(acc *Account, headers http.Header)

	// UpstreamURL returns the base URL for this provider.
	UpstreamURL() *url.URL

	// MatchesPath returns true if this provider handles the given request path.
	MatchesPath(path string) bool

	// NormalizePath adjusts the request path for the upstream (if needed).
	NormalizePath(path string) string

	// DetectsSSE returns true if SSE detection should be enabled for this path.
	DetectsSSE(path string, contentType string) bool
}

// ProviderRegistry manages all provider implementations.
type ProviderRegistry struct {
	providers []Provider
	byType    map[AccountType]Provider
}

// NewProviderRegistry creates a registry with all configured providers.
func NewProviderRegistry(codex *CodexProvider, claude *ClaudeProvider, gemini *GeminiProvider) *ProviderRegistry {
	providers := []Provider{codex, claude, gemini}
	byType := make(map[AccountType]Provider)
	for _, p := range providers {
		byType[p.Type()] = p
	}
	return &ProviderRegistry{
		providers: providers,
		byType:    byType,
	}
}

// ForType returns the provider for the given account type.
func (r *ProviderRegistry) ForType(t AccountType) Provider {
	return r.byType[t]
}

// ForPath returns the provider that handles the given request path.
// Returns nil if no provider matches.
func (r *ProviderRegistry) ForPath(path string) Provider {
	for _, p := range r.providers {
		if p.MatchesPath(path) {
			return p
		}
	}
	return nil
}

// LoadAccount attempts to load an account using any matching provider.
// The provider is selected based on filename prefix.
func (r *ProviderRegistry) LoadAccount(name, path string, data []byte) (*Account, error) {
	for _, p := range r.providers {
		acc, err := p.LoadAccount(name, path, data)
		if err != nil {
			return nil, err
		}
		if acc != nil {
			return acc, nil
		}
	}
	return nil, nil
}

// All returns all registered providers.
func (r *ProviderRegistry) All() []Provider {
	return r.providers
}

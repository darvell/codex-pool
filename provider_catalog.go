package main

import (
	"context"
	"errors"
	"net/http"
	"net/url"
)

type modelCatalogProvider interface {
	modelCatalog() providerModelCatalog
}

type providerModelCatalog struct {
	base    *url.URL
	path    string
	parse   func([]byte) (map[string]DiscoveredModel, error)
	headers func(http.Header)
}

func (p *CodexProvider) modelCatalog() providerModelCatalog {
	var base *url.URL
	if p.whamBase != nil {
		target := *p.whamBase
		query := target.Query()
		query.Set("client_version", currentCodexFingerprint().Version)
		target.RawQuery = query.Encode()
		base = &target
	}
	return providerModelCatalog{base: base, path: "/codex/models", parse: parseProviderModels}
}

func (p *ClaudeProvider) modelCatalog() providerModelCatalog {
	return providerModelCatalog{base: p.UpstreamURL("/v1/models"), path: "/v1/models", parse: parseProviderModels, headers: func(h http.Header) {
		h.Set("Anthropic-Version", "2023-06-01")
		h.Set("Anthropic-Beta", "oauth-2025-04-20")
	}}
}

func (p *GrokProvider) modelCatalog() providerModelCatalog {
	return providerModelCatalog{base: p.UpstreamURL("/v1/models"), path: "/models", parse: parseProviderModels}
}

func (p *KimiProvider) modelCatalog() providerModelCatalog {
	return providerModelCatalog{base: p.UpstreamURL("/v1/models"), path: "/v1/models", parse: parseProviderModels}
}

func (p *MinimaxProvider) modelCatalog() providerModelCatalog {
	return providerModelCatalog{base: p.UpstreamURL("/v1/models"), path: "/v1/models", parse: parseProviderModels}
}

func (p *ZAIProvider) modelCatalog() providerModelCatalog {
	return providerModelCatalog{base: p.UpstreamURL("/v1/models"), path: "/v1/models", parse: parseProviderModels}
}

func (p *MistralProvider) modelCatalog() providerModelCatalog {
	return providerModelCatalog{base: p.UpstreamURL("/v1/models"), path: "/v1/models", parse: parseMistralModels}
}

func (p *mistralVibeProvider) modelCatalog() providerModelCatalog {
	return providerModelCatalog{base: p.UpstreamURL("/v1/models"), path: "/v1/models", parse: parseMistralModels}
}

func (p *OpencodeGoProvider) modelCatalog() providerModelCatalog {
	return providerModelCatalog{base: p.UpstreamURL("/models"), path: "/models", parse: parseProviderModels}
}

func (c providerModelCatalog) endpoint() (*url.URL, bool) {
	if c.base == nil {
		return nil, false
	}
	target := *c.base
	target.Path = singleJoin(target.Path, c.path)
	return &target, true
}

func catalogFor(provider Provider) (providerModelCatalog, error) {
	capability, ok := provider.(modelCatalogProvider)
	if !ok {
		return providerModelCatalog{}, errors.New("provider has no model discovery endpoint")
	}
	catalog := capability.modelCatalog()
	if _, ok := catalog.endpoint(); !ok {
		return providerModelCatalog{}, errors.New("provider has no model discovery endpoint")
	}
	return catalog, nil
}

func (c providerModelCatalog) request(ctx context.Context, provider Provider, account *Account) (*http.Request, error) {
	target, ok := c.endpoint()
	if !ok {
		return nil, errors.New("provider has no model discovery endpoint")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return nil, err
	}
	provider.SetAuthHeaders(req, account)
	req.Header.Set("Accept", "application/json")
	if c.headers != nil {
		c.headers(req.Header)
	}
	return req, nil
}

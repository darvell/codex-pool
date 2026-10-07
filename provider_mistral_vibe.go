package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	vibeConsoleURL    = "https://console.mistral.ai"
	vibePlanTTL       = 15 * time.Minute
	vibeHTTPTimeout   = 30 * time.Second
	vibeResponseLimit = 1 << 20
)

type vibeAccountInfo struct {
	PlanType    string    `json:"plan_type"`
	PlanName    string    `json:"plan_name"`
	APIBase     string    `json:"api_base,omitempty"`
	ValidatedAt time.Time `json:"validated_at"`
}

func (info *vibeAccountInfo) eligible() bool {
	if info == nil || !strings.EqualFold(info.PlanType, "chat") {
		return false
	}
	switch strings.ToUpper(info.PlanName) {
	case "INDIVIDUAL", "EDU", "TEAM":
		return true
	default:
		return false
	}
}

func (info *vibeAccountInfo) current() bool {
	return info.eligible() && !info.ValidatedAt.IsZero() && !info.ValidatedAt.After(time.Now()) && time.Since(info.ValidatedAt) < vibePlanTTL
}

type mistralVibeProvider struct{ *MistralProvider }

func newMistralVibeProvider(base *url.URL) *mistralVibeProvider {
	return &mistralVibeProvider{NewMistralProvider(base)}
}

func (p *mistralVibeProvider) Type() AccountType { return AccountTypeMistralVibe }

func (p *mistralVibeProvider) LoadAccount(name, path string, data []byte) (*Account, error) {
	account, err := p.MistralProvider.LoadAccount(name, path, data)
	if err != nil || account == nil {
		return account, err
	}
	var auth struct {
		Info *vibeAccountInfo `json:"vibe_account"`
	}
	if err := json.Unmarshal(data, &auth); err != nil {
		return nil, err
	}
	account.Type = AccountTypeMistralVibe
	account.vibeAccount = auth.Info
	account.PlanType = "unverified"
	if auth.Info.eligible() {
		account.PlanType = strings.ToLower(auth.Info.PlanName)
	}
	return account, nil
}

func (p *mistralVibeProvider) ParseUsage(obj map[string]any) *RequestUsage {
	usage := p.MistralProvider.ParseUsage(obj)
	if usage != nil && usage.Model != "" {
		usage.Model = mistralPublicID(AccountTypeMistralVibe, mistralCanonicalModel(usage.Model))
	}
	return usage
}

func isMistralType(kind AccountType) bool {
	return kind == AccountTypeMistral || kind == AccountTypeMistralVibe
}

func isMistralVibeModel(model string) bool {
	prefix := "mistral-vibe/"
	model = strings.TrimSpace(model)
	return len(model) > len(prefix) && strings.EqualFold(model[:len(prefix)], prefix)
}

func mistralPublicID(kind AccountType, model string) string {
	if kind == AccountTypeMistralVibe {
		return "mistral-vibe/" + mistralCanonicalModel(model)
	}
	return mistralCatalogID(model)
}

func (h *proxyHandler) vibeAccountInfo(ctx context.Context, key string) (*vibeAccountInfo, error) {
	var info vibeAccountInfo
	if err := h.vibeJSON(ctx, http.MethodGet, vibeConsoleURL+"/api/vibe/whoami", nil, key, &info); err != nil {
		return nil, err
	}
	if !info.eligible() {
		return nil, errors.New("Sign in with a Mistral Pro, Education, or Team subscription")
	}
	if info.APIBase != "" {
		base, err := url.Parse(info.APIBase)
		if err != nil || base.User != nil || base.Scheme != h.cfg.mistralBase.Scheme || base.Host != h.cfg.mistralBase.Host || strings.TrimRight(base.Path, "/") != strings.TrimRight(h.cfg.mistralBase.Path, "/") || base.RawQuery != "" || base.Fragment != "" {
			return nil, errors.New("This subscription requires a different Mistral deployment")
		}
	}
	info.ValidatedAt = time.Now().UTC()
	return &info, nil
}

func (h *proxyHandler) syncVibeAccount(now time.Time, account *Account) {
	account.mu.Lock()
	key := account.AccessToken
	info := account.vibeAccount
	stale := !info.current() || now.Sub(info.ValidatedAt) >= h.cfg.usageRefresh
	account.mu.Unlock()
	if !stale {
		return
	}
	fresh, err := h.vibeAccountInfo(context.Background(), key)
	account.mu.Lock()
	if account.AccessToken != key {
		account.mu.Unlock()
		return
	}
	if err != nil {
		account.vibeAccount = nil
		account.PlanType = "unverified"
		account.HealthError = err.Error()
		account.mu.Unlock()
		return
	}
	account.vibeAccount = fresh
	account.PlanType = strings.ToLower(fresh.PlanName)
	account.HealthError = ""
	account.mu.Unlock()
}

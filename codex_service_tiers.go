package main

import (
	"encoding/json"
	"net/http"
	"sort"
	"strings"
)

const codexRoutingHintHeader = "x-codex-routing-hint"

type modelServiceTier struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

func serviceTierFromJSON(body []byte) string {
	var controls struct {
		ServiceTier string `json:"service_tier"`
		Response    struct {
			ServiceTier string `json:"service_tier"`
		} `json:"response"`
	}
	_ = json.Unmarshal(body, &controls)
	if controls.ServiceTier != "" {
		return controls.ServiceTier
	}
	return controls.Response.ServiceTier
}

func tierNeedsDiscovery(tier string) bool {
	// Keep the established API tiers working before discovery completes.
	// New catalog-defined tiers must never fall back to an unentitled account.
	switch tier {
	case "", "default", "auto", "priority", "flex":
		return false
	default:
		return true
	}
}

func accountSupportsTier(account *Account, model, tier string) bool {
	if !tierNeedsDiscovery(tier) {
		return true
	}
	if account == nil {
		return false
	}
	account.mu.Lock()
	defer account.mu.Unlock()
	discovered, ok := accountDiscoveredModel(account, model)
	if !ok {
		return false
	}
	for _, supported := range discovered.ServiceTiers {
		if supported.ID == tier {
			return true
		}
	}
	return false
}

func (p *poolState) tierExclusions(exclude map[string]bool, accountType AccountType, model, tier string) map[string]bool {
	if accountType != AccountTypeCodex || !tierNeedsDiscovery(tier) {
		return exclude
	}
	filtered := make(map[string]bool, len(exclude))
	for id, blocked := range exclude {
		filtered[id] = blocked
	}
	for _, account := range p.allAccounts() {
		if account.Type == accountType && !accountSupportsTier(account, model, tier) {
			filtered[account.ID] = true
		}
	}
	return filtered
}

func (p *poolState) candidateForTier(conversationID string, exclude map[string]bool, accountType AccountType, requiredPlan, clientIP, model, tier string) *Account {
	return p.candidateForModel(conversationID, p.tierExclusions(exclude, accountType, model, tier), accountType, requiredPlan, clientIP, model)
}

func codexRoutingHint(headers http.Header) (model, tier string) {
	for _, part := range strings.Split(headers.Get(codexRoutingHintHeader), ";") {
		key, value, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			continue
		}
		switch key {
		case "model":
			model = strings.TrimSpace(value)
		case "tier":
			tier = strings.TrimSpace(value)
		}
	}
	return model, tier
}

func mergeCodexServiceTiers(body []byte, pool *poolState) []byte {
	if pool == nil {
		return body
	}
	var catalog struct {
		Models []map[string]json.RawMessage `json:"models"`
	}
	if json.Unmarshal(body, &catalog) != nil {
		return body
	}
	// Aggregate account-specific entitlements, not the randomly selected
	// account's catalog. Disabled/dead accounts cannot provide a tier.
	byModel := make(map[string]map[string]modelServiceTier)
	for _, account := range pool.allAccounts() {
		account.mu.Lock()
		if account.Type == AccountTypeCodex && !account.Dead && !account.Disabled {
			for id, model := range account.Models {
				if byModel[id] == nil {
					byModel[id] = make(map[string]modelServiceTier)
				}
				for _, tier := range model.ServiceTiers {
					if tier.ID != "" {
						byModel[id][tier.ID] = tier
					}
				}
			}
		}
		account.mu.Unlock()
	}
	for _, row := range catalog.Models {
		var slug string
		_ = json.Unmarshal(row["slug"], &slug)
		if upstream, ok := defaultModelAliases[strings.ToLower(slug)]; ok {
			slug = upstream
		}
		tiers, known := byModel[slug]
		if !known {
			// Injected fallback rows may inherit tiers from a different model.
			// Never advertise a catalog-defined tier without discovered support.
			if !strings.HasPrefix(slug, "gpt-") {
				continue
			}
			tiers = make(map[string]modelServiceTier)
			var advertised []modelServiceTier
			_ = json.Unmarshal(row["service_tiers"], &advertised)
			for _, tier := range advertised {
				if !tierNeedsDiscovery(tier.ID) {
					tiers[tier.ID] = tier
				}
			}
		}
		ordered := make([]modelServiceTier, 0, len(tiers))
		for _, tier := range tiers {
			ordered = append(ordered, tier)
		}
		sort.Slice(ordered, func(i, j int) bool { return ordered[i].ID < ordered[j].ID })
		row["service_tiers"], _ = json.Marshal(ordered)
		var defaultTier string
		if json.Unmarshal(row["default_service_tier"], &defaultTier) == nil && defaultTier != "" {
			if _, supported := tiers[defaultTier]; !supported {
				row["default_service_tier"] = json.RawMessage("null")
			}
		}
	}
	// Preserve top-level fields and every unrelated model field.
	var root map[string]json.RawMessage
	if json.Unmarshal(body, &root) != nil {
		return body
	}
	root["models"], _ = json.Marshal(catalog.Models)
	out, err := json.Marshal(root)
	if err != nil {
		return body
	}
	return out
}

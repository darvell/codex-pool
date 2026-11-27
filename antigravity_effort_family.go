package main

import (
	"encoding/json"
	"strings"
	"time"
)

// Antigravity publishes some models once per reasoning level, as
// gemini-4-neon-low, -medium, -high, and -xhigh, each a separate upstream
// model. Client model pickers show the family once, as gemini-4-neon, with
// those levels as its reasoning options. A request for the family resolves
// to the tier matching its reasoning effort before routing, so quota,
// cooldowns, and account selection all work on the real upstream model.
// The tier IDs stay routable for clients that already name them.

var antigravityEffortTiers = []string{"low", "medium", "high", "xhigh"}

const antigravityDefaultEffortTier = "medium"

// minAntigravityFamilyTiers keeps a lone "-high" model from being mistaken
// for a family.
const minAntigravityFamilyTiers = 2

func splitAntigravityEffortTier(id string) (string, string, bool) {
	for _, tier := range antigravityEffortTiers {
		if base, ok := strings.CutSuffix(id, "-"+tier); ok && base != "" {
			return base, tier, true
		}
	}
	return "", "", false
}

// antigravityFamilyTiersLocked returns the tiers published for base, in
// effort order, or nil when base is not a reasoning family. The caller
// holds r.mu.
func (r *antigravityModelRegistry) antigravityFamilyTiersLocked(base string) []string {
	present := map[string]bool{}
	for _, snapshot := range r.accounts {
		if _, ok := snapshot.Models[base]; ok {
			return nil
		}
		for id := range snapshot.Models {
			if family, tier, ok := splitAntigravityEffortTier(id); ok && family == base {
				present[tier] = true
			}
		}
	}
	if len(r.accounts) == 0 {
		for _, fallback := range antigravityFallbackModels {
			if family, tier, ok := splitAntigravityEffortTier(fallback.ID); ok && family == base {
				present[tier] = true
			}
		}
	}
	if len(present) < minAntigravityFamilyTiers {
		return nil
	}
	tiers := make([]string, 0, len(present))
	for _, tier := range antigravityEffortTiers {
		if present[tier] {
			tiers = append(tiers, tier)
		}
	}
	return tiers
}

// resolveEffortTier maps a family model and the request's reasoning effort
// to the tier model. Any other model is returned unchanged.
func (r *antigravityModelRegistry) resolveEffortTier(model, effort string) string {
	prefix := ""
	base := strings.TrimSpace(model)
	if trimmed, ok := strings.CutPrefix(base, "antigravity/"); ok {
		prefix, base = "antigravity/", trimmed
	}
	r.mu.RLock()
	tiers := r.antigravityFamilyTiersLocked(base)
	r.mu.RUnlock()
	if tiers == nil {
		return model
	}
	return prefix + base + "-" + pickAntigravityEffortTier(tiers, effort)
}

// pickAntigravityEffortTier chooses the published tier closest to the
// requested effort, preferring the lower tier on a tie.
func pickAntigravityEffortTier(tiers []string, effort string) string {
	want := antigravityEffortRank(effort)
	best, bestDistance := tiers[0], -1
	for _, tier := range tiers {
		distance := antigravityEffortRank(tier) - want
		if distance < 0 {
			distance = -distance
		}
		if bestDistance < 0 || distance < bestDistance {
			best, bestDistance = tier, distance
		}
	}
	return best
}

func antigravityEffortRank(effort string) int {
	switch strings.ToLower(strings.TrimSpace(effort)) {
	case "none", "minimal", "low":
		return 0
	case "high":
		return 2
	case "xhigh", "max":
		return 3
	default:
		return 1
	}
}

// requestReasoningEffort reads the reasoning effort a client asked for in
// any of the request shapes the pool accepts.
func requestReasoningEffort(body []byte) string {
	var request struct {
		ReasoningEffort string `json:"reasoning_effort"`
		Reasoning       struct {
			Effort string `json:"effort"`
		} `json:"reasoning"`
		OutputConfig struct {
			Effort string `json:"effort"`
		} `json:"output_config"`
		Thinking struct {
			BudgetTokens float64 `json:"budget_tokens"`
		} `json:"thinking"`
		GenerationConfig struct {
			ThinkingConfig struct {
				ThinkingLevel  string  `json:"thinkingLevel"`
				ThinkingBudget float64 `json:"thinkingBudget"`
			} `json:"thinkingConfig"`
		} `json:"generationConfig"`
	}
	if json.Unmarshal(body, &request) != nil {
		return ""
	}
	thinking := request.GenerationConfig.ThinkingConfig
	for _, effort := range []string{request.Reasoning.Effort, request.ReasoningEffort, request.OutputConfig.Effort, thinking.ThinkingLevel} {
		if effort = strings.TrimSpace(effort); effort != "" {
			return effort
		}
	}
	for _, budget := range []float64{request.Thinking.BudgetTokens, thinking.ThinkingBudget} {
		if budget > 0 {
			return reasoningEffortFromBudget(budget)
		}
	}
	return ""
}

// collapseAntigravityEffortFamilies lists each reasoning family once in
// place of its tiers. The family entry carries the default tier's metadata
// and the combined availability of every tier.
func collapseAntigravityEffortFamilies(models []AntigravityCatalogModel) []AntigravityCatalogModel {
	ids := make(map[string]bool, len(models))
	families := map[string][]AntigravityCatalogModel{}
	for _, model := range models {
		ids[model.ID] = true
		if base, _, ok := splitAntigravityEffortTier(model.ID); ok {
			families[base] = append(families[base], model)
		}
	}

	out := make([]AntigravityCatalogModel, 0, len(models))
	emitted := map[string]bool{}
	for _, model := range models {
		base, _, ok := splitAntigravityEffortTier(model.ID)
		if !ok || ids[base] || len(families[base]) < minAntigravityFamilyTiers {
			out = append(out, model)
			continue
		}
		if emitted[base] {
			continue
		}
		emitted[base] = true
		out = append(out, antigravityFamilyEntry(base, families[base]))
	}
	return out
}

func antigravityFamilyEntry(base string, tiers []AntigravityCatalogModel) AntigravityCatalogModel {
	byTier := map[string]AntigravityCatalogModel{}
	for _, model := range tiers {
		_, tier, _ := splitAntigravityEffortTier(model.ID)
		byTier[tier] = model
	}
	var levels []string
	for _, tier := range antigravityEffortTiers {
		if _, ok := byTier[tier]; ok {
			levels = append(levels, tier)
		}
	}
	defaultTier := pickAntigravityEffortTier(levels, antigravityDefaultEffortTier)

	entry := byTier[defaultTier]
	entry.ID = base
	entry.DisplayName = antigravityFamilyDisplayName(entry.DisplayName)
	entry.Aliases = []string{"antigravity/" + base}
	entry.ReasoningLevels = levels
	entry.DefaultReasoningLevel = defaultTier
	entry.Stale = true
	entry.AvailableNow = false
	entry.NextResetAt = time.Time{}
	for _, model := range tiers {
		if model.SupportingAccounts > entry.SupportingAccounts {
			entry.SupportingAccounts = model.SupportingAccounts
		}
		if model.AvailableAccounts > entry.AvailableAccounts {
			entry.AvailableAccounts = model.AvailableAccounts
		}
		entry.AvailableNow = entry.AvailableNow || model.AvailableNow
		entry.Stale = entry.Stale && model.Stale
		if !model.NextResetAt.IsZero() && (entry.NextResetAt.IsZero() || model.NextResetAt.Before(entry.NextResetAt)) {
			entry.NextResetAt = model.NextResetAt
		}
	}
	return entry
}

// antigravityFamilyDisplayName drops the tier suffix upstream puts on each
// tier's name, as in "Gemini 4 Neon (Medium)".
func antigravityFamilyDisplayName(name string) string {
	if open := strings.LastIndex(name, " ("); open > 0 && strings.HasSuffix(name, ")") {
		if _, _, ok := splitAntigravityEffortTier("x-" + strings.ToLower(name[open+2:len(name)-1])); ok {
			return name[:open]
		}
	}
	return name
}

func antigravityListedCatalog(pool *poolState) []AntigravityCatalogModel {
	return collapseAntigravityEffortFamilies(antigravityCatalog(pool))
}

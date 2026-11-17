package main

const profileContextWindow = 1000000

type contextProfile struct {
	id           string
	base         string
	requestModel string
	billingModel string
	name         string
	description  string
}

// Request aliases follow model upgrades; billing retains the requested model family.
var contextProfiles = []contextProfile{
	{id: "gpt-6-astra[1m]", base: "gpt-6-astra", requestModel: "gpt-6-astra", billingModel: "gpt-6-astra", name: "GPT-6-Astra (1M)", description: "This is really fucking expensive."},
	{id: "gpt-6-sol[1m]", base: "gpt-6-sol", requestModel: "gpt-6.1-sol", billingModel: "gpt-6-sol", name: "GPT-6-Sol (1M)"},
	{id: "gpt-6.1-sol[1m]", base: "gpt-6.1-sol", requestModel: "gpt-6.1-sol", billingModel: "gpt-6.1-sol", name: "GPT-6.1-Sol (1M)"},
	{id: "gpt-6-luna[1m]", base: "gpt-6-luna", requestModel: "gpt-6-luna", billingModel: "gpt-6-luna", name: "GPT-6-Luna (1M)"},
	{id: "gpt-5.6-sol[1m]", base: "gpt-5.6-sol", requestModel: "gpt-5.6-sol", billingModel: "gpt-5.6-sol", name: "GPT-5.6-Sol (1M)", description: "Frontier agentic coding model with a 1M context window."},
	{id: "gpt-5.6-terra[1m]", base: "gpt-5.6-terra", requestModel: "gpt-5.6-terra", billingModel: "gpt-5.6-terra", name: "GPT-5.6-Terra (1M)", description: "Balanced agentic coding model with a 1M context window."},
	{id: "gpt-5.6-luna[1m]", base: "gpt-5.6-luna", requestModel: "gpt-5.6-luna", billingModel: "gpt-5.6-luna", name: "GPT-5.6-Luna (1M)", description: "Fast and affordable agentic coding model with a 1M context window."},
}

func addContextProfiles(models []poolModel) []poolModel {
	result := make([]poolModel, 0, len(models)+len(contextProfiles))
	for _, model := range models {
		result = append(result, model)
		if model.AccountType != AccountTypeCodex {
			continue
		}
		for _, profile := range contextProfiles {
			if profile.base != model.ID {
				continue
			}
			expanded := model
			expanded.ID = profile.id
			expanded.DisplayName = profile.name
			expanded.Description = profile.description
			expanded.ContextWindow = profileContextWindow
			expanded.Aliases = nil
			expanded.Input = append([]string(nil), model.Input...)
			result = append(result, expanded)
		}
	}
	return result
}

func profileRequestAliases(aliases map[string]string) map[string]string {
	for _, profile := range contextProfiles {
		aliases[profile.id] = profile.requestModel
	}
	return aliases
}

func profilePricingAliases(aliases map[string]string) map[string]string {
	for _, profile := range contextProfiles {
		aliases[profile.id] = profile.billingModel
	}
	return aliases
}

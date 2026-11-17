package main

import (
	"testing"
	"time"
)

func TestProviderClaimPrecedence(t *testing.T) {
	pool := newPoolState(nil, false)
	names := []string{"future-model"}
	for _, provider := range []AccountType{AccountTypeKimi, AccountTypeMinimax, AccountTypeZAI, AccountTypeXiaomi, AccountTypeAdverserial} {
		for _, model := range modelsForProvider(provider) {
			names = append(names, model.ID)
			names = append(names, model.Aliases...)
		}
	}
	for _, model := range grokModelCatalog {
		names = append(names, model.ID)
		names = append(names, grokPublicAliases(model)...)
	}
	collisions := make(map[string]AntigravityModelInfo, len(names))
	for _, name := range names {
		collisions[name] = AntigravityModelInfo{ID: name}
	}
	pool.antigravityModels.ReplaceAccount("collision", AntigravityAccountSnapshot{FetchedAt: time.Now(), Models: collisions})
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			if !isAntigravityModel(&pool.antigravityModels, name) {
				t.Fatal("collision model missing from Antigravity discovery")
			}
			claimed := name != "future-model"
			if externalModelClaimed(name) != claimed || opencodeGoBareModelTaken(name) != claimed || shouldRouteAntigravityModel(&pool.antigravityModels, name) == claimed {
				t.Fatalf("claim=%v Go exclusion=%v Antigravity=%v", externalModelClaimed(name), opencodeGoBareModelTaken(name), shouldRouteAntigravityModel(&pool.antigravityModels, name))
			}
			if !shouldRouteAntigravityModel(&pool.antigravityModels, "antigravity/"+name) {
				t.Fatal("explicit Antigravity model rejected")
			}
		})
	}
}

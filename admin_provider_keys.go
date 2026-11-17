package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var apiKeyDirectories = map[AccountType]string{
	AccountTypeKimi:        "kimi",
	AccountTypeMinimax:     "minimax",
	AccountTypeMistral:     "mistral",
	AccountTypeMistralVibe: "mistral_vibe",
	AccountTypeOpencodeGo:  "opencode_go",
	AccountTypeXiaomi:      "xiaomi",
	AccountTypeZAI:         "zai",
	AccountTypeAdverserial: "adverserial",
}

func readAdmissionKey(w http.ResponseWriter, r *http.Request) (string, bool) {
	var req struct {
		APIKey string `json:"api_key"`
	}
	if r.Header.Get("Content-Type") == "application/json" {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			respondJSONError(w, http.StatusBadRequest, "invalid json: "+err.Error())
			return "", false
		}
	} else {
		req.APIKey = r.FormValue("api_key")
	}
	apiKey := strings.TrimSpace(req.APIKey)
	if apiKey == "" {
		respondJSONError(w, http.StatusBadRequest, "api_key is required")
		return "", false
	}
	return apiKey, true
}

func (h *proxyHandler) handleCatalogKeyAdd(w http.ResponseWriter, r *http.Request, name string, provider Provider, apiKey string) {
	catalog, err := catalogFor(provider)
	if err != nil {
		respondJSONError(w, http.StatusInternalServerError, "invalid "+name+" validation URL")
		return
	}
	req, err := catalog.request(r.Context(), provider, &Account{AccessToken: apiKey})
	if err != nil {
		respondJSONError(w, http.StatusInternalServerError, "invalid "+name+" validation URL")
		return
	}
	resp, err := h.transport.RoundTrip(req)
	if err != nil {
		respondJSONError(w, http.StatusBadGateway, "failed to validate key: "+err.Error())
		return
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	resp.Body.Close()
	if err != nil {
		respondJSONError(w, http.StatusBadGateway, "failed to read "+name+" catalog")
		return
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		respondJSONError(w, http.StatusBadRequest, "invalid API key (authentication failed)")
		return
	}
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		respondJSONError(w, http.StatusBadGateway, fmt.Sprintf("key validation returned status %d", resp.StatusCode))
		return
	}
	models, err := catalog.parse(body)
	if err != nil {
		respondJSONError(w, http.StatusBadGateway, "key validation returned an unexpected catalog: "+err.Error())
		return
	}
	snapshot := &providerModelSnapshot{FetchedAt: time.Now().UTC(), Models: models}
	h.saveAPIKeySnapshot(w, r, provider.Type(), apiKey, snapshot)
}

func (h *proxyHandler) handleAPIKeyList(w http.ResponseWriter, acctType AccountType) {
	accounts := h.pool.allAccounts()

	type accountInfo struct {
		ID       string        `json:"id"`
		PlanType string        `json:"plan_type"`
		Dead     bool          `json:"dead"`
		Disabled bool          `json:"disabled"`
		Usage    UsageSnapshot `json:"usage,omitempty"`
	}

	var result []accountInfo
	for _, acc := range accounts {
		if acc.Type != acctType {
			continue
		}
		acc.mu.Lock()
		info := accountInfo{
			ID:       acc.ID,
			PlanType: acc.PlanType,
			Dead:     acc.Dead,
			Disabled: acc.Disabled,
			Usage:    acc.Usage,
		}
		acc.mu.Unlock()
		result = append(result, info)
	}

	respondJSON(w, map[string]any{
		"accounts": result,
		"count":    len(result),
	})
}

func (h *proxyHandler) handleAPIKeyRemove(w http.ResponseWriter, acctType AccountType, accountID string) {
	accounts := h.pool.allAccounts()
	var target *Account
	for _, acc := range accounts {
		if acc.Type == acctType && acc.ID == accountID {
			target = acc
			break
		}
	}

	if target == nil {
		respondJSONError(w, http.StatusNotFound, "account not found")
		return
	}

	target.mu.Lock()
	target.Dead = true
	target.Penalty += 100.0
	target.LastPenalty = time.Now()
	target.mu.Unlock()

	if err := saveAccount(target); err != nil {
		log.Printf("warning: failed to save dead %s account %s: %v", acctType, accountID, err)
		respondJSONError(w, http.StatusInternalServerError, "failed to persist: "+err.Error())
		return
	}

	log.Printf("removed %s account %s (marked dead)", acctType, accountID)

	respondJSON(w, map[string]any{
		"success":    true,
		"account_id": accountID,
	})
}

func (h *proxyHandler) saveAPIKeyAccountFile(w http.ResponseWriter, r *http.Request, acctType AccountType, apiKey string) {
	h.saveAPIKeySnapshot(w, r, acctType, apiKey, nil)
}

func (h *proxyHandler) saveAPIKeySnapshot(w http.ResponseWriter, r *http.Request, acctType AccountType, apiKey string, snapshot *providerModelSnapshot) {
	extra := make(map[string]any)
	if snapshot != nil {
		extra["provider_model_snapshot"] = snapshot
	}
	accountID, err := h.writeAPIKeyAccount(acctType, apiKey, extra)
	if err != nil {
		respondJSONError(w, http.StatusInternalServerError, "failed to save account: "+err.Error())
		return
	}
	h.reloadAccounts()
	h.auditProviderContribution(r, string(acctType), accountID)
	respondJSON(w, map[string]any{"success": true, "account_id": accountID})
}

func (h *proxyHandler) writeAPIKeyAccount(acctType AccountType, apiKey string, extra map[string]any) (string, error) {
	subdir, ok := apiKeyDirectories[acctType]
	if !ok {
		return "", fmt.Errorf("unsupported API-key account type %q", acctType)
	}
	accountID := subdir + "_" + randomHex(4)

	poolDir := filepath.Join(h.cfg.poolDir, subdir)
	if err := os.MkdirAll(poolDir, 0755); err != nil {
		return "", fmt.Errorf("create pool directory: %w", err)
	}

	filePath := filepath.Join(poolDir, accountID+".json")

	if _, err := os.Stat(filePath); err == nil {
		for i := 2; i <= 99; i++ {
			newPath := filepath.Join(poolDir, fmt.Sprintf("%s_%d.json", accountID, i))
			if _, err := os.Stat(newPath); os.IsNotExist(err) {
				filePath = newPath
				accountID = fmt.Sprintf("%s_%d", accountID, i)
				break
			}
		}
	}

	authJSON := map[string]any{
		"api_key":  apiKey,
		"added_at": time.Now().UTC().Format(time.RFC3339Nano),
	}
	for key, value := range extra {
		authJSON[key] = value
	}

	if err := atomicWriteJSON(filePath, authJSON); err != nil {
		return "", fmt.Errorf("write account: %w", err)
	}

	log.Printf("saved new %s account: %s -> %s", acctType, accountID, filePath)
	return accountID, nil
}

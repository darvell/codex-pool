package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

type operatorRoute struct {
	Method, Pattern, Capability string
	serve                       func(*proxyHandler, http.ResponseWriter, *http.Request)
}

var operatorRoutes = []operatorRoute{
	{http.MethodGet, "/api/operator/v1", "operator.read", func(h *proxyHandler, w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		noStore(w)
		_, ok := h.requireOperatorAPI(w, r)
		if !ok {
			return
		}
		respondJSON(w, map[string]any{"api_version": operatorAPIVersion, "openapi": "/api/operator/v1/openapi.json", "guide": "/api/operator/v1/guide", "whoami": "/api/operator/v1/whoami", "models": "/api/operator/v1/models", "pi_config": "/api/operator/v1/config/pi", "accounting_requests": "/api/operator/v1/accounting/requests", "quota_waste": "/api/pool/quota-waste"})
	}},
	{http.MethodGet, "/api/operator/v1/whoami", "operator.read", func(h *proxyHandler, w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		noStore(w)
		access, ok := h.requireOperatorAPI(w, r)
		if !ok {
			return
		}
		response := map[string]any{"principal": publicPrincipal(access.Principal), "credential_kind": "browser_session", "permissions": []string{"operator.read", "operator.write"}}
		if access.Token != nil {
			response["credential_kind"] = "operator_token"
			response["token"] = access.Token
			response["permissions"] = operatorTokenPermissions(access.Token.Scope)
		}
		respondJSON(w, response)
	}},
	{http.MethodGet, "/api/operator/v1/openapi.json", "operator.read", func(h *proxyHandler, w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		noStore(w)
		_, ok := h.requireOperatorAPI(w, r)
		if !ok {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(operatorOpenAPI)
	}},
	{http.MethodGet, "/api/operator/v1/guide", "operator.read", func(h *proxyHandler, w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		noStore(w)
		_, ok := h.requireOperatorAPI(w, r)
		if !ok {
			return
		}
		w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
		_, _ = w.Write(operatorGuide)
	}},
	{http.MethodGet, "/api/operator/v1/models", "operator.read", func(h *proxyHandler, w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		noStore(w)
		_, ok := h.requireOperatorAPI(w, r)
		if !ok {
			return
		}
		now := time.Now().UTC()
		mode, ok := operatorCatalogMode(w, r, "full")
		if !ok {
			return
		}
		models := operatorModelManifest(h.pool, now)
		if mode == "configured" {
			filtered := models[:0]
			for _, model := range models {
				if model.SupportingAccounts > 0 {
					filtered = append(filtered, model)
				}
			}
			models = filtered
		}
		respondJSON(w, map[string]any{"schema_version": poolModelsSchemaVersion, "generated_at": now, "catalog_mode": mode, "catalog_semantics": map[string]any{"full": "all models known to this deployment", "configured": "models with at least one configured supporting account", "supporting_accounts": "configured accounts supporting the model", "available_now": "transient routing readiness; false does not remove a model from the catalog"}, "pricing": map[string]any{"version": analyticsPricingVersion, "as_of": now, "freshness": "current runtime rate hints only; unknown is explicit and these rates are not historical facts"}, "pi_export": map[string]any{"endpoint": "/api/operator/v1/config/pi", "default_catalog": "configured", "credential_environment_variable": "CODEX_POOL_MODEL_API_KEY", "limitations": []string{"A generated Pi provider entry uses one API protocol, so mixed-endpoint OpenCode Go models not assigned to that entry are omitted; Pi itself supports Responses and Messages through other entries."}}, "models": models})
	}},
	{http.MethodGet, "/api/operator/v1/config/pi", "operator.read", func(h *proxyHandler, w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		noStore(w)
		_, ok := h.requireOperatorAPI(w, r)
		if !ok {
			return
		}
		mode, ok := operatorCatalogMode(w, r, "configured")
		if !ok {
			return
		}
		publicURL := h.cfg.publicURL()
		if publicURL == "" {
			respondJSONError(w, http.StatusServiceUnavailable, "public_url must be configured for portable exports")
			return
		}
		config := preparePiModels(publicURL, "CODEX_POOL_MODEL_API_KEY", "CODEX_POOL_MODEL_API_KEY", h.pool)
		if mode == "configured" {
			configured := map[string]bool{}
			for _, model := range poolModelsForClients(h.pool) {
				if model.SupportingAccounts > 0 {
					configured[piProviderKeyForDescriptor(model.Provider)+"\x00"+model.ID] = true
				}
			}
			for name, provider := range config.Providers {
				filtered := provider.Models[:0]
				for _, model := range provider.Models {
					if configured[name+"\x00"+model.ID] {
						filtered = append(filtered, model)
					}
				}
				if len(filtered) == 0 {
					delete(config.Providers, name)
					continue
				}
				provider.Models = filtered
				config.Providers[name] = provider
			}
		}
		data, err := json.MarshalIndent(config, "", "  ")
		if err != nil {
			respondJSONError(w, http.StatusInternalServerError, "failed to generate Pi configuration")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(data)
	}},
	{http.MethodGet, "/api/operator/v1/accounting/requests", "operator.read", func(h *proxyHandler, w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		noStore(w)
		_, ok := h.requireOperatorAPI(w, r)
		if !ok {
			return
		}
		h.handleOperatorAccountingRequests(w, r)
	}},
	{http.MethodGet, "/api/pool/stats", "operator.read", func(h *proxyHandler, w http.ResponseWriter, r *http.Request) {
		if !h.checkMemberOrAdminAuth(w, r) {
			return
		}
		h.handlePoolStats(w, r)
		return
	}},
	{http.MethodGet, "/api/pool/quota-waste", "operator.read", func(h *proxyHandler, w http.ResponseWriter, r *http.Request) {
		// This endpoint intentionally does not accept member authentication;
		// operator bearer/session authorization is required for quota economics.
		if _, ok := h.requireOperatorAPI(w, r); !ok {
			return
		}
		h.handleQuotaWaste(w, r)
		return
	}},
	{http.MethodGet, "/api/pool/users", "operator.read", func(h *proxyHandler, w http.ResponseWriter, r *http.Request) {
		if !h.checkMemberOrAdminAuth(w, r) {
			return
		}
		h.handlePoolUsers(w, r)
		return
	}},
	{http.MethodGet, "/api/pool/origins", "operator.read", func(h *proxyHandler, w http.ResponseWriter, r *http.Request) {
		if !h.checkMemberOrAdminAuth(w, r) {
			return
		}
		h.handlePoolOrigins(w, r)
		return
	}},
	{http.MethodGet, "/api/pool/daily-breakdown", "operator.read", func(h *proxyHandler, w http.ResponseWriter, r *http.Request) {
		if !h.checkMemberOrAdminAuth(w, r) {
			return
		}
		h.handleDailyBreakdown(w, r)
		return
	}},
	{http.MethodGet, "/api/pool/hourly", "operator.read", func(h *proxyHandler, w http.ResponseWriter, r *http.Request) {
		if !h.checkMemberOrAdminAuth(w, r) {
			return
		}
		h.handleGlobalHourly(w, r)
		return
	}},
	{http.MethodGet, "/api/pool/signal", "operator.read", func(h *proxyHandler, w http.ResponseWriter, r *http.Request) {
		if !h.checkMemberOrAdminAuth(w, r) {
			return
		}
		h.handleSignalAnalytics(w, r)
		return
	}},
	{http.MethodGet, "/api/pool/failure-insights", "operator.read", func(h *proxyHandler, w http.ResponseWriter, r *http.Request) {
		if !h.checkMemberOrAdminAuth(w, r) {
			return
		}
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		h.handlePoolFailureInsights(w, r)
		return
	}},
	{http.MethodGet, "/api/pool/catalog", "operator.read", func(h *proxyHandler, w http.ResponseWriter, r *http.Request) {
		if !h.checkMemberOrAdminAuth(w, r) {
			return
		}
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		servePoolModels(w, h.pool)
		return
	}},
	{http.MethodGet, "/api/me/usage", "operator.read", func(h *proxyHandler, w http.ResponseWriter, r *http.Request) {
		h.handlePassportUsage(w, r)
		return
	}},
	{http.MethodGet, "/api/pool/users/*/daily", "operator.read", func(h *proxyHandler, w http.ResponseWriter, r *http.Request) {
		if !h.checkMemberOrAdminAuth(w, r) {
			return
		}
		h.handleUserDaily(w, r)
	}},
	{http.MethodGet, "/api/pool/users/*/hourly", "operator.read", func(h *proxyHandler, w http.ResponseWriter, r *http.Request) {
		if !h.checkMemberOrAdminAuth(w, r) {
			return
		}
		h.handleUserHourly(w, r)
	}},
	{http.MethodGet, "/api/console/principals", "operator.read", func(h *proxyHandler, w http.ResponseWriter, r *http.Request) {
		h.handleConsolePrincipals(w, r)
		return
	}},
	{http.MethodGet, "/api/console/principals/*/usage", "operator.read", func(h *proxyHandler, w http.ResponseWriter, r *http.Request) {
		h.handleConsolePrincipalUsage(w, r)
	}},
	{http.MethodGet, "/api/console/audit", "operator.read", func(h *proxyHandler, w http.ResponseWriter, r *http.Request) {
		h.handleConsoleAudit(w, r)
		return
	}},
	{http.MethodGet, "/api/console/analytics-health", "operator.read", func(h *proxyHandler, w http.ResponseWriter, r *http.Request) {
		h.handleConsoleAnalyticsHealth(w, r)
		return
	}},
	{http.MethodGet, "/api/passes", "operator.read", func(h *proxyHandler, w http.ResponseWriter, r *http.Request) {
		h.handlePasses(w, r)
		return
	}},
	{http.MethodGet, "/admin/accounts", "operator.read", func(h *proxyHandler, w http.ResponseWriter, r *http.Request) {
		if !h.checkAdminAuth(w, r) {
			return
		}
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		h.serveAccounts(w, operatorAccessFromRequest(r) != nil)
		return
	}},
	{http.MethodGet, "/admin/tokens", "operator.read", func(h *proxyHandler, w http.ResponseWriter, r *http.Request) {
		if !h.checkAdminAuth(w, r) {
			return
		}
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		h.serveTokenCapacity(w, operatorAccessFromRequest(r) != nil)
		return
	}},
	{http.MethodPost, "/admin/reload", "operator.write", func(h *proxyHandler, w http.ResponseWriter, r *http.Request) {
		if !h.checkAdminAuth(w, r) {
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		h.reloadAccounts()
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
		return
	}},
	{http.MethodPost, "/admin/economics", "operator.write", func(h *proxyHandler, w http.ResponseWriter, r *http.Request) {
		if !h.checkAdminAuth(w, r) {
			return
		}
		h.handleEconomicsAdmin(w, r)
	}},
	{http.MethodPost, "/admin/clear-rate-limits", "operator.write", func(h *proxyHandler, w http.ResponseWriter, r *http.Request) {
		if !h.checkAdminAuth(w, r) {
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		h.clearAllRateLimits(w)
		return
	}},
	{http.MethodPost, "/admin/purge-anonymous", "operator.write", func(h *proxyHandler, w http.ResponseWriter, r *http.Request) {
		if !h.checkAdminAuth(w, r) {
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		h.purgeAnonymousUsers(w, operatorAccessFromRequest(r) != nil)
		return
	}},
	{http.MethodPost, "/admin/accounts/*/enable", "operator.write", func(h *proxyHandler, w http.ResponseWriter, r *http.Request) {
		h.handleAdminAccount(w, r)
	}},
	{http.MethodPost, "/admin/accounts/*/disable", "operator.write", func(h *proxyHandler, w http.ResponseWriter, r *http.Request) {
		h.handleAdminAccount(w, r)
	}},
	{http.MethodPost, "/admin/accounts/*/resurrect", "operator.write", func(h *proxyHandler, w http.ResponseWriter, r *http.Request) {
		h.handleAdminAccount(w, r)
	}},
	{http.MethodPost, "/admin/accounts/*/refresh", "operator.write", func(h *proxyHandler, w http.ResponseWriter, r *http.Request) {
		h.handleAdminAccount(w, r)
	}},
	{http.MethodPost, "/admin/antigravity/models/sync", "operator.write", func(h *proxyHandler, w http.ResponseWriter, r *http.Request) {
		if !h.checkAdminAuth(w, r) {
			return
		}
		if r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		h.handleAntigravityModelSync(w, r)
	}},
	{http.MethodPost, "/admin/antigravity/models/verify", "operator.write", func(h *proxyHandler, w http.ResponseWriter, r *http.Request) {
		if !h.checkAdminAuth(w, r) {
			return
		}
		if r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		h.handleAntigravityModelVerify(w, r)
	}},
	{http.MethodPost, "/api/console/members", "operator.write", func(h *proxyHandler, w http.ResponseWriter, r *http.Request) {
		h.handleConsoleMembers(w, r)
		return
	}},
	{http.MethodPost, "/api/passes", "operator.write", func(h *proxyHandler, w http.ResponseWriter, r *http.Request) {
		h.handlePasses(w, r)
		return
	}},
	{http.MethodPatch, "/api/passes/*", "operator.write", func(h *proxyHandler, w http.ResponseWriter, r *http.Request) {
		h.handlePassItem(w, r)
	}},
	{http.MethodDelete, "/api/passes/*", "operator.write", func(h *proxyHandler, w http.ResponseWriter, r *http.Request) {
		h.handlePassItem(w, r)
	}},
	{http.MethodPost, "/api/passes/*/restore", "operator.write", func(h *proxyHandler, w http.ResponseWriter, r *http.Request) {
		h.handlePassItem(w, r)
	}},
	{http.MethodPost, "/api/passes/*/rotate", "operator.write", func(h *proxyHandler, w http.ResponseWriter, r *http.Request) {
		h.handlePassItem(w, r)
	}},
	{http.MethodPatch, "/api/principals/*", "operator.write", func(h *proxyHandler, w http.ResponseWriter, r *http.Request) {
		h.handlePrincipalItem(w, r)
	}},
}

func (h *proxyHandler) dispatchOperatorRoute(w http.ResponseWriter, r *http.Request) bool {
	var fallback *operatorRoute
	for i := range operatorRoutes {
		route := &operatorRoutes[i]
		if !operatorPathMatches(route.Pattern, r.URL.Path) || (!strings.Contains(route.Pattern, "*") && route.Pattern != r.URL.Path) {
			continue
		}
		if route.Method == r.Method {
			route.serve(h, w, r)
			return true
		}
		if fallback == nil {
			fallback = route
		}
	}
	// Legacy cookie and break-glass handlers retain their own method responses.
	// Bearer authorization has already rejected unregistered methods.
	if fallback != nil {
		fallback.serve(h, w, r)
		return true
	}
	return false
}

func (h *proxyHandler) handleAdminAccount(w http.ResponseWriter, r *http.Request) {
	if !h.checkAdminAuth(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/admin/accounts/")
	separator := strings.LastIndex(path, "/")
	if separator < 0 {
		http.NotFound(w, r)
		return
	}
	publicID, action := path[:separator], path[separator+1:]
	accountID := h.resolveOperatorAccountID(r, publicID)
	switch action {
	case "enable", "disable":
		h.setAccountDisabled(w, accountID, action == "disable", publicID)
	case "resurrect":
		h.resurrectAccount(w, accountID, publicID)
	case "refresh":
		h.forceRefreshAccountWithSafety(w, accountID, operatorAccessFromRequest(r) != nil, publicID)
	default:
		http.NotFound(w, r)
	}
}

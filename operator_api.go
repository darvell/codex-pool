package main

import (
	"context"
	"crypto/subtle"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"go.etcd.io/bbolt"
)

const (
	bucketOperatorTokens = "operator_tokens"
	operatorTokenPrefix  = "poolop_"
	operatorScopeRead    = "read"
	operatorScopeWrite   = "write"
	operatorAPIVersion   = "v1"
)

type OperatorToken struct {
	ID          string     `json:"id"`
	PrincipalID string     `json:"principal_id"`
	Label       string     `json:"label"`
	Scope       string     `json:"scope"`
	Status      string     `json:"status"`
	CreatedAt   time.Time  `json:"created_at"`
	ExpiresAt   time.Time  `json:"expires_at"`
	LastUsedAt  *time.Time `json:"last_used_at,omitempty"`
}

type operatorTokenRecord struct {
	OperatorToken
	Digest string `json:"digest"`
}

type operatorAccess struct {
	Principal *Principal
	Token     *OperatorToken
}

type operatorAccessKey struct{}

func operatorAccessFromRequest(r *http.Request) *operatorAccess {
	access, _ := r.Context().Value(operatorAccessKey{}).(*operatorAccess)
	return access
}

func operatorActor(r *http.Request, fallback string) string {
	if access := operatorAccessFromRequest(r); access != nil {
		return access.Principal.ID + "#operator-token:" + access.Token.ID
	}
	return fallback
}

func operatorTokenPermissions(scope string) []string {
	if scope == operatorScopeWrite {
		return []string{"operator.read", "operator.write"}
	}
	return []string{"operator.read"}
}

func (p *PassportStore) createOperatorToken(actorID, principalID, label, scope string, expiresAt time.Time) (*OperatorToken, string, error) {
	label = strings.TrimSpace(label)
	if label == "" || len([]rune(label)) > 80 {
		return nil, "", errors.New("label required (max 80 characters)")
	}
	if scope != operatorScopeRead && scope != operatorScopeWrite {
		return nil, "", errors.New("scope must be read or write")
	}
	now := time.Now().UTC()
	if !expiresAt.After(now) || expiresAt.After(now.Add(366*24*time.Hour)) {
		return nil, "", errors.New("expiry must be in the future and no more than 366 days away")
	}
	owner := p.principal(principalID)
	if owner == nil || owner.Kind != PrincipalOperator || owner.Status != PrincipalActive {
		return nil, "", errors.New("active operator required")
	}
	id, err := secureID(9)
	if err != nil {
		return nil, "", err
	}
	secret, err := secureToken(32)
	if err != nil {
		return nil, "", err
	}
	token := operatorTokenPrefix + id + "_" + secret
	digest := hashToken(token)
	record := operatorTokenRecord{OperatorToken: OperatorToken{ID: id, PrincipalID: principalID, Label: label, Scope: scope, Status: "active", CreatedAt: now, ExpiresAt: expiresAt.UTC()}, Digest: hex.EncodeToString(digest[:])}
	err = p.db.Update(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket([]byte(bucketOperatorTokens))
		active := 0
		if err := bucket.ForEach(func(_, value []byte) error {
			var existing operatorTokenRecord
			if json.Unmarshal(value, &existing) == nil && existing.PrincipalID == principalID && existing.Status == "active" && existing.ExpiresAt.After(now) {
				active++
			}
			return nil
		}); err != nil {
			return err
		}
		if active >= 20 {
			return errors.New("operator token limit reached")
		}
		if err := putJSON(bucket, id, &record); err != nil {
			return err
		}
		return p.audit(tx, actorID, "operator_token.created", id, label+" ("+scope+")")
	})
	if err != nil {
		return nil, "", err
	}
	view := record.OperatorToken
	return &view, token, nil
}

func (p *PassportStore) listOperatorTokens(principalID string) ([]OperatorToken, error) {
	out := []OperatorToken{}
	now := time.Now()
	err := p.db.View(func(tx *bbolt.Tx) error {
		return tx.Bucket([]byte(bucketOperatorTokens)).ForEach(func(_, value []byte) error {
			var record operatorTokenRecord
			if err := json.Unmarshal(value, &record); err != nil {
				return err
			}
			if record.PrincipalID == principalID {
				view := record.OperatorToken
				if view.Status == "active" && !view.ExpiresAt.After(now) {
					view.Status = "expired"
				}
				out = append(out, view)
			}
			return nil
		})
	})
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, err
}

func (p *PassportStore) operatorToken(principalID, id string) (*OperatorToken, error) {
	var record operatorTokenRecord
	err := p.db.View(func(tx *bbolt.Tx) error {
		value := tx.Bucket([]byte(bucketOperatorTokens)).Get([]byte(id))
		if value == nil || json.Unmarshal(value, &record) != nil || record.PrincipalID != principalID {
			return errors.New("operator token not found")
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	view := record.OperatorToken
	return &view, nil
}

func (p *PassportStore) replaceOperatorToken(actorID, principalID, id string) (*OperatorToken, string, error) {
	old, err := p.operatorToken(principalID, id)
	if err != nil {
		return nil, "", err
	}
	if old.Status != "active" || !old.ExpiresAt.After(time.Now()) {
		return nil, "", errors.New("active operator token required")
	}
	duration := 90 * 24 * time.Hour
	if old.Scope == operatorScopeWrite {
		duration = 30 * 24 * time.Hour
	}
	newID, err := secureID(9)
	if err != nil {
		return nil, "", err
	}
	secret, err := secureToken(32)
	if err != nil {
		return nil, "", err
	}
	raw := operatorTokenPrefix + newID + "_" + secret
	digest := hashToken(raw)
	now := time.Now().UTC()
	replacement := operatorTokenRecord{OperatorToken: OperatorToken{ID: newID, PrincipalID: principalID, Label: old.Label, Scope: old.Scope, Status: "active", CreatedAt: now, ExpiresAt: now.Add(duration)}, Digest: hex.EncodeToString(digest[:])}
	err = p.db.Update(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket([]byte(bucketOperatorTokens))
		value := bucket.Get([]byte(id))
		if value == nil {
			return errors.New("operator token not found")
		}
		var current operatorTokenRecord
		if json.Unmarshal(value, &current) != nil || current.PrincipalID != principalID {
			return errors.New("operator token not found")
		}
		if current.Status != "active" || !current.ExpiresAt.After(now) {
			return errors.New("active operator token required")
		}
		current.Status = "revoked"
		if err := putJSON(bucket, id, &current); err != nil {
			return err
		}
		if err := putJSON(bucket, newID, &replacement); err != nil {
			return err
		}
		if err := p.audit(tx, actorID, "operator_token.replaced", id, newID); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return nil, "", err
	}
	view := replacement.OperatorToken
	return &view, raw, nil
}

func (p *PassportStore) revokeOperatorToken(actorID, principalID, id string) error {
	return p.db.Update(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket([]byte(bucketOperatorTokens))
		value := bucket.Get([]byte(id))
		if value == nil {
			return errors.New("operator token not found")
		}
		var record operatorTokenRecord
		if json.Unmarshal(value, &record) != nil || record.PrincipalID != principalID {
			return errors.New("operator token not found")
		}
		if record.Status == "revoked" {
			return nil
		}
		record.Status = "revoked"
		if err := putJSON(bucket, id, &record); err != nil {
			return err
		}
		return p.audit(tx, actorID, "operator_token.revoked", id, record.Label)
	})
}

func revokePrincipalOps(tx *bbolt.Tx, principalID string) error {
	bucket := tx.Bucket([]byte(bucketOperatorTokens))
	var records []operatorTokenRecord
	if err := bucket.ForEach(func(_, value []byte) error {
		var record operatorTokenRecord
		if err := json.Unmarshal(value, &record); err != nil {
			return err
		}
		if record.PrincipalID == principalID && record.Status == "active" {
			record.Status = "revoked"
			records = append(records, record)
		}
		return nil
	}); err != nil {
		return err
	}
	for _, record := range records {
		if err := putJSON(bucket, record.ID, &record); err != nil {
			return err
		}
	}
	return nil
}

func splitOperatorToken(raw string) (string, bool) {
	if !strings.HasPrefix(raw, operatorTokenPrefix) {
		return "", false
	}
	rest := strings.TrimPrefix(raw, operatorTokenPrefix)
	id, secret, ok := strings.Cut(rest, "_")
	return id, ok && id != "" && secret != ""
}

func (p *PassportStore) authenticateOperatorToken(raw string) (*Principal, *OperatorToken) {
	id, ok := splitOperatorToken(raw)
	if !ok {
		return nil, nil
	}
	var record operatorTokenRecord
	if p.db.View(func(tx *bbolt.Tx) error {
		value := tx.Bucket([]byte(bucketOperatorTokens)).Get([]byte(id))
		if value == nil {
			return errors.New("missing")
		}
		return json.Unmarshal(value, &record)
	}) != nil {
		return nil, nil
	}
	digest := hashToken(raw)
	got := hex.EncodeToString(digest[:])
	if subtle.ConstantTimeCompare([]byte(got), []byte(record.Digest)) != 1 || record.Status != "active" || !record.ExpiresAt.After(time.Now()) {
		return nil, nil
	}
	principal := p.principal(record.PrincipalID)
	if principal == nil || principal.Kind != PrincipalOperator || principal.Status != PrincipalActive || (principal.ExpiresAt != nil && time.Now().After(*principal.ExpiresAt)) || record.CreatedAt.Before(principal.CredentialsValidAfter) {
		return nil, nil
	}
	view := record.OperatorToken
	now := time.Now().UTC()
	if record.LastUsedAt == nil || now.Sub(*record.LastUsedAt) >= time.Minute {
		p.markOperatorTokenSeen(id, now)
		view.LastUsedAt = &now
	}
	return principal, &view
}

func (p *PassportStore) markOperatorTokenSeen(id string, now time.Time) {
	_ = p.db.Update(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket([]byte(bucketOperatorTokens))
		value := bucket.Get([]byte(id))
		if value == nil {
			return nil
		}
		var record operatorTokenRecord
		if json.Unmarshal(value, &record) != nil {
			return nil
		}
		if record.LastUsedAt != nil && now.Sub(*record.LastUsedAt) < time.Minute {
			return nil
		}
		record.LastUsedAt = &now
		return putJSON(bucket, id, &record)
	})
}

type operatorRoute struct{ Method, Pattern, Capability string }

var operatorRoutes = []operatorRoute{
	{http.MethodGet, "/api/operator/v1", "operator.read"},
	{http.MethodGet, "/api/operator/v1/whoami", "operator.read"},
	{http.MethodGet, "/api/operator/v1/openapi.json", "operator.read"},
	{http.MethodGet, "/api/operator/v1/guide", "operator.read"},
	{http.MethodGet, "/api/operator/v1/models", "operator.read"},
	{http.MethodGet, "/api/operator/v1/config/pi", "operator.read"},
	{http.MethodGet, "/api/operator/v1/accounting/requests", "operator.read"},
	{http.MethodGet, "/api/pool/stats", "operator.read"}, {http.MethodGet, "/api/pool/users", "operator.read"},
	{http.MethodGet, "/api/pool/origins", "operator.read"}, {http.MethodGet, "/api/pool/daily-breakdown", "operator.read"},
	{http.MethodGet, "/api/pool/hourly", "operator.read"}, {http.MethodGet, "/api/pool/signal", "operator.read"},
	{http.MethodGet, "/api/pool/catalog", "operator.read"}, {http.MethodGet, "/api/me/usage", "operator.read"}, {http.MethodGet, "/api/pool/users/*/daily", "operator.read"},
	{http.MethodGet, "/api/pool/users/*/hourly", "operator.read"}, {http.MethodGet, "/api/console/principals", "operator.read"},
	{http.MethodGet, "/api/console/principals/*/usage", "operator.read"}, {http.MethodGet, "/api/console/audit", "operator.read"},
	{http.MethodGet, "/api/console/analytics-health", "operator.read"}, {http.MethodGet, "/api/passes", "operator.read"},
	{http.MethodGet, "/admin/accounts", "operator.read"}, {http.MethodGet, "/admin/tokens", "operator.read"},
	{http.MethodPost, "/admin/reload", "operator.write"}, {http.MethodPost, "/admin/economics", "operator.write"},
	{http.MethodPost, "/admin/clear-rate-limits", "operator.write"}, {http.MethodPost, "/admin/purge-anonymous", "operator.write"},
	{http.MethodPost, "/admin/accounts/*/enable", "operator.write"}, {http.MethodPost, "/admin/accounts/*/disable", "operator.write"},
	{http.MethodPost, "/admin/accounts/*/resurrect", "operator.write"}, {http.MethodPost, "/admin/accounts/*/refresh", "operator.write"},
	{http.MethodPost, "/admin/antigravity/models/sync", "operator.write"}, {http.MethodPost, "/admin/antigravity/models/verify", "operator.write"},
	{http.MethodPost, "/api/console/members", "operator.write"}, {http.MethodPost, "/api/passes", "operator.write"},
	{http.MethodPatch, "/api/passes/*", "operator.write"}, {http.MethodDelete, "/api/passes/*", "operator.write"},
	{http.MethodPost, "/api/passes/*/restore", "operator.write"}, {http.MethodPost, "/api/passes/*/rotate", "operator.write"},
	{http.MethodPatch, "/api/principals/*", "operator.write"},
}

func operatorPathMatches(pattern, path string) bool {
	p, q := strings.Split(strings.Trim(pattern, "/"), "/"), strings.Split(strings.Trim(path, "/"), "/")
	if len(p) != len(q) {
		return false
	}
	for i := range p {
		if p[i] != "*" && p[i] != q[i] {
			return false
		}
	}
	return true
}

func operatorRouteCapability(method, path string) (string, bool) {
	for _, route := range operatorRoutes {
		if route.Method == method && operatorPathMatches(route.Pattern, path) {
			return route.Capability, true
		}
	}
	return "", false
}

func (h *proxyHandler) resolveOperatorAccountID(r *http.Request, id string) string {
	if operatorAccessFromRequest(r) == nil || h.pool == nil {
		return id
	}
	for _, account := range h.pool.allAccounts() {
		if hashAccountID(account.ID) == id {
			return account.ID
		}
	}
	return id
}

func (h *proxyHandler) authorizeOperatorBearer(w http.ResponseWriter, r *http.Request) bool {
	header := strings.TrimSpace(r.Header.Get("Authorization"))
	if header == "" {
		return true
	}
	capability, registered := operatorRouteCapability(r.Method, r.URL.Path)
	headerExclusive := registered || r.URL.Path == "/api/operator-tokens" || strings.HasPrefix(r.URL.Path, "/api/operator-tokens/")
	parts := strings.Fields(header)
	isBearer := len(parts) == 2 && strings.EqualFold(parts[0], "Bearer")
	looksOperator := strings.Contains(strings.ToLower(header), operatorTokenPrefix)
	// On routes exposed to operator credentials, any explicit Authorization
	// selects header authentication and may never borrow an ambient cookie or
	// break-glass header. On other routes, only operator-looking credentials are
	// intercepted so ordinary model bearer credentials still reach inference.
	if !headerExclusive && !looksOperator {
		return true
	}
	if !isBearer || !strings.HasPrefix(parts[1], operatorTokenPrefix) || h.passport == nil {
		respondJSONError(w, http.StatusUnauthorized, "valid operator token required")
		return false
	}
	principal, token := h.passport.authenticateOperatorToken(parts[1])
	if principal == nil {
		respondJSONError(w, http.StatusUnauthorized, "invalid or expired operator token")
		return false
	}
	if !registered {
		respondJSONError(w, http.StatusForbidden, "operator token is not permitted for this route")
		return false
	}
	if capability == "operator.write" && token.Scope != operatorScopeWrite {
		respondJSONError(w, http.StatusForbidden, "operator.write permission required")
		return false
	}
	access := &operatorAccess{Principal: principal, Token: token}
	*r = *r.WithContext(context.WithValue(r.Context(), operatorAccessKey{}, access))
	if capability == "operator.write" {
		if err := h.passport.recordAudit(operatorActor(r, principal.ID), "operator_api.write_attempt", token.ID, r.Method+" "+r.URL.Path); err != nil {
			respondJSONError(w, http.StatusServiceUnavailable, "operator audit unavailable")
			return false
		}
	}
	return true
}

func (h *proxyHandler) requireOperatorAPI(w http.ResponseWriter, r *http.Request) (*operatorAccess, bool) {
	if access := operatorAccessFromRequest(r); access != nil {
		return access, true
	}
	// A caller that supplied header credentials has chosen non-browser auth.
	// Never let an invalid/model bearer silently borrow an ambient cookie.
	if strings.TrimSpace(r.Header.Get("Authorization")) != "" {
		respondJSONError(w, http.StatusUnauthorized, "valid operator token required")
		return nil, false
	}
	if h.passport != nil {
		if principal, _ := h.passport.authenticate(r); principal != nil && principal.Kind == PrincipalOperator {
			return &operatorAccess{Principal: principal}, true
		}
	}
	respondJSONError(w, http.StatusUnauthorized, "operator authentication required")
	return nil, false
}

//go:embed docs/openapi/operator-v1.openapi.json
var operatorOpenAPI []byte

//go:embed docs/operator-api.md
var operatorGuide []byte

//go:embed docs/operator-api-reference.md
var operatorReference []byte

type operatorModelManifestEntry struct {
	poolModelDescriptor
	PricingStatus   string         `json:"pricing_status"`
	AdvertisedCost  *piModelCost   `json:"advertised_cost_per_million_tokens,omitempty"`
	PiConfiguration *piModelConfig `json:"pi_configuration,omitempty"`
	PiProviderKey   string         `json:"pi_provider_key,omitempty"`
	PiAPI           string         `json:"pi_api,omitempty"`
	PiSupported     bool           `json:"pi_supported"`
}

type operatorPiModel struct {
	Model piModelConfig
	API   string
}

func piProviderKeyForDescriptor(provider string) string {
	switch AccountType(provider) {
	case AccountTypeMistral:
		return "pool-mistral"
	case AccountTypeMistralVibe:
		return "pool-mistral-vibe"
	case AccountTypeOpencodeGo:
		return "opencode-go"
	default:
		return provider
	}
}

func operatorAdvertisedModelCost(model string, now time.Time) (*piModelCost, bool) {
	pricing, ok := publishedModelPricing(now)[canonicalPricingModel(model)]
	if !ok {
		return nil, false
	}
	return &piModelCost{Input: pricing.InputCostPerToken * 1_000_000, Output: pricing.OutputCostPerToken * 1_000_000, CacheRead: pricing.CacheReadCost * 1_000_000, CacheWrite: pricing.CacheWriteCost * 1_000_000}, true
}

func operatorModelManifest(pool *poolState, now time.Time) []operatorModelManifestEntry {
	piByProviderID := make(map[string]operatorPiModel)
	if data, err := generatePiModelsJSON("https://configured-public-url.invalid", "CODEX_POOL_MODEL_API_KEY", "CODEX_POOL_MODEL_API_KEY", pool); err == nil {
		var config piModelsConfig
		if json.Unmarshal(data, &config) == nil {
			for providerKey, provider := range config.Providers {
				for _, model := range provider.Models {
					piByProviderID[providerKey+"\x00"+model.ID] = operatorPiModel{Model: model, API: provider.API}
				}
			}
		}
	}
	descriptors := poolModelsForClients(pool)
	out := make([]operatorModelManifestEntry, 0, len(descriptors))
	for _, descriptor := range descriptors {
		pricingModel := descriptor.UpstreamID
		if pricingModel == "" {
			pricingModel = descriptor.ID
		}
		cost, known := operatorAdvertisedModelCost(pricingModel, now)
		entry := operatorModelManifestEntry{poolModelDescriptor: descriptor, PricingStatus: "unknown"}
		if known {
			entry.AdvertisedCost = cost
			entry.PricingStatus = "current_runtime_rate"
		}
		providerKey := piProviderKeyForDescriptor(descriptor.Provider)
		if piModel, ok := piByProviderID[providerKey+"\x00"+descriptor.ID]; ok {
			copy := piModel.Model
			entry.PiConfiguration = &copy
			entry.PiProviderKey = providerKey
			entry.PiAPI = piModel.API
			entry.PiSupported = true
		}
		out = append(out, entry)
	}
	return out
}

func operatorCatalogMode(w http.ResponseWriter, r *http.Request, defaultMode string) (string, bool) {
	mode := strings.TrimSpace(r.URL.Query().Get("catalog"))
	if mode == "" {
		mode = defaultMode
	}
	if mode != "full" && mode != "configured" {
		respondJSONError(w, 400, "catalog must be full or configured")
		return "", false
	}
	return mode, true
}

func (h *proxyHandler) handleOperatorAPI(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	access, ok := h.requireOperatorAPI(w, r)
	if !ok {
		return
	}
	switch r.URL.Path {
	case "/api/operator/v1":
		respondJSON(w, map[string]any{"api_version": operatorAPIVersion, "openapi": "/api/operator/v1/openapi.json", "guide": "/api/operator/v1/guide", "whoami": "/api/operator/v1/whoami", "models": "/api/operator/v1/models", "pi_config": "/api/operator/v1/config/pi", "accounting_requests": "/api/operator/v1/accounting/requests"})
	case "/api/operator/v1/whoami":
		response := map[string]any{"principal": publicPrincipal(access.Principal), "credential_kind": "browser_session", "permissions": []string{"operator.read", "operator.write"}}
		if access.Token != nil {
			response["credential_kind"] = "operator_token"
			response["token"] = access.Token
			response["permissions"] = operatorTokenPermissions(access.Token.Scope)
		}
		respondJSON(w, response)
	case "/api/operator/v1/openapi.json":
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(operatorOpenAPI)
	case "/api/operator/v1/guide":
		w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
		_, _ = w.Write(operatorGuide)
	case "/api/operator/v1/models":
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
	case "/api/operator/v1/config/pi":
		mode, ok := operatorCatalogMode(w, r, "configured")
		if !ok {
			return
		}
		publicURL := getPublicURL()
		if publicURL == "" {
			respondJSONError(w, http.StatusServiceUnavailable, "public_url must be configured for portable exports")
			return
		}
		data, err := generatePiModelsJSON(publicURL, "CODEX_POOL_MODEL_API_KEY", "CODEX_POOL_MODEL_API_KEY", h.pool)
		if err != nil {
			respondJSONError(w, 500, "failed to generate Pi configuration")
			return
		}
		if mode == "configured" {
			configured := map[string]bool{}
			for _, model := range poolModelsForClients(h.pool) {
				if model.SupportingAccounts > 0 {
					configured[piProviderKeyForDescriptor(model.Provider)+"\x00"+model.ID] = true
				}
			}
			var config piModelsConfig
			if json.Unmarshal(data, &config) == nil {
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
				data, _ = json.MarshalIndent(config, "", "  ")
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(data)
	case "/api/operator/v1/accounting/requests":
		h.handleOperatorAccountingRequests(w, r)
	default:
		http.NotFound(w, r)
	}
}

type accountingCursor struct {
	At time.Time `json:"at"`
	ID string    `json:"id"`
}

func encodeAccountingCursor(at time.Time, id string) string {
	data, _ := json.Marshal(accountingCursor{At: at, ID: id})
	return base64.RawURLEncoding.EncodeToString(data)
}
func decodeAccountingCursor(raw string) (*accountingCursor, error) {
	if raw == "" {
		return nil, nil
	}
	data, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return nil, err
	}
	var cursor accountingCursor
	if json.Unmarshal(data, &cursor) != nil || cursor.At.IsZero() || cursor.ID == "" {
		return nil, errors.New("invalid cursor")
	}
	return &cursor, nil
}

func (h *proxyHandler) handleOperatorAccountingRequests(w http.ResponseWriter, r *http.Request) {
	if h.duckAnalytics == nil {
		respondJSONError(w, http.StatusServiceUnavailable, "analytics unavailable")
		return
	}
	limit := 100
	if raw := r.URL.Query().Get("limit"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > 200 {
			respondJSONError(w, 400, "limit must be between 1 and 200")
			return
		}
		limit = parsed
	}
	to := time.Now().UTC()
	from := to.Add(-30 * 24 * time.Hour)
	if raw := r.URL.Query().Get("from"); raw != "" {
		parsed, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			respondJSONError(w, 400, "from must be RFC3339")
			return
		}
		from = parsed
	}
	if raw := r.URL.Query().Get("to"); raw != "" {
		parsed, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			respondJSONError(w, 400, "to must be RFC3339")
			return
		}
		to = parsed
	}
	if !from.Before(to) || to.Sub(from) > 366*24*time.Hour {
		respondJSONError(w, 400, "range must be positive and no more than 366 days")
		return
	}
	cursor, err := decodeAccountingCursor(r.URL.Query().Get("cursor"))
	if err != nil {
		respondJSONError(w, 400, "invalid cursor")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	rows, next, err := h.duckAnalytics.AccountingRequests(ctx, from, to, limit, cursor, r.URL.Query().Get("principal_id"), r.URL.Query().Get("provider"), r.URL.Query().Get("model"))
	if err != nil {
		respondJSONError(w, 500, "accounting query failed")
		return
	}
	respondJSON(w, map[string]any{"requests": rows, "next_cursor": next, "range": map[string]any{"from": from, "to": to}, "pricing_provenance_note": "pricing_version identifies calculation code only; historical rates and their source were not retained, so exact historical reconstruction is unavailable"})
}

func (h *proxyHandler) handleOperatorTokens(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	principal, session, ok := h.requireOperator(w, r)
	if !ok {
		return
	}
	if operatorAccessFromRequest(r) != nil {
		respondJSONError(w, http.StatusForbidden, "operator tokens cannot manage operator tokens")
		return
	}
	switch r.Method {
	case http.MethodGet:
		tokens, err := h.passport.listOperatorTokens(principal.ID)
		if err != nil {
			respondJSONError(w, 500, "operator tokens unavailable")
			return
		}
		respondJSON(w, tokens)
	case http.MethodPost:
		if !h.passportCSRF(r, session) {
			respondJSONError(w, 403, "csrf validation failed")
			return
		}
		if session.AuthenticatedAt.IsZero() || time.Since(session.AuthenticatedAt) > 15*time.Minute {
			respondJSONError(w, 403, "recent authentication required; sign in again")
			return
		}
		var input struct {
			Label     string     `json:"label"`
			Scope     string     `json:"scope"`
			ExpiresAt *time.Time `json:"expires_at"`
		}
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&input) != nil {
			respondJSONError(w, 400, "invalid json")
			return
		}
		duration := 90 * 24 * time.Hour
		if input.Scope == operatorScopeWrite {
			duration = 30 * 24 * time.Hour
		}
		expires := time.Now().UTC().Add(duration)
		if input.ExpiresAt != nil {
			expires = input.ExpiresAt.UTC()
		}
		token, secret, err := h.passport.createOperatorToken(principal.ID, principal.ID, input.Label, input.Scope, expires)
		if err != nil {
			respondJSONError(w, 400, err.Error())
			return
		}
		respondJSON(w, map[string]any{"token": token, "secret": secret})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (h *proxyHandler) handleOperatorTokenItem(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	principal, session, ok := h.requireOperator(w, r)
	if !ok {
		return
	}
	if operatorAccessFromRequest(r) != nil {
		respondJSONError(w, 403, "operator tokens cannot manage operator tokens")
		return
	}
	if !h.passportCSRF(r, session) {
		respondJSONError(w, 403, "csrf validation failed")
		return
	}
	path := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/operator-tokens/"), "/")
	id, action, _ := strings.Cut(path, "/")
	if id == "" || (action != "" && action != "replace") {
		http.NotFound(w, r)
		return
	}
	switch {
	case r.Method == http.MethodDelete && action == "":
		if err := h.passport.revokeOperatorToken(principal.ID, principal.ID, id); err != nil {
			respondJSONError(w, 404, err.Error())
			return
		}
		respondJSON(w, map[string]any{"success": true})
	case r.Method == http.MethodPost && action == "replace":
		if session.AuthenticatedAt.IsZero() || time.Since(session.AuthenticatedAt) > 15*time.Minute {
			respondJSONError(w, 403, "recent authentication required; sign in again")
			return
		}
		replacement, secret, err := h.passport.replaceOperatorToken(principal.ID, principal.ID, id)
		if err != nil {
			respondJSONError(w, 404, err.Error())
			return
		}
		respondJSON(w, map[string]any{"token": replacement, "secret": secret})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func validateOperatorOpenAPIRoutes() error {
	var spec struct {
		Paths map[string]map[string]json.RawMessage `json:"paths"`
	}
	if err := json.Unmarshal(operatorOpenAPI, &spec); err != nil {
		return err
	}
	registered := make(map[string]string, len(operatorRoutes))
	for _, route := range operatorRoutes {
		path := strings.ReplaceAll(route.Pattern, "*", "{id}")
		key := strings.ToLower(route.Method) + " " + path
		registered[key] = route.Capability
		raw, ok := spec.Paths[path][strings.ToLower(route.Method)]
		if !ok {
			return fmt.Errorf("operator route missing from OpenAPI: %s %s", route.Method, route.Pattern)
		}
		var operation struct {
			Capability string `json:"x-operator-capability"`
		}
		if json.Unmarshal(raw, &operation) != nil || operation.Capability != route.Capability {
			return fmt.Errorf("operator capability mismatch in OpenAPI: %s", key)
		}
	}
	reference := string(operatorReference)
	if !strings.Contains(reference, "Generated by scripts/render_operator_api_reference.py") {
		return errors.New("operator API reference is not generated")
	}
	for path, item := range spec.Paths {
		for method := range item {
			switch method {
			case "get", "post", "put", "patch", "delete", "head", "options":
			default:
				continue
			}
			if _, ok := registered[method+" "+path]; !ok {
				return fmt.Errorf("OpenAPI operation missing from operator registry: %s %s", strings.ToUpper(method), path)
			}
			row := "| `" + strings.ToUpper(method) + "` | `" + path + "` |"
			if !strings.Contains(reference, row) {
				return fmt.Errorf("generated operator API reference is stale: %s %s", strings.ToUpper(method), path)
			}
		}
	}
	return nil
}

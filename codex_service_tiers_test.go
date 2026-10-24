package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
)

func tierAccounts(t *testing.T) (*Account, *Account) {
	t.Helper()
	models, err := parseProviderModels([]byte(`{"models":[{"slug":"gpt-6-astra","service_tiers":[{"id":"priority","name":"Fast","description":"Fast processing"},{"id":"ultrafast","name":"Ultrafast","description":"Fastest processing"}]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	ordinary := &Account{ID: "ordinary", AccountID: "ordinary", Type: AccountTypeCodex, PlanType: "pro", AccessToken: "ordinary-token", Models: map[string]DiscoveredModel{
		"gpt-6-astra": {ID: "gpt-6-astra", ServiceTiers: []modelServiceTier{{ID: "priority", Name: "Fast"}}},
	}}
	eligible := &Account{ID: "eligible", AccountID: "eligible", Type: AccountTypeCodex, PlanType: "pro", AccessToken: "eligible-token", Models: models, Penalty: 10}
	return ordinary, eligible
}

func TestDiscoveredServiceTiersPersist(t *testing.T) {
	_, account := tierAccounts(t)
	data, err := json.Marshal(providerModelSnapshot{Models: account.Models})
	if err != nil {
		t.Fatal(err)
	}
	var restored providerModelSnapshot
	if err := json.Unmarshal(data, &restored); err != nil {
		t.Fatal(err)
	}
	account.Models = restored.Models
	if !accountSupportsTier(account, "gpt-6-astra[1m]", "ultrafast") || accountSupportsTier(account, "gpt-6.1-sol", "ultrafast") {
		t.Fatalf("restored tier entitlements = %+v", restored.Models)
	}
}

func TestTierSelectionHonorsPinAndExclusions(t *testing.T) {
	ordinary, eligible := tierAccounts(t)
	pool := newPoolState([]*Account{ordinary, eligible}, false)
	pool.pin("conversation", ordinary.ID)
	if got := pool.candidateForTier("conversation", nil, AccountTypeCodex, "", "", "gpt-6-astra[1m]", "ultrafast"); got != eligible {
		t.Fatalf("ultrafast candidate = %v, want eligible", got)
	}
	if got := pool.candidateForTier("conversation", map[string]bool{eligible.ID: true}, AccountTypeCodex, "", "", "gpt-6-astra", "ultrafast"); got != nil {
		t.Fatalf("exhausted ultrafast candidate = %v", got)
	}
	eligible.Disabled = true
	if got := pool.candidateForTier("", nil, AccountTypeCodex, "", "", "gpt-6-astra", "ultrafast"); got != nil {
		t.Fatalf("disabled ultrafast candidate = %v", got)
	}
	if got := pool.candidateForTier("", nil, AccountTypeCodex, "", "", "gpt-6-astra", "priority"); got != ordinary {
		t.Fatalf("ordinary Fast candidate = %v", got)
	}
}

func TestCatalogAggregatesVerifiedTiers(t *testing.T) {
	ordinary, eligible := tierAccounts(t)
	pool := newPoolState([]*Account{ordinary, eligible}, false)
	body := []byte(`{"extra":"preserved","models":[{"slug":"gpt-6-astra","context_window":272000,"service_tiers":[{"id":"priority","name":"Fast"}]},{"slug":"gpt-6-astra[1m]"},{"slug":"gpt-6.1-sol","service_tiers":[{"id":"ultrafast","name":"Ultrafast"}],"default_service_tier":"ultrafast"}]}`)
	for _, enabled := range []bool{true, false} {
		eligible.Disabled = !enabled
		var result struct {
			Extra  string `json:"extra"`
			Models []struct {
				Slug    string             `json:"slug"`
				Context int                `json:"context_window"`
				Tiers   []modelServiceTier `json:"service_tiers"`
				Default *string            `json:"default_service_tier"`
			} `json:"models"`
		}
		if err := json.Unmarshal(mergeCodexServiceTiers(body, pool), &result); err != nil {
			t.Fatal(err)
		}
		if result.Extra != "preserved" || result.Models[0].Context != 272000 {
			t.Fatalf("unrelated fields changed: %+v", result)
		}
		for _, model := range result.Models {
			hasUltra := false
			for _, tier := range model.Tiers {
				hasUltra = hasUltra || tier.ID == "ultrafast"
			}
			want := enabled && strings.HasPrefix(model.Slug, "gpt-6-astra")
			if hasUltra != want {
				t.Fatalf("%s ultrafast=%v, want %v", model.Slug, hasUltra, want)
			}
			if model.Slug == "gpt-6.1-sol" && model.Default != nil {
				t.Fatal("unsupported inherited default tier survived")
			}
		}
	}
}

func TestUltrafastHTTPRouting(t *testing.T) {
	t.Setenv("POOL_JWT_SECRET", "tier-test-secret")
	for _, mode := range []string{"memory", "disk", "exhausted", "failover"} {
		t.Run(mode, func(t *testing.T) {
			ordinary, eligible := tierAccounts(t)
			hits := []string{}
			h := preflightHandler(roundTripFunc(func(req *http.Request) (*http.Response, error) {
				id := req.Header.Get("ChatGPT-Account-ID")
				hits = append(hits, id)
				if id == ordinary.ID {
					t.Fatal("Ultrafast reached unentitled account")
				}
				data, err := io.ReadAll(req.Body)
				if err != nil {
					t.Fatal(err)
				}
				if serviceTierFromJSON(data) != "ultrafast" {
					t.Fatalf("tier not forwarded: %s", data)
				}
				if mode == "failover" && len(hits) == 1 {
					return nil, errors.New("temporary upstream failure")
				}
				return preflightReply(), nil
			}))
			accounts := []*Account{ordinary, eligible}
			if mode == "failover" {
				second := &Account{ID: "eligible-2", AccountID: "eligible-2", Type: AccountTypeCodex, PlanType: "pro", AccessToken: "second-token", Models: eligible.Models, Penalty: 20}
				accounts = append(accounts, second)
			}
			if mode == "exhausted" {
				eligible.Disabled = true
			}
			h.pool = newPoolState(accounts, false)
			h.cfg.disableRefresh = true
			h.cfg.maxSpoolBodyBytes = 1 << 20
			body := `{"model":"gpt-6-astra","stream":true,"input":"hello","service_tier":"ultrafast"}`
			req := httptest.NewRequest(http.MethodPost, "/v1/responses", strings.NewReader(body))
			if mode == "disk" {
				req.ContentLength = -1
			}
			req.Header.Set("Authorization", "Bearer "+generateClaudePoolToken("tier-test-secret", "tier-user"))
			req.Header.Set("Content-Type", "application/json")
			rr := httptest.NewRecorder()
			h.proxyRequest(rr, req, "tier-routing")
			wantStatus, wantHits := http.StatusOK, 1
			if mode == "exhausted" {
				wantStatus, wantHits = http.StatusServiceUnavailable, 0
			}
			if mode == "failover" {
				wantHits = 2
			}
			if rr.Code != wantStatus || len(hits) != wantHits {
				t.Fatalf("status=%d hits=%v body=%s", rr.Code, hits, rr.Body.String())
			}
		})
	}
}

func TestUltrafastWebSocketRouting(t *testing.T) {
	t.Setenv("POOL_JWT_SECRET", "tier-ws-secret")
	for _, mode := range []string{"hint", "late-selection", "nested", "tier-change", "unavailable"} {
		t.Run(mode, func(t *testing.T) {
			ordinary, eligible := tierAccounts(t)
			if mode == "unavailable" {
				eligible.Disabled = true
			}
			upstream := newFakeCodexUpstream(t)
			started := make(chan string, 2)
			upstream.on(ordinary.ID, func(ctx context.Context, conn *websocket.Conn) {
				started <- ordinary.ID
				_, data, err := conn.Read(ctx)
				if err == nil && serviceTierFromJSON(data) == "ultrafast" {
					t.Error("Ultrafast frame reached unentitled account")
				}
				if err == nil && mode == "tier-change" {
					_ = conn.Write(ctx, websocket.MessageText, []byte(`{"type":"response.completed","response":{"id":"resp_standard","status":"completed"}}`))
					_, data, err = conn.Read(ctx)
					if err == nil && serviceTierFromJSON(data) == "ultrafast" {
						t.Error("Tier change reached unentitled account")
					}
				}
			})
			upstream.on(eligible.ID, func(ctx context.Context, conn *websocket.Conn) {
				started <- eligible.ID
				_, data, err := conn.Read(ctx)
				if err != nil {
					return
				}
				if serviceTierFromJSON(data) != "ultrafast" {
					t.Errorf("tier missing from upstream frame: %s", data)
				}
				_ = conn.Write(ctx, websocket.MessageText, []byte(`{"type":"response.completed","response":{"id":"resp_tier","status":"completed"}}`))
				_, _, _ = conn.Read(ctx)
			})
			base, _ := url.Parse(upstream.server.URL)
			fx := newCodexProxyFixture(t, base, []*Account{ordinary, eligible})
			headers := http.Header{"Authorization": {"Bearer " + generateClaudePoolToken("tier-ws-secret", "tier-user")}}
			if mode == "hint" {
				headers.Set(codexRoutingHintHeader, "model=gpt-6-astra;tier=ultrafast")
			}
			conn := dialClientWS(t, fx, headers)
			// Join handler admission before sending/closing hijacked sockets.
			<-started
			frame := `{"type":"response.create","model":"gpt-6-astra","service_tier":"ultrafast","input":[]}`
			if mode == "nested" {
				frame = `{"type":"response.create","response":{"model":"gpt-6-astra","service_tier":"ultrafast","input":[]}}`
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if mode == "tier-change" {
				if err := conn.Write(ctx, websocket.MessageText, []byte(`{"type":"response.create","model":"gpt-6-astra","input":[]}`)); err != nil {
					t.Fatal(err)
				}
				_, data, err := conn.Read(ctx)
				if err != nil || !strings.Contains(string(data), "resp_standard") {
					t.Fatalf("standard response=%s err=%v", data, err)
				}
			}
			if err := conn.Write(ctx, websocket.MessageText, []byte(frame)); err != nil {
				t.Fatal(err)
			}
			_, data, err := conn.Read(ctx)
			if mode == "unavailable" {
				if err != nil || !strings.Contains(string(data), "service_tier_unavailable") || upstream.hitCount(eligible.ID) != 0 {
					t.Fatalf("unavailable response=%s err=%v", data, err)
				}
				return
			}
			if err != nil || !strings.Contains(string(data), "response.completed") {
				t.Fatalf("response=%s err=%v", data, err)
			}
			if mode != "hint" {
				<-started
			}
			if upstream.hitCount(eligible.ID) != 1 || (mode == "hint" && upstream.hitCount(ordinary.ID) != 0) {
				t.Fatalf("upstream connections: eligible=%d ordinary=%d", upstream.hitCount(eligible.ID), upstream.hitCount(ordinary.ID))
			}
		})
	}
}

func TestCodexCatalogPublishesTiers(t *testing.T) {
	t.Setenv("POOL_JWT_SECRET", "tier-catalog-secret")
	ordinary, eligible := tierAccounts(t)
	h := preflightHandler(roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK, Status: "200 OK",
			Header: http.Header{"Content-Type": {"application/json"}},
			Body:   io.NopCloser(strings.NewReader(`{"models":[{"slug":"gpt-6-astra","service_tiers":[{"id":"priority","name":"Fast"}]}]}`)),
		}, nil
	}))
	h.pool = newPoolState([]*Account{ordinary, eligible}, false)
	req := httptest.NewRequest(http.MethodGet, "/backend-api/codex/models?client_version=0.159.0", nil)
	req.Header.Set("Authorization", "Bearer "+generateClaudePoolToken("tier-catalog-secret", "tier-user"))
	rr := httptest.NewRecorder()
	h.proxyRequest(rr, req, "tier-catalog")
	if rr.Code != http.StatusOK {
		t.Fatalf("catalog status=%d body=%s", rr.Code, rr.Body.String())
	}
	var catalog struct {
		Models []struct {
			Slug  string             `json:"slug"`
			Tiers []modelServiceTier `json:"service_tiers"`
		} `json:"models"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &catalog); err != nil {
		t.Fatal(err)
	}
	found := 0
	for _, row := range catalog.Models {
		for _, tier := range row.Tiers {
			if tier.ID != "ultrafast" {
				continue
			}
			if row.Slug != "gpt-6-astra" && row.Slug != "gpt-6-astra[1m]" {
				t.Fatalf("ultrafast leaked into model %s", row.Slug)
			}
			found++
		}
	}
	if found != 2 {
		t.Fatalf("Ultrafast Astra catalog entries=%d, want 2", found)
	}
}

func TestCyberSwapRespectsServiceTier(t *testing.T) {
	ordinary, eligible := tierAccounts(t)
	ordinary.CyberAccess = true
	state := &codexRelayState{
		h:             &proxyHandler{pool: newPoolState([]*Account{ordinary, eligible}, false)},
		activeAccount: eligible,
		turns:         []*codexRelayTurn{{model: "gpt-6-astra", request: []byte(`{"service_tier":"ultrafast"}`)}},
	}
	if got := state.pickCyberAccessCandidate(); got != nil {
		t.Fatalf("cyber retry selected unentitled account %s", got.ID)
	}
}

func TestUltrafastWebSocketCannotFallback(t *testing.T) {
	ordinary, eligible := tierAccounts(t)
	pool := newPoolState([]*Account{ordinary, eligible}, false)
	eligible.Disabled = true
	state := &codexRelayState{h: &proxyHandler{pool: pool}, activeAccount: ordinary}
	_, err := state.inspectClient([]byte(`{"type":"response.create","model":"gpt-6-astra","service_tier":"ultrafast"}`))
	if err == nil || !strings.Contains(err.Error(), "service tier") || len(state.turns) != 0 {
		t.Fatalf("unsupported tier err=%v turns=%d", err, len(state.turns))
	}
}

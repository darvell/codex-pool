package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/html"
)

func TestStatusMistralRenderedCells(t *testing.T) {
	tests := []struct {
		name      string
		kind      AccountType
		plan      string
		usage     UsageSnapshot
		wantType  string
		primary   string
		secondary string
	}{
		{name: "vibe absent quota", kind: AccountTypeMistralVibe, plan: "individual", wantType: "Mistral Vibe", primary: "Not reported", secondary: "Not reported"},
		{name: "api absent quota", kind: AccountTypeMistral, plan: "individual", wantType: "Mistral API", primary: "Not reported", secondary: "Not reported"},
		{name: "primary reported zero", kind: AccountTypeMistralVibe, plan: "individual", usage: UsageSnapshot{PrimaryWindowMinutes: 300}, wantType: "Mistral Vibe", primary: "0%", secondary: "Not reported"},
		{name: "secondary reported zero", kind: AccountTypeMistral, plan: "individual", usage: UsageSnapshot{SecondaryResetAt: time.Now().Add(time.Hour)}, wantType: "Mistral API", primary: "Not reported", secondary: "0%"},
		{name: "reported percentages", kind: AccountTypeMistralVibe, plan: "individual", usage: UsageSnapshot{PrimaryUsedPercent: 0.25, SecondaryUsed: 0.5}, wantType: "Mistral Vibe", primary: "25%", secondary: "50%"},
		{name: "unknown escaped labels", kind: AccountType("<script>type</script>"), plan: "<script>plan</script>", wantType: "<script>type</script>", primary: "0%", secondary: "0%"},
		{name: "empty labels", wantType: "Unknown", primary: "0%", secondary: "0%"},
		{name: "existing codex", kind: AccountTypeCodex, plan: "pro", wantType: "codex", primary: "0%", secondary: "0%"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			account := &Account{ID: "mistral_vibe_f1f2db4c", Type: tt.kind, PlanType: tt.plan, Usage: tt.usage}
			h := &proxyHandler{pool: newPoolState([]*Account{account}, false), startTime: time.Now()}
			rr := httptest.NewRecorder()
			h.serveStatusPage(rr, httptest.NewRequest(http.MethodGet, "/status", nil))
			if rr.Code != http.StatusOK {
				t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
			}
			cells := statusRowCells(t, rr.Body.String(), account.ID)
			wantPlan := tt.plan
			if wantPlan == "" {
				wantPlan = "Unknown"
			}
			if cells[1] != tt.wantType || cells[2] != wantPlan {
				t.Errorf("type/plan = %q/%q, want %q/%q", cells[1], cells[2], tt.wantType, wantPlan)
			}
			for i, want := range []string{tt.primary, tt.secondary} {
				cell := cells[i+3]
				if !strings.Contains(cell, want) {
					t.Errorf("quota cell %d = %q, want %q", i, cell, want)
				}
				if want == "Not reported" && strings.Contains(cell, "%") {
					t.Errorf("unreported quota cell %d contains percentage: %q", i, cell)
				}
			}
			if strings.Contains(rr.Body.String(), "<script>") {
				t.Error("type or plan rendered as unescaped HTML")
			}
			if tt.kind == AccountTypeMistralVibe && !strings.Contains(rr.Body.String(), `<div class="stat-label">Mistral Vibe</div>`) {
				t.Error("missing Mistral Vibe provider summary")
			}
		})
	}
}

func statusRowCells(t *testing.T, body, id string) []string {
	t.Helper()
	root, err := html.Parse(strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	var text func(*html.Node) string
	text = func(n *html.Node) string {
		if n.Type == html.TextNode {
			return n.Data
		}
		var result string
		for child := n.FirstChild; child != nil; child = child.NextSibling {
			result += text(child)
		}
		return result
	}
	var cells []string
	var visit func(*html.Node)
	visit = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "tr" {
			var row []string
			for child := n.FirstChild; child != nil; child = child.NextSibling {
				if child.Type == html.ElementNode && child.Data == "td" {
					row = append(row, strings.TrimSpace(text(child)))
				}
			}
			if len(row) > 0 && row[0] == id {
				cells = row
			}
		}
		for child := n.FirstChild; child != nil; child = child.NextSibling {
			visit(child)
		}
	}
	visit(root)
	if len(cells) != 9 {
		t.Fatalf("account %q: got %d cells, want 9", id, len(cells))
	}
	return cells
}

func TestStatusJSONCountsMistralVibe(t *testing.T) {
	h := &proxyHandler{
		pool: newPoolState([]*Account{
			{ID: "vibe", Type: AccountTypeMistralVibe},
			{ID: "api", Type: AccountTypeMistral},
		}, false),
		startTime: time.Now(),
	}
	req := httptest.NewRequest(http.MethodGet, "/status", nil)
	req.Header.Set("Accept", "application/json")
	rr := httptest.NewRecorder()
	h.serveStatusPage(rr, req)
	var data struct {
		TotalCount       int
		MistralVibeCount int
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &data); err != nil {
		t.Fatal(err)
	}
	if rr.Code != http.StatusOK || data.TotalCount != 2 || data.MistralVibeCount != 1 {
		t.Fatalf("status = %d, counts = %+v", rr.Code, data)
	}
}

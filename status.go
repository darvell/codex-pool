package main

import (
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"sort"
	"time"
)

// StatusData contains all the data for the status page.
type StatusData struct {
	GeneratedAt time.Time
	Uptime      time.Duration
	TotalCount  int
	CodexCount  int
	GeminiCount int
	PoolUsers   int
	Accounts    []AccountStatus
}

// AccountStatus shows the status of a single account.
type AccountStatus struct {
	ID                 string
	Type               string
	PlanType           string
	Disabled           bool
	Dead               bool
	PrimaryUsed        float64
	SecondaryUsed      float64
	EffectivePrimary   float64 // After applying plan weight
	EffectiveSecondary float64
	PrimaryResetIn     string
	SecondaryResetIn   string
	ExpiresIn          string
	LastUsed           string
	Score              float64
	Inflight           int64
	TotalTokens        int64
}


func (h *proxyHandler) serveStatusPage(w http.ResponseWriter, r *http.Request) {
	h.pool.mu.RLock()
	defer h.pool.mu.RUnlock()

	now := time.Now()
	data := StatusData{
		GeneratedAt: now,
		Uptime:      now.Sub(h.startTime),
		TotalCount:  len(h.pool.accounts),
	}

	if h.poolUsers != nil {
		data.PoolUsers = len(h.poolUsers.List())
	}

	for _, a := range h.pool.accounts {
		a.mu.Lock()

		if a.Type == AccountTypeCodex {
			data.CodexCount++
		} else if a.Type == AccountTypeGemini {
			data.GeminiCount++
		}

		primaryUsed := a.Usage.PrimaryUsedPercent
		if primaryUsed == 0 {
			primaryUsed = a.Usage.PrimaryUsed
		}
		secondaryUsed := a.Usage.SecondaryUsedPercent
		if secondaryUsed == 0 {
			secondaryUsed = a.Usage.SecondaryUsed
		}

		// Apply plan weight for effective usage
		weight := planCapacityWeight(a.PlanType)
		effectivePrimary := primaryUsed * weight
		effectiveSecondary := secondaryUsed * weight
		if effectivePrimary > 1.0 {
			effectivePrimary = 1.0
		}
		if effectiveSecondary > 1.0 {
			effectiveSecondary = 1.0
		}

		status := AccountStatus{
			ID:                 a.ID,
			Type:               string(a.Type),
			PlanType:           a.PlanType,
			Disabled:           a.Disabled,
			Dead:               a.Dead,
			PrimaryUsed:        primaryUsed * 100,
			SecondaryUsed:      secondaryUsed * 100,
			EffectivePrimary:   effectivePrimary * 100,
			EffectiveSecondary: effectiveSecondary * 100,
			Score:              scoreAccountLocked(a, now),
			Inflight:           a.Inflight,
			TotalTokens:        a.Totals.TotalBillableTokens,
		}

		// Format time strings
		if !a.Usage.PrimaryResetAt.IsZero() && a.Usage.PrimaryResetAt.After(now) {
			status.PrimaryResetIn = formatDuration(a.Usage.PrimaryResetAt.Sub(now))
		} else if a.Usage.PrimaryWindowMinutes > 0 {
			status.PrimaryResetIn = fmt.Sprintf("~%dm", a.Usage.PrimaryWindowMinutes)
		}

		if !a.Usage.SecondaryResetAt.IsZero() && a.Usage.SecondaryResetAt.After(now) {
			status.SecondaryResetIn = formatDuration(a.Usage.SecondaryResetAt.Sub(now))
		} else if a.Usage.SecondaryWindowMinutes > 0 {
			status.SecondaryResetIn = fmt.Sprintf("~%dd", a.Usage.SecondaryWindowMinutes/60/24)
		}

		if !a.ExpiresAt.IsZero() {
			if a.ExpiresAt.Before(now) {
				status.ExpiresIn = "EXPIRED"
			} else {
				status.ExpiresIn = formatDuration(a.ExpiresAt.Sub(now))
			}
		}

		if !a.LastUsed.IsZero() {
			status.LastUsed = formatDuration(now.Sub(a.LastUsed)) + " ago"
		} else {
			status.LastUsed = "never"
		}

		a.mu.Unlock()
		data.Accounts = append(data.Accounts, status)
	}

	// Sort by score descending (best accounts first)
	sort.Slice(data.Accounts, func(i, j int) bool {
		return data.Accounts[i].Score > data.Accounts[j].Score
	})

	// Check Accept header for JSON
	if r.Header.Get("Accept") == "application/json" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(data)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	tmpl := template.Must(template.New("status").Funcs(template.FuncMap{
		"pct": func(v float64) string {
			return fmt.Sprintf("%.0f%%", v)
		},
		"score": func(v float64) string {
			return fmt.Sprintf("%.2f", v)
		},
		"bar": func(v float64) template.HTML {
			width := v
			if width > 100 {
				width = 100
			}
			color := "#4a4"
			if v > 80 {
				color = "#a44"
			} else if v > 50 {
				color = "#aa4"
			}
			return template.HTML(fmt.Sprintf(
				`<div class="bar"><div class="fill" style="width:%.0f%%;background:%s"></div></div>`,
				width, color,
			))
		},
	}).Parse(statusHTML))
	tmpl.Execute(w, data)
}

func formatDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm", int(d.Minutes()))
	}
	if d < 24*time.Hour {
		return fmt.Sprintf("%.1fh", d.Hours())
	}
	return fmt.Sprintf("%.1fd", d.Hours()/24)
}

const statusHTML = `<!DOCTYPE html>
<html>
<head>
    <title>Pool Status</title>
    <meta http-equiv="refresh" content="30">
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, monospace;
            margin: 0;
            padding: 20px;
            background: #0d1117;
            color: #c9d1d9;
        }
        h1 { color: #58a6ff; margin-bottom: 5px; }
        .meta { color: #8b949e; margin-bottom: 20px; font-size: 14px; }
        .stats {
            display: flex;
            gap: 20px;
            margin-bottom: 20px;
        }
        .stat {
            background: #161b22;
            padding: 15px 20px;
            border-radius: 6px;
            border: 1px solid #30363d;
        }
        .stat-value { font-size: 28px; font-weight: bold; color: #58a6ff; }
        .stat-label { font-size: 12px; color: #8b949e; text-transform: uppercase; }
        table {
            width: 100%;
            border-collapse: collapse;
            background: #161b22;
            border-radius: 6px;
            overflow: hidden;
        }
        th, td {
            padding: 10px 12px;
            text-align: left;
            border-bottom: 1px solid #21262d;
        }
        th {
            background: #21262d;
            color: #8b949e;
            font-weight: 500;
            font-size: 12px;
            text-transform: uppercase;
        }
        tr:hover { background: #1c2128; }
        .bar {
            width: 80px;
            height: 8px;
            background: #21262d;
            border-radius: 4px;
            overflow: hidden;
            display: inline-block;
            vertical-align: middle;
            margin-right: 8px;
        }
        .fill { height: 100%; }
        .status-ok { color: #3fb950; }
        .status-warn { color: #d29922; }
        .status-dead { color: #f85149; }
        .tag {
            display: inline-block;
            padding: 2px 6px;
            border-radius: 3px;
            font-size: 11px;
            font-weight: 500;
        }
        .tag-pro { background: #238636; color: #fff; }
        .tag-plus { background: #1f6feb; color: #fff; }
        .tag-team { background: #8957e5; color: #fff; }
        .tag-gemini { background: #ea4335; color: #fff; }
        .tag-codex { background: #10a37f; color: #fff; }
        .tag-disabled { background: #6e7681; color: #fff; }
        .tag-dead { background: #f85149; color: #fff; }
        .usage-cell { white-space: nowrap; }
        .effective { color: #8b949e; font-size: 11px; }
        a { color: #58a6ff; text-decoration: none; }
        a:hover { text-decoration: underline; }
    </style>
</head>
<body>
    <h1>🏊 Pool Status</h1>
    <div class="meta">
        Generated: {{.GeneratedAt.Format "2006-01-02 15:04:05"}} · Uptime: {{.Uptime.Round 1000000000}}
    </div>

    <div class="stats">
        <div class="stat">
            <div class="stat-value">{{.TotalCount}}</div>
            <div class="stat-label">Total Accounts</div>
        </div>
        <div class="stat">
            <div class="stat-value">{{.CodexCount}}</div>
            <div class="stat-label">Codex</div>
        </div>
        <div class="stat">
            <div class="stat-value">{{.GeminiCount}}</div>
            <div class="stat-label">Gemini</div>
        </div>
        {{if .PoolUsers}}
        <div class="stat">
            <div class="stat-value">{{.PoolUsers}}</div>
            <div class="stat-label">Pool Users</div>
        </div>
        {{end}}
    </div>

    <table>
        <tr>
            <th>Account</th>
            <th>Type</th>
            <th>Plan</th>
            <th>Primary (5h)</th>
            <th>Secondary (7d)</th>
            <th>Score</th>
            <th>Expires</th>
            <th>Last Used</th>
            <th>Tokens</th>
        </tr>
        {{range .Accounts}}
        <tr>
            <td>
                {{.ID}}
                {{if .Disabled}}<span class="tag tag-disabled">disabled</span>{{end}}
                {{if .Dead}}<span class="tag tag-dead">dead</span>{{end}}
            </td>
            <td>
                {{if eq .Type "codex"}}<span class="tag tag-codex">codex</span>{{end}}
                {{if eq .Type "gemini"}}<span class="tag tag-gemini">gemini</span>{{end}}
            </td>
            <td>
                {{if eq .PlanType "pro"}}<span class="tag tag-pro">pro</span>{{end}}
                {{if eq .PlanType "plus"}}<span class="tag tag-plus">plus</span>{{end}}
                {{if eq .PlanType "team"}}<span class="tag tag-team">team</span>{{end}}
                {{if eq .PlanType "gemini"}}<span class="tag tag-gemini">gemini</span>{{end}}
            </td>
            <td class="usage-cell">
                {{bar .EffectivePrimary}}{{pct .PrimaryUsed}}
                {{if ne .PlanType "pro"}}{{if ne .PlanType "gemini"}}<span class="effective">(→{{pct .EffectivePrimary}})</span>{{end}}{{end}}
                {{if .PrimaryResetIn}}<br><small>resets in {{.PrimaryResetIn}}</small>{{end}}
            </td>
            <td class="usage-cell">
                {{bar .EffectiveSecondary}}{{pct .SecondaryUsed}}
                {{if ne .PlanType "pro"}}{{if ne .PlanType "gemini"}}<span class="effective">(→{{pct .EffectiveSecondary}})</span>{{end}}{{end}}
                {{if .SecondaryResetIn}}<br><small>resets in {{.SecondaryResetIn}}</small>{{end}}
            </td>
            <td>
                {{if .Dead}}<span class="status-dead">—</span>
                {{else if .Disabled}}<span class="status-warn">—</span>
                {{else}}{{score .Score}}{{end}}
            </td>
            <td>{{.ExpiresIn}}</td>
            <td>{{.LastUsed}}</td>
            <td>{{.TotalTokens}}</td>
        </tr>
        {{end}}
    </table>

    <p style="margin-top: 20px; color: #8b949e; font-size: 12px;">
        <strong>Note:</strong> Plus accounts have ~10x less capacity than Pro.
        "Effective" usage shows the weighted value used for load balancing.
        <br>
        <a href="/admin/accounts">Raw account data</a> ·
        <a href="/healthz">Health check</a> ·
        <a href="/metrics">Prometheus metrics</a>
    </p>
</body>
</html>`

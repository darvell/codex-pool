package main

import (
	"encoding/json"
	"html/template"
	"log"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Claude account admin handlers

// In-memory store for pending OAuth sessions (should use a proper store in production)
var claudeOAuthSessions = struct {
	sync.RWMutex
	sessions map[string]*ClaudeOAuthSession
}{sessions: make(map[string]*ClaudeOAuthSession)}

func (h *proxyHandler) serveClaudeAdmin(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/admin/claude")
	if path == "" {
		path = "/"
	}

	switch {
	case path == "/" && r.Method == http.MethodGet:
		if !h.checkPoolAdminAuth(w, r) {
			return
		}
		h.serveClaudeAccountsList(w, r)

	case path == "/add" && r.Method == http.MethodGet:
		if !h.checkPoolAdminAuth(w, r) {
			return
		}
		h.serveClaudeAddForm(w, r)

	case path == "/add" && r.Method == http.MethodPost:
		if !h.checkPoolAdminAuth(w, r) {
			return
		}
		h.handleClaudeAddStart(w, r)

	case path == "/callback" && r.Method == http.MethodGet:
		// Callback doesn't need admin auth - uses session state
		h.handleClaudeOAuthCallback(w, r)

	case path == "/exchange" && r.Method == http.MethodPost:
		if !h.checkPoolAdminAuth(w, r) {
			return
		}
		h.handleClaudeExchange(w, r)

	case path == "/refresh-all" && r.Method == http.MethodPost:
		if !h.checkPoolAdminAuth(w, r) {
			return
		}
		h.handleClaudeRefreshAll(w, r)

	case strings.HasSuffix(path, "/refresh") && r.Method == http.MethodPost:
		if !h.checkPoolAdminAuth(w, r) {
			return
		}
		id := strings.TrimPrefix(path, "/")
		id = strings.TrimSuffix(id, "/refresh")
		h.handleClaudeRefresh(w, r, id)

	default:
		http.NotFound(w, r)
	}
}

func (h *proxyHandler) serveClaudeAccountsList(w http.ResponseWriter, r *http.Request) {
	accounts := h.pool.allAccounts()
	var claudeAccounts []*Account
	for _, acc := range accounts {
		if acc.Type == AccountTypeClaude {
			claudeAccounts = append(claudeAccounts, acc)
		}
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	tmpl := template.Must(template.New("list").Funcs(template.FuncMap{
		"isOAuth": func(token string) bool {
			return strings.HasPrefix(token, "sk-ant-oat")
		},
		"formatTime": func(t time.Time) string {
			if t.IsZero() {
				return "never"
			}
			return t.Format("2006-01-02 15:04")
		},
		"timeUntil": func(t time.Time) string {
			if t.IsZero() {
				return "unknown"
			}
			d := time.Until(t)
			if d < 0 {
				return "expired"
			}
			if d < time.Hour {
				return d.Round(time.Minute).String()
			}
			return d.Round(time.Hour).String()
		},
	}).Parse(claudeAccountsListHTML))
	tmpl.Execute(w, map[string]any{
		"Accounts": claudeAccounts,
	})
}

func (h *proxyHandler) serveClaudeAddForm(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	tmpl := template.Must(template.New("add").Parse(claudeAddFormHTML))
	tmpl.Execute(w, nil)
}

func (h *proxyHandler) handleClaudeAddStart(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	accountID := strings.TrimSpace(r.FormValue("account_id"))
	if accountID == "" {
		accountID = "claude_" + randomHex(8)
	}

	// Generate OAuth URL
	authURL, session, err := ClaudeAuthorize(accountID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Store session
	claudeOAuthSessions.Lock()
	claudeOAuthSessions.sessions[session.PKCE.Verifier] = session
	claudeOAuthSessions.Unlock()

	// Clean up old sessions (older than 10 minutes)
	go cleanupOldSessions()

	// Show the authorization page with instructions
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	tmpl := template.Must(template.New("auth").Parse(claudeAuthStartHTML))
	tmpl.Execute(w, map[string]any{
		"AuthURL":   authURL,
		"AccountID": accountID,
		"Verifier":  session.PKCE.Verifier,
	})
}

func (h *proxyHandler) handleClaudeOAuthCallback(w http.ResponseWriter, r *http.Request) {
	// This is shown when the user comes back from Anthropic
	// They need to copy the code and paste it
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	tmpl := template.Must(template.New("callback").Parse(claudeCallbackHTML))
	tmpl.Execute(w, map[string]any{
		"Code":  code,
		"State": state,
	})
}

func (h *proxyHandler) handleClaudeExchange(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	code := strings.TrimSpace(r.FormValue("code"))
	verifier := strings.TrimSpace(r.FormValue("verifier"))

	if code == "" || verifier == "" {
		http.Error(w, "code and verifier are required", http.StatusBadRequest)
		return
	}

	// Look up session
	claudeOAuthSessions.RLock()
	session, ok := claudeOAuthSessions.sessions[verifier]
	claudeOAuthSessions.RUnlock()

	if !ok {
		http.Error(w, "invalid or expired session", http.StatusBadRequest)
		return
	}

	// Exchange code for tokens
	tokens, err := ClaudeExchange(code, verifier)
	if err != nil {
		log.Printf("Claude token exchange failed: %v", err)
		http.Error(w, "Token exchange failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Save the account
	if err := SaveClaudeAccount(h.cfg.poolDir, session.AccountID, tokens); err != nil {
		http.Error(w, "Failed to save account: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Remove session
	claudeOAuthSessions.Lock()
	delete(claudeOAuthSessions.sessions, verifier)
	claudeOAuthSessions.Unlock()

	// Reload accounts
	h.reloadAccounts()

	// Show success
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	tmpl := template.Must(template.New("success").Parse(claudeAddSuccessHTML))
	tmpl.Execute(w, map[string]any{
		"AccountID": session.AccountID,
	})
}

func (h *proxyHandler) handleClaudeRefresh(w http.ResponseWriter, r *http.Request, accountID string) {
	accounts := h.pool.allAccounts()
	var target *Account
	for _, acc := range accounts {
		if acc.Type == AccountTypeClaude && acc.ID == accountID {
			target = acc
			break
		}
	}

	if target == nil {
		http.Error(w, "account not found", http.StatusNotFound)
		return
	}

	if err := RefreshClaudeAccountTokens(target); err != nil {
		http.Error(w, "refresh failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/admin/claude", http.StatusSeeOther)
}

func (h *proxyHandler) handleClaudeRefreshAll(w http.ResponseWriter, r *http.Request) {
	accounts := h.pool.allAccounts()
	var refreshed, failed int

	for _, acc := range accounts {
		if acc.Type != AccountTypeClaude {
			continue
		}
		// Only refresh OAuth tokens
		if !strings.HasPrefix(acc.AccessToken, "sk-ant-oat") {
			continue
		}
		if acc.RefreshToken == "" {
			continue
		}

		if err := RefreshClaudeAccountTokens(acc); err != nil {
			log.Printf("Failed to refresh Claude account %s: %v", acc.ID, err)
			failed++
		} else {
			refreshed++
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"refreshed": refreshed,
		"failed":    failed,
	})
}

func cleanupOldSessions() {
	claudeOAuthSessions.Lock()
	defer claudeOAuthSessions.Unlock()

	now := time.Now()
	for verifier, session := range claudeOAuthSessions.sessions {
		if now.Sub(session.CreatedAt) > 10*time.Minute {
			delete(claudeOAuthSessions.sessions, verifier)
		}
	}
}

// HTML Templates

const claudeAccountsListHTML = `<!DOCTYPE html>
<html>
<head>
    <title>Claude Accounts</title>
    <style>
        body { font-family: monospace; margin: 20px; background: #1a1a1a; color: #e0e0e0; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #444; padding: 8px; text-align: left; }
        th { background: #2a2a2a; }
        tr:nth-child(even) { background: #222; }
        a { color: #6af; }
        .btn { background: #444; color: #fff; border: none; padding: 5px 10px; cursor: pointer; text-decoration: none; display: inline-block; }
        .btn:hover { background: #555; }
        .btn-primary { background: #4a4; }
        .btn-primary:hover { background: #5b5; }
        .dead { color: #f66; }
        .healthy { color: #6f6; }
        .expired { color: #fa0; }
        .api-key { color: #aaa; }
        .oauth { color: #6af; }
    </style>
</head>
<body>
    <h1>Claude Accounts</h1>
    <p>
        <a href="/admin/claude/add" class="btn btn-primary">+ Add Claude Account</a>
        <form method="POST" action="/admin/claude/refresh-all" style="display:inline; margin-left: 10px;">
            <button class="btn" type="submit">Refresh All OAuth Tokens</button>
        </form>
    </p>
    <table>
        <tr>
            <th>ID</th>
            <th>Type</th>
            <th>Plan</th>
            <th>Status</th>
            <th>Expires</th>
            <th>Last Refresh</th>
            <th>Actions</th>
        </tr>
        {{range .Accounts}}
        <tr>
            <td>{{.ID}}</td>
            <td>{{if isOAuth .AccessToken}}<span class="oauth">OAuth</span>{{else}}<span class="api-key">API Key</span>{{end}}</td>
            <td>{{.PlanType}}</td>
            <td>{{if .Dead}}<span class="dead">Dead</span>{{else if .Disabled}}<span class="expired">Disabled</span>{{else}}<span class="healthy">Healthy</span>{{end}}</td>
            <td>{{timeUntil .ExpiresAt}}</td>
            <td>{{formatTime .LastRefresh}}</td>
            <td>
                {{if isOAuth .AccessToken}}
                <form method="POST" action="/admin/claude/{{.ID}}/refresh" style="display:inline">
                    <button class="btn" type="submit">Refresh</button>
                </form>
                {{else}}
                <span class="api-key">N/A</span>
                {{end}}
            </td>
        </tr>
        {{else}}
        <tr><td colspan="7">No Claude accounts yet. <a href="/admin/claude/add">Add one</a>.</td></tr>
        {{end}}
    </table>
    <p style="margin-top: 20px;"><a href="/admin/accounts">&larr; Back to all accounts</a></p>
</body>
</html>`

const claudeAddFormHTML = `<!DOCTYPE html>
<html>
<head>
    <title>Add Claude Account</title>
    <style>
        body { font-family: monospace; margin: 20px; background: #1a1a1a; color: #e0e0e0; }
        input { padding: 8px; margin: 5px 0; background: #2a2a2a; color: #e0e0e0; border: 1px solid #444; width: 300px; }
        button { background: #4a4; color: #fff; border: none; padding: 10px 20px; cursor: pointer; margin-top: 10px; }
        button:hover { background: #5b5; }
        a { color: #6af; }
        label { display: block; margin-top: 10px; }
        .note { color: #888; font-size: 0.9em; margin-top: 5px; }
    </style>
</head>
<body>
    <h1>Add Claude Account</h1>
    <p><a href="/admin/claude">&larr; Back to list</a></p>

    <p>This will start the OAuth flow to add a Claude account with your Claude.ai subscription.</p>

    <form method="POST">
        <label>Account ID (optional):
            <input type="text" name="account_id" placeholder="e.g., claude_myaccount">
            <div class="note">If empty, a random ID will be generated</div>
        </label>
        <br>
        <button type="submit">Start OAuth Flow</button>
    </form>
</body>
</html>`

const claudeAuthStartHTML = `<!DOCTYPE html>
<html>
<head>
    <title>Authorize Claude Account</title>
    <style>
        body { font-family: monospace; margin: 20px; background: #1a1a1a; color: #e0e0e0; }
        a { color: #6af; }
        pre { background: #2a2a2a; padding: 15px; overflow-x: auto; border: 1px solid #444; }
        code { color: #8f8; }
        .btn { background: #4a4; color: #fff; border: none; padding: 10px 20px; cursor: pointer; text-decoration: none; display: inline-block; }
        .btn:hover { background: #5b5; }
        .step { margin: 20px 0; padding: 15px; background: #222; border-radius: 5px; }
        .step h3 { color: #6af; margin-top: 0; }
        input { padding: 8px; margin: 5px 0; background: #2a2a2a; color: #e0e0e0; border: 1px solid #444; width: 100%; box-sizing: border-box; }
        textarea { padding: 8px; margin: 5px 0; background: #2a2a2a; color: #e0e0e0; border: 1px solid #444; width: 100%; box-sizing: border-box; font-family: monospace; }
        button { background: #4a4; color: #fff; border: none; padding: 10px 20px; cursor: pointer; margin-top: 10px; }
        button:hover { background: #5b5; }
    </style>
</head>
<body>
    <h1>Authorize Claude Account: {{.AccountID}}</h1>

    <div class="step">
        <h3>Step 1: Authorize with Anthropic</h3>
        <p>Click the button below to open the Anthropic authorization page in a new tab:</p>
        <p><a href="{{.AuthURL}}" target="_blank" class="btn">Open Anthropic Authorization</a></p>
    </div>

    <div class="step">
        <h3>Step 2: Complete Authorization</h3>
        <p>After logging in and authorizing, you'll be redirected to a page that shows a code.</p>
        <p>Copy the <strong>entire URL</strong> or just the <strong>code</strong> parameter from the URL.</p>
    </div>

    <div class="step">
        <h3>Step 3: Enter the Code</h3>
        <form method="POST" action="/admin/claude/exchange">
            <input type="hidden" name="verifier" value="{{.Verifier}}">
            <label>Authorization Code:
                <textarea name="code" rows="3" placeholder="Paste the code here (e.g., ant_oc_xxx#verifier or just the code part)"></textarea>
            </label>
            <br>
            <button type="submit">Complete Setup</button>
        </form>
    </div>

    <p><a href="/admin/claude">&larr; Cancel</a></p>
</body>
</html>`

const claudeCallbackHTML = `<!DOCTYPE html>
<html>
<head>
    <title>OAuth Callback</title>
    <style>
        body { font-family: monospace; margin: 20px; background: #1a1a1a; color: #e0e0e0; }
        pre { background: #2a2a2a; padding: 15px; overflow-x: auto; border: 1px solid #444; }
        code { color: #8f8; }
    </style>
</head>
<body>
    <h1>Authorization Code Received</h1>
    {{if .Code}}
    <p>Your authorization code:</p>
    <pre><code>{{.Code}}{{if .State}}#{{.State}}{{end}}</code></pre>
    <p>Copy this code and paste it in the authorization form.</p>
    {{else}}
    <p>No code received. Please try the authorization flow again.</p>
    {{end}}
</body>
</html>`

const claudeAddSuccessHTML = `<!DOCTYPE html>
<html>
<head>
    <title>Claude Account Added</title>
    <style>
        body { font-family: monospace; margin: 20px; background: #1a1a1a; color: #e0e0e0; }
        a { color: #6af; }
        .success { color: #6f6; font-size: 1.2em; }
    </style>
</head>
<body>
    <h1>Claude Account Added</h1>
    <p class="success">Successfully added Claude account: {{.AccountID}}</p>
    <p>The pool has been reloaded and the new account is now active.</p>
    <p><a href="/admin/claude">&larr; Back to Claude Accounts</a></p>
</body>
</html>`

// randomHex is already defined in pool_users.go, but we need it here too
func init() {
	// Ensure the pool/claude directory exists
	_ = filepath.Join("pool", "claude")
}

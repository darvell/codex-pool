package main

import (
	"encoding/json"
	"html/template"
	"net/http"
	"strings"
	"time"
)

// Pool user admin handlers

func (h *proxyHandler) checkPoolAdminAuth(w http.ResponseWriter, r *http.Request) bool {
	password := getPoolAdminPassword()
	if password == "" {
		http.Error(w, "pool user admin not configured (set POOL_ADMIN_PASSWORD)", http.StatusServiceUnavailable)
		return false
	}

	user, pass, ok := r.BasicAuth()
	if !ok || (user != "admin" && user != "") || pass != password {
		w.Header().Set("WWW-Authenticate", `Basic realm="Pool Admin"`)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return false
	}
	return true
}

func (h *proxyHandler) servePoolUsersAdmin(w http.ResponseWriter, r *http.Request) {
	if h.poolUsers == nil {
		http.Error(w, "pool users not configured", http.StatusServiceUnavailable)
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/admin/pool-users")
	if path == "" {
		path = "/"
	}

	switch {
	case path == "/" && r.Method == http.MethodGet:
		if !h.checkPoolAdminAuth(w, r) {
			return
		}
		h.servePoolUsersList(w, r)
	case path == "/create" && r.Method == http.MethodGet:
		if !h.checkPoolAdminAuth(w, r) {
			return
		}
		h.servePoolUsersCreateForm(w, r)
	case path == "/create" && r.Method == http.MethodPost:
		if !h.checkPoolAdminAuth(w, r) {
			return
		}
		h.handlePoolUsersCreate(w, r)
	case strings.HasPrefix(path, "/") && strings.HasSuffix(path, "/disable") && r.Method == http.MethodPost:
		if !h.checkPoolAdminAuth(w, r) {
			return
		}
		id := strings.TrimPrefix(path, "/")
		id = strings.TrimSuffix(id, "/disable")
		h.handlePoolUserDisable(w, r, id)
	default:
		http.NotFound(w, r)
	}
}

func (h *proxyHandler) servePoolUsersList(w http.ResponseWriter, r *http.Request) {
	users := h.poolUsers.List()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	tmpl := template.Must(template.New("list").Parse(poolUsersListHTML))
	tmpl.Execute(w, map[string]any{
		"Users": users,
	})
}

func (h *proxyHandler) servePoolUsersCreateForm(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	tmpl := template.Must(template.New("create").Parse(poolUsersCreateHTML))
	tmpl.Execute(w, nil)
}

func (h *proxyHandler) handlePoolUsersCreate(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	email := strings.TrimSpace(r.FormValue("email"))
	planType := r.FormValue("plan_type")
	if planType == "" {
		planType = "pro"
	}

	if email == "" {
		http.Error(w, "email is required", http.StatusBadRequest)
		return
	}

	user := &PoolUser{
		ID:        randomHex(16),
		Token:     randomHex(32),
		Email:     email,
		PlanType:  planType,
		CreatedAt: time.Now(),
	}

	if err := h.poolUsers.Create(user); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Generate the setup page
	baseURL := getPublicURL()
	if baseURL == "" {
		host := r.Host
		if host == "" {
			host = "PROXY_HOST:8989"
		}
		baseURL = "http://" + host
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	tmpl := template.Must(template.New("created").Parse(poolUsersCreatedHTML))
	tmpl.Execute(w, map[string]any{
		"User":    user,
		"BaseURL": baseURL,
		"Token":   user.Token,
	})
}

func (h *proxyHandler) handlePoolUserDisable(w http.ResponseWriter, r *http.Request, id string) {
	if err := h.poolUsers.Disable(id); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	http.Redirect(w, r, "/admin/pool-users", http.StatusSeeOther)
}

// Config download endpoints (no auth - token IS the auth)

func (h *proxyHandler) serveConfigDownload(w http.ResponseWriter, r *http.Request) {
	if h.poolUsers == nil {
		http.Error(w, "pool users not configured", http.StatusServiceUnavailable)
		return
	}

	path := r.URL.Path
	var configType string
	var token string

	switch {
	case strings.HasPrefix(path, "/config/codex/"):
		configType = "codex"
		token = strings.TrimPrefix(path, "/config/codex/")
	case strings.HasPrefix(path, "/config/gemini/"):
		configType = "gemini"
		token = strings.TrimPrefix(path, "/config/gemini/")
	default:
		http.NotFound(w, r)
		return
	}

	token = strings.TrimSuffix(token, "/")
	if token == "" {
		http.Error(w, "token required", http.StatusBadRequest)
		return
	}

	user := h.poolUsers.GetByToken(token)
	if user == nil {
		http.Error(w, "invalid token", http.StatusNotFound)
		return
	}
	if user.Disabled {
		http.Error(w, "user disabled", http.StatusForbidden)
		return
	}

	secret := getPoolJWTSecret()
	if secret == "" {
		http.Error(w, "JWT secret not configured", http.StatusServiceUnavailable)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	switch configType {
	case "codex":
		auth, err := generateCodexAuth(secret, user)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(auth)
	case "gemini":
		auth, err := generateGeminiAuth(secret, user)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(auth)
	}
}

// HTML Templates

const poolUsersListHTML = `<!DOCTYPE html>
<html>
<head>
    <title>Pool Users</title>
    <style>
        body { font-family: monospace; margin: 20px; background: #1a1a1a; color: #e0e0e0; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #444; padding: 8px; text-align: left; }
        th { background: #2a2a2a; }
        tr:nth-child(even) { background: #222; }
        a { color: #6af; }
        .btn { background: #444; color: #fff; border: none; padding: 5px 10px; cursor: pointer; }
        .btn:hover { background: #555; }
        .disabled { color: #f66; }
    </style>
</head>
<body>
    <h1>Pool Users</h1>
    <p><a href="/admin/pool-users/create">+ Create New User</a></p>
    <table>
        <tr>
            <th>Email</th>
            <th>Plan</th>
            <th>Created</th>
            <th>Status</th>
            <th>Actions</th>
        </tr>
        {{range .Users}}
        <tr>
            <td>{{.Email}}</td>
            <td>{{.PlanType}}</td>
            <td>{{.CreatedAt.Format "2006-01-02 15:04"}}</td>
            <td>{{if .Disabled}}<span class="disabled">Disabled</span>{{else}}Active{{end}}</td>
            <td>
                {{if not .Disabled}}
                <form method="POST" action="/admin/pool-users/{{.ID}}/disable" style="display:inline">
                    <button class="btn" type="submit">Disable</button>
                </form>
                {{end}}
            </td>
        </tr>
        {{else}}
        <tr><td colspan="5">No users yet</td></tr>
        {{end}}
    </table>
</body>
</html>`

const poolUsersCreateHTML = `<!DOCTYPE html>
<html>
<head>
    <title>Create Pool User</title>
    <style>
        body { font-family: monospace; margin: 20px; background: #1a1a1a; color: #e0e0e0; }
        input, select { padding: 8px; margin: 5px 0; background: #2a2a2a; color: #e0e0e0; border: 1px solid #444; }
        button { background: #4a4; color: #fff; border: none; padding: 10px 20px; cursor: pointer; margin-top: 10px; }
        button:hover { background: #5b5; }
        a { color: #6af; }
        label { display: block; margin-top: 10px; }
    </style>
</head>
<body>
    <h1>Create Pool User</h1>
    <p><a href="/admin/pool-users">&larr; Back to list</a></p>
    <form method="POST">
        <label>Email:
            <input type="email" name="email" required placeholder="user@example.com" style="width: 300px;">
        </label>
        <label>Plan Type (Codex):
            <select name="plan_type">
                <option value="pro">Pro</option>
                <option value="team">Team</option>
                <option value="plus">Plus</option>
            </select>
        </label>
        <br>
        <button type="submit">Create User</button>
    </form>
</body>
</html>`

const poolUsersCreatedHTML = `<!DOCTYPE html>
<html>
<head>
    <title>User Created</title>
    <style>
        body { font-family: monospace; margin: 20px; background: #1a1a1a; color: #e0e0e0; }
        pre { background: #2a2a2a; padding: 15px; overflow-x: auto; border: 1px solid #444; }
        code { color: #8f8; }
        h2 { color: #6af; border-bottom: 1px solid #444; padding-bottom: 10px; }
        a { color: #6af; }
        .section { margin: 20px 0; padding: 15px; background: #222; border-radius: 5px; }
    </style>
</head>
<body>
    <h1>User Created: {{.User.Email}}</h1>
    <p><a href="/admin/pool-users">&larr; Back to list</a></p>

    <div class="section">
        <h2>Codex CLI Setup</h2>
        <p>1. Download auth file:</p>
        <pre><code>curl {{.BaseURL}}/config/codex/{{.Token}} > ~/.codex/auth.json</code></pre>

        <p>2. Add to <code>~/.codex/config.toml</code>:</p>
        <pre><code>model_provider = "codex-pool"
chatgpt_base_url = "{{.BaseURL}}/backend-api"

[model_providers.codex-pool]
name = "OpenAI via codex-pool proxy"
base_url = "{{.BaseURL}}/v1"
wire_api = "responses"
requires_openai_auth = true</code></pre>
    </div>

    <div class="section">
        <h2>Gemini CLI Setup</h2>
        <p>1. Download auth file:</p>
        <pre><code>curl {{.BaseURL}}/config/gemini/{{.Token}} > ~/.gemini/oauth_creds.json</code></pre>

        <p>2. Set endpoint (add to <code>~/.bashrc</code> or <code>~/.zshrc</code>):</p>
        <pre><code>export CODE_ASSIST_ENDPOINT={{.BaseURL}}</code></pre>

        <p>Or create <code>~/.gemini/settings.json</code>:</p>
        <pre><code>{
  "codeAssistEndpoint": "{{.BaseURL}}"
}</code></pre>
    </div>
</body>
</html>`

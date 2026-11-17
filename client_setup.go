package main

import (
	"net/http"
	"strings"
)

func (h *proxyHandler) serveGrokSetupScript(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimPrefix(r.URL.Path, "/setup/grok/")
	if token == "" || strings.Contains(token, "/") {
		http.Error(w, "invalid token", http.StatusBadRequest)
		return
	}
	baseURL := strings.TrimRight(h.getEffectivePublicURL(r), "/")
	setupModels := grokSetupModels()

	if wantsPowerShell(r) {
		powerShellModels := make([]string, 0, len(setupModels))
		for _, model := range setupModels {
			modelID := strings.ReplaceAll(model.ID, "'", "''")
			backend := strings.ReplaceAll(model.APIBackend, "'", "''")
			powerShellModels = append(powerShellModels, "@{ Id = '"+modelID+"'; Backend = '"+backend+"' }")
		}
		script := renderSetupScript(grokPowerShell, setupScriptData{token: token, publicURL: baseURL, models: strings.Join(powerShellModels, ", ")})
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write([]byte(script))
		return
	}

	modelSpecs := make([]string, 0, len(setupModels))
	for _, model := range setupModels {
		modelSpecs = append(modelSpecs, model.ID+":"+model.APIBackend)
	}
	script := renderSetupScript(grokBash, setupScriptData{token: token, publicURL: baseURL, models: strings.Join(modelSpecs, " ")})
	w.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
	w.Write([]byte(script))
}

func (h *proxyHandler) servePiSetupScript(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimPrefix(r.URL.Path, "/setup/pi/")
	if token == "" || strings.Contains(token, "/") {
		http.Error(w, "invalid token", http.StatusBadRequest)
		return
	}
	baseURL := strings.TrimRight(h.getEffectivePublicURL(r), "/")

	if wantsPowerShell(r) {
		script := renderSetupScript(piPowerShell, setupScriptData{publicURL: baseURL, token: token})
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write([]byte(script))
		return
	}

	script := renderSetupScript(piBash, setupScriptData{publicURL: baseURL, token: token})
	w.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
	w.Write([]byte(script))
}

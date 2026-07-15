package main

import (
	"encoding/json"
	"net/http"
)

func poolModelDescriptors() ([]cuteCodeModelConfig, error) {
	data, err := generateCuteCodeSettingsJSON("", "")
	if err != nil {
		return nil, err
	}

	var settings cuteCodeSettings
	if err := json.Unmarshal(data, &settings); err != nil {
		return nil, err
	}
	for index := range settings.CustomModels {
		settings.CustomModels[index].BaseURL = ""
		settings.CustomModels[index].APIKey = ""
	}
	return settings.CustomModels, nil
}

func servePoolModels(w http.ResponseWriter) {
	models, err := poolModelDescriptors()
	if err != nil {
		respondJSONError(w, http.StatusInternalServerError, "Failed to generate model catalog.")
		return
	}
	respondJSON(w, map[string]any{"models": models})
}

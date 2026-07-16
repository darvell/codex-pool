package main

import (
	"encoding/json"
	"math"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var geminiRetryInPattern = regexp.MustCompile(`(?i)please retry in\s+([0-9]+(?:\.[0-9]+)?)s`)

func parseGeminiRateLimitReset(body []byte, now time.Time) (time.Time, bool) {
	var payload struct {
		Error struct {
			Message string `json:"message"`
			Details []struct {
				Metadata map[string]any `json:"metadata"`
			} `json:"details"`
		} `json:"error"`
	}
	_ = json.Unmarshal(body, &payload)

	message := strings.ToLower(payload.Error.Message)
	if strings.Contains(message, "per day") || strings.Contains(message, "requests per day") {
		if reset, ok := nextGeminiPacificMidnight(now); ok {
			return reset, true
		}
	}

	for _, detail := range payload.Error.Details {
		raw, _ := detail.Metadata["quotaResetDelay"].(string)
		if duration, err := time.ParseDuration(strings.TrimSpace(raw)); err == nil && duration > 0 {
			return now.Add(time.Duration(math.Ceil(duration.Seconds())) * time.Second), true
		}
	}

	match := geminiRetryInPattern.FindStringSubmatch(string(body))
	if len(match) == 2 {
		seconds, err := strconv.ParseFloat(match[1], 64)
		if err == nil && seconds > 0 {
			return now.Add(time.Duration(math.Ceil(seconds)) * time.Second), true
		}
	}
	return time.Time{}, false
}

func nextGeminiPacificMidnight(now time.Time) (time.Time, bool) {
	location, err := time.LoadLocation("America/Los_Angeles")
	if err != nil {
		return time.Time{}, false
	}
	local := now.In(location)
	return time.Date(local.Year(), local.Month(), local.Day()+1, 0, 0, 0, 0, location), true
}

func (h *proxyHandler) applyRateLimitResponse(a *Account, headers http.Header, body []byte) time.Duration {
	if a == nil || a.Type != AccountTypeGemini {
		return h.applyRateLimit(a, headers)
	}
	resetAt, ok := parseGeminiRateLimitReset(body, time.Now())
	if !ok {
		return h.applyRateLimit(a, headers)
	}
	wait := time.Until(resetAt)
	if wait <= 0 {
		return h.applyRateLimit(a, headers)
	}
	seconds := int64(math.Ceil(wait.Seconds()))
	if seconds < 1 {
		seconds = 1
	}
	cloned := make(http.Header)
	if headers != nil {
		cloned = headers.Clone()
	}
	cloned.Set("Retry-After", strconv.FormatInt(seconds, 10))
	return h.applyRateLimit(a, cloned)
}

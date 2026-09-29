package main

import (
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const antigravitySnapshotFreshFor = 24 * time.Hour

type antigravityEligibilityReason string

const (
	antigravityEligible             antigravityEligibilityReason = "eligible"
	antigravityUnsupported          antigravityEligibilityReason = "unsupported_model"
	antigravityCapabilityUnknown    antigravityEligibilityReason = "capability_unknown"
	antigravityDisabled             antigravityEligibilityReason = "disabled"
	antigravityDead                 antigravityEligibilityReason = "dead"
	antigravityVerificationRequired antigravityEligibilityReason = "verification_required"
	antigravitySourceIPDenied       antigravityEligibilityReason = "source_ip_denied"
	antigravityAccountCooldown      antigravityEligibilityReason = "account_cooldown"
	antigravityModelCooldown        antigravityEligibilityReason = "model_cooldown"
	antigravityFamilyQuotaExhausted antigravityEligibilityReason = "quota_family_exhausted"
	antigravityModelQuotaExhausted  antigravityEligibilityReason = "model_quota_exhausted"
	antigravityAlreadyAttempted     antigravityEligibilityReason = "already_attempted"
)

type antigravityAccountEligibility struct {
	account    *Account
	reason     antigravityEligibilityReason
	eligible   bool
	supporting bool
	healthy    bool
	temporary  bool
	retryAt    time.Time
	headroom   float64
	inflight   int64
}

type antigravityEligibilityReport struct {
	Total       int
	Supporting  int
	Healthy     int
	Ready       int
	Temporary   int
	NextRetryAt time.Time
	Reasons     map[antigravityEligibilityReason]int
}

func (r antigravityEligibilityReport) publicMessage(model string) string {
	keys := make([]string, 0, len(r.Reasons))
	for reason, count := range r.Reasons {
		if count > 0 {
			keys = append(keys, fmt.Sprintf("%s=%d", reason, count))
		}
	}
	sort.Strings(keys)
	if len(keys) == 0 {
		keys = append(keys, "no_configured_capacity=1")
	}
	return fmt.Sprintf("no Antigravity account is currently eligible for %s (%s)", model, strings.Join(keys, ", "))
}

// temporaryOnly is true only when at least one healthy account can support or
// probe the model and every such account is blocked by a known temporary limit.
func (r antigravityEligibilityReport) temporaryOnly() bool {
	return r.Supporting > 0 && r.Healthy > 0 && r.Ready == 0 && r.Temporary == r.Healthy
}

func antigravitySnapshotHeadroom(snapshot AntigravityAccountSnapshot, model string) float64 {
	headroom := 1.0
	known := false
	if info, ok := snapshot.Models[model]; ok && info.Quota.RemainingFraction != nil {
		headroom = *info.Quota.RemainingFraction
		known = true
	}
	if group := snapshot.Quota.group(antigravityQuotaFamily(model)); group != nil {
		for _, bucket := range group.Buckets {
			if !known || bucket.RemainingFraction < headroom {
				headroom = bucket.RemainingFraction
				known = true
			}
		}
	}
	if !known {
		return 0.5
	}
	if headroom < 0 {
		return 0
	}
	if headroom > 1 {
		return 1
	}
	return headroom
}

func antigravityEvaluateAccount(account *Account, snapshot AntigravityAccountSnapshot, hasSnapshot bool, model, clientIP string, attempted bool, now time.Time) antigravityAccountEligibility {
	decision := antigravityAccountEligibility{account: account, reason: antigravityEligible, headroom: 0.5}
	if account == nil || account.Type != AccountTypeAntigravity {
		decision.reason = antigravityUnsupported
		return decision
	}
	if attempted {
		decision.reason = antigravityAlreadyAttempted
		return decision
	}
	if !hasSnapshot {
		decision.reason = antigravityCapabilityUnknown
		decision.supporting = true
	} else if _, ok := snapshot.Models[model]; ok {
		decision.supporting = true
		decision.headroom = antigravitySnapshotHeadroom(snapshot, model)
	} else if now.Sub(snapshot.FetchedAt) > antigravitySnapshotFreshFor {
		// A stale negative is not evidence that a newly introduced model is
		// unsupported. Permit a bounded probe and let discovery catch up.
		decision.reason = antigravityCapabilityUnknown
		decision.supporting = true
	} else {
		decision.reason = antigravityUnsupported
		return decision
	}

	account.mu.Lock()
	defer account.mu.Unlock()
	decision.inflight = atomic.LoadInt64(&account.Inflight)
	if account.Disabled {
		decision.reason = antigravityDisabled
		return decision
	}
	if account.Dead {
		decision.reason = antigravityDead
		return decision
	}
	if account.NeedsVerification {
		decision.reason = antigravityVerificationRequired
		return decision
	}
	if !accountAllowsClientIPLocked(account, clientIP) {
		decision.reason = antigravitySourceIPDenied
		return decision
	}
	decision.healthy = true
	if account.RateLimitUntil.After(now) {
		decision.reason, decision.temporary, decision.retryAt = antigravityAccountCooldown, true, account.RateLimitUntil
		return decision
	}
	if until := account.ModelRateLimits[model]; until.After(now) {
		decision.reason, decision.temporary, decision.retryAt = antigravityModelCooldown, true, until
		return decision
	}
	if family := antigravityQuotaFamily(model); family != "" {
		if until := account.ModelRateLimits["family:"+family]; until.After(now) {
			decision.reason, decision.temporary, decision.retryAt = antigravityFamilyQuotaExhausted, true, until
			return decision
		}
	}
	if hasSnapshot {
		if info, ok := snapshot.Models[model]; ok && info.Quota.RemainingFraction != nil && *info.Quota.RemainingFraction <= 0 && info.Quota.ResetTime.After(now) {
			decision.reason, decision.temporary, decision.retryAt = antigravityModelQuotaExhausted, true, info.Quota.ResetTime
			return decision
		}
		if until := snapshot.Quota.exhaustedUntil(model, now); until.After(now) {
			decision.reason, decision.temporary, decision.retryAt = antigravityFamilyQuotaExhausted, true, until
			return decision
		}
	}
	decision.eligible = true
	return decision
}

func buildAntigravityReport(decisions []antigravityAccountEligibility) antigravityEligibilityReport {
	report := antigravityEligibilityReport{Reasons: make(map[antigravityEligibilityReason]int)}
	for _, decision := range decisions {
		report.Total++
		report.Reasons[decision.reason]++
		if decision.supporting {
			report.Supporting++
		}
		if decision.healthy {
			report.Healthy++
		}
		if decision.eligible {
			report.Ready++
		}
		if decision.temporary {
			report.Temporary++
			if !decision.retryAt.IsZero() && (report.NextRetryAt.IsZero() || decision.retryAt.Before(report.NextRetryAt)) {
				report.NextRetryAt = decision.retryAt
			}
		}
	}
	return report
}

type antigravityReservation struct {
	Account    *Account
	generation uint64
	once       sync.Once
}

func (r *antigravityReservation) Release() {
	if r == nil || r.Account == nil {
		return
	}
	r.once.Do(func() { atomic.AddInt64(&r.Account.Inflight, -1) })
}

// withCurrentAntigravityReservation gates all account state changes and saves
// against a reload. The lifecycle read lock remains held while the callback
// mutates/persists the object, so a replacement cannot pass between validation
// and the write. No network I/O belongs in the callback.
func (p *poolState) withCurrentAntigravityReservation(reservation *antigravityReservation, fn func(*Account) error) error {
	if p == nil || reservation == nil || reservation.Account == nil || fn == nil {
		return errStaleAntigravityAccount
	}
	p.stateMu.RLock()
	defer p.stateMu.RUnlock()
	p.mu.RLock()
	current := p.generation == reservation.generation
	if current {
		current = false
		for _, account := range p.accounts {
			if account == reservation.Account {
				current = true
				break
			}
		}
	}
	p.mu.RUnlock()
	if !current {
		return errStaleAntigravityAccount
	}
	return fn(reservation.Account)
}

func (p *poolState) antigravityDecisions(exclude map[string]bool, model, clientIP string, now time.Time) []antigravityAccountEligibility {
	p.stateMu.RLock()
	defer p.stateMu.RUnlock()
	model = antigravityCanonicalModel(model)
	snapshots := antigravityModels.Snapshots()
	p.mu.RLock()
	defer p.mu.RUnlock()
	decisions := make([]antigravityAccountEligibility, 0)
	for _, account := range p.accounts {
		if account.Type != AccountTypeAntigravity {
			continue
		}
		snapshot, ok := snapshots[account.ID]
		decisions = append(decisions, antigravityEvaluateAccount(account, snapshot, ok, model, clientIP, exclude != nil && exclude[account.ID], now))
	}
	return decisions
}

// reserveAntigravityModel evaluates all accounts and increments the chosen
// account's Inflight count before releasing pool.mu. Registry state is
// snapshotted first, so the lock order remains pool -> account and never nests
// registry and account locks.
func (p *poolState) reserveAntigravityModel(conversationID string, exclude map[string]bool, model, clientIP string) (*antigravityReservation, antigravityEligibilityReport) {
	p.stateMu.RLock()
	defer p.stateMu.RUnlock()
	model = antigravityCanonicalModel(model)
	now := time.Now()
	snapshots := antigravityModels.Snapshots()
	p.mu.Lock()
	defer p.mu.Unlock()

	decisions := make([]antigravityAccountEligibility, 0)
	pinKey := "antigravity:" + model + ":" + conversationID
	pinnedID := ""
	if conversationID != "" {
		pinnedID = p.convPin[pinKey]
	}
	var eligible []antigravityAccountEligibility
	for _, account := range p.accounts {
		if account.Type != AccountTypeAntigravity {
			continue
		}
		snapshot, ok := snapshots[account.ID]
		decision := antigravityEvaluateAccount(account, snapshot, ok, model, clientIP, exclude != nil && exclude[account.ID], now)
		decisions = append(decisions, decision)
		if decision.eligible {
			eligible = append(eligible, decision)
		}
	}
	report := buildAntigravityReport(decisions)
	if len(eligible) == 0 {
		if pinnedID != "" {
			delete(p.convPin, pinKey)
		}
		return nil, report
	}
	chosen := -1
	if pinnedID != "" {
		for i := range eligible {
			if eligible[i].account.ID == pinnedID {
				chosen = i
				break
			}
		}
	}
	if chosen < 0 {
		// Quota headroom is the primary signal. Within a small headroom band,
		// lower inflight wins, and p.rr rotates exact ties deterministically.
		bestHeadroom := -1.0
		for _, candidate := range eligible {
			if candidate.headroom > bestHeadroom {
				bestHeadroom = candidate.headroom
			}
		}
		competitive := make([]int, 0, len(eligible))
		for i, candidate := range eligible {
			if candidate.headroom >= bestHeadroom-0.02 {
				competitive = append(competitive, i)
			}
		}
		minInflight := int64(math.MaxInt64)
		for _, i := range competitive {
			if eligible[i].inflight < minInflight {
				minInflight = eligible[i].inflight
			}
		}
		tied := make([]int, 0, len(competitive))
		for _, i := range competitive {
			if eligible[i].inflight == minInflight {
				tied = append(tied, i)
			}
		}
		chosen = tied[int(p.rr%uint64(len(tied)))]
	}
	account := eligible[chosen].account
	atomic.AddInt64(&account.Inflight, 1)
	p.rr++
	return &antigravityReservation{Account: account, generation: p.generation}, report
}

func (p *poolState) pinAntigravityModel(reservation *antigravityReservation, conversationID, model string) bool {
	if reservation == nil || reservation.Account == nil || conversationID == "" {
		return false
	}
	p.stateMu.RLock()
	defer p.stateMu.RUnlock()
	model = antigravityCanonicalModel(model)
	p.mu.Lock()
	defer p.mu.Unlock()
	if reservation.generation != p.generation {
		return false
	}
	current := false
	for _, account := range p.accounts {
		if account == reservation.Account {
			current = true
			break
		}
	}
	if !current {
		return false
	}
	p.convPin["antigravity:"+model+":"+conversationID] = reservation.Account.ID
	return true
}

func antigravityRetryAt(headers http.Header, body []byte, fallbackLevel int, now time.Time) time.Time {
	var latest time.Time
	if reset, ok := parseAntigravityRetry(body, now); ok && reset.After(latest) {
		latest = reset
	}
	if wait, ok := parseRetryAfterAt(headers, now); ok {
		reset := now.Add(wait)
		if reset.After(latest) {
			latest = reset
		}
	}
	if latest.IsZero() {
		latest = now.Add(backoffDuration(fallbackLevel))
	}
	return latest
}

func parseRetryAfterAt(headers http.Header, now time.Time) (time.Duration, bool) {
	if headers == nil {
		return 0, false
	}
	value := strings.TrimSpace(headers.Get("Retry-After"))
	if value == "" {
		return 0, false
	}
	if seconds, err := time.ParseDuration(value + "s"); err == nil && seconds > 0 {
		return seconds, true
	}
	if when, err := http.ParseTime(value); err == nil && when.After(now) {
		return when.Sub(now), true
	}
	return 0, false
}

func antigravityRateLimitScope(model string, body []byte) string {
	model = antigravityCanonicalModel(model)
	family := antigravityQuotaFamily(model)
	// Only structured provider-emitted quota/bucket identifiers positively
	// establish that the live limit is shared. Generic RESOURCE_EXHAUSTED and
	// free-form messages remain exact-model scoped.
	var root any
	if json.Unmarshal(body, &root) == nil && antigravityBodyIdentifiesQuotaFamily(root, family) {
		return "family:" + family
	}
	return model
}

func antigravityBodyIdentifiesQuotaFamily(value any, family string) bool {
	if family == "" {
		return false
	}
	switch node := value.(type) {
	case map[string]any:
		for key, child := range node {
			lowerKey := strings.ToLower(key)
			if text, ok := child.(string); ok && (strings.Contains(lowerKey, "quota") || strings.Contains(lowerKey, "bucket") || strings.Contains(lowerKey, "limit")) {
				identifier := strings.ToLower(strings.TrimSpace(text))
				if family == antigravityQuotaFamilyGemini && (identifier == "gemini-weekly" || identifier == "gemini-5h") {
					return true
				}
				if family == antigravityQuotaFamilyThirdParty && (identifier == "3p-weekly" || identifier == "3p-5h") {
					return true
				}
			}
			if antigravityBodyIdentifiesQuotaFamily(child, family) {
				return true
			}
		}
	case []any:
		for _, child := range node {
			if antigravityBodyIdentifiesQuotaFamily(child, family) {
				return true
			}
		}
	}
	return false
}

func applyAntigravityRateLimit(account *Account, model string, headers http.Header, body []byte, now time.Time) time.Time {
	if account == nil {
		return time.Time{}
	}
	scope := antigravityRateLimitScope(model, body)
	account.mu.Lock()
	if account.ModelRateLimits == nil {
		account.ModelRateLimits = make(map[string]time.Time)
	}
	if account.ModelBackoffLevels == nil {
		account.ModelBackoffLevels = make(map[string]int)
	}
	level := account.ModelBackoffLevels[scope]
	until := antigravityRetryAt(headers, body, level, now)
	if until.After(account.ModelRateLimits[scope]) {
		account.ModelRateLimits[scope] = until
	}
	account.ModelBackoffLevels[scope] = level + 1
	account.mu.Unlock()
	_ = saveAccount(account)
	return until
}

func clearAntigravityRuntimeState(account *Account, model string) {
	if account == nil {
		return
	}
	model = antigravityCanonicalModel(model)
	account.mu.Lock()
	familyKey := "family:" + antigravityQuotaFamily(model)
	_, cooldown := account.ModelRateLimits[model]
	_, familyCooldown := account.ModelRateLimits[familyKey]
	_, backoff := account.ModelBackoffLevels[model]
	_, familyBackoff := account.ModelBackoffLevels[familyKey]
	delete(account.ModelRateLimits, model)
	delete(account.ModelRateLimits, familyKey)
	delete(account.ModelBackoffLevels, model)
	delete(account.ModelBackoffLevels, familyKey)
	account.BackoffLevel = 0
	account.RateLimitUntil = time.Time{}
	account.LastUsed = time.Now()
	account.mu.Unlock()
	if cooldown || familyCooldown || backoff || familyBackoff {
		_ = saveAccount(account)
	}
}

func antigravitySetRetryAfter(header http.Header, until time.Time, now time.Time) {
	if until.IsZero() {
		return
	}
	seconds := int64(math.Ceil(until.Sub(now).Seconds()))
	if seconds < 1 {
		seconds = 1
	}
	header.Set("Retry-After", fmt.Sprintf("%d", seconds))
}

func antigravityPublicErrorBody(message string) []byte {
	body, _ := json.Marshal(map[string]any{"error": map[string]any{"message": message}})
	return body
}

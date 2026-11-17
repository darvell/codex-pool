package main

// resolveUsageIdentity accepts installed credential identities at recording
// boundaries. Persisted request rows and facts retain separate principal/client IDs.
func resolveUsageIdentity(u RequestUsage) RequestUsage {
	if u.UserID == "" {
		return u
	}
	principalID, clientID := splitClientIdentity(u.UserID)
	u.UserID = principalID
	if u.ClientCredentialID == "" {
		u.ClientCredentialID = clientID
	}
	return u
}

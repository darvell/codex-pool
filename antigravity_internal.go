package main

type antigravityInternalProfile struct {
	path      string
	userAgent func() string
	apiClient string
}

var antigravityLoadProfile = antigravityInternalProfile{
	path:      "/v1internal:loadCodeAssist",
	userAgent: antigravityUserAgent,
}

var antigravityOnboardProfile = antigravityInternalProfile{
	path:      "/v1internal:onboardUser",
	userAgent: antigravityOnboardUserAgent,
	apiClient: "gl-node/22.21.1",
}

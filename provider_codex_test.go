package main

import "testing"

func TestCodexProviderLoadAccountReadsCyberAccess(t *testing.T) {
	provider := &CodexProvider{}
	data := []byte(`{
		"cyber_access": true,
		"tokens": {
			"access_token": "access",
			"refresh_token": "refresh",
			"id_token": "id",
			"account_id": "acct_123"
		}
	}`)

	acc, err := provider.LoadAccount("darv.json", "/tmp/darv.json", data)
	if err != nil {
		t.Fatalf("LoadAccount: %v", err)
	}
	if acc == nil {
		t.Fatal("expected account")
	}
	if !acc.CyberAccess {
		t.Fatal("expected cyber access flag")
	}
}

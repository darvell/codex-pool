package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestApplyProxyAuthFailure(t *testing.T) {
	t.Run("codex proxy auth failure stays lightweight", func(t *testing.T) {
		acc := &Account{Type: AccountTypeCodex}

		markedDead, penaltyNow := applyProxyAuthFailure(acc, false)

		if markedDead {
			t.Fatal("codex account should not be marked dead from proxy auth failure")
		}
		if acc.Dead {
			t.Fatal("codex account unexpectedly marked dead")
		}
		if penaltyNow != 0.2 || acc.Penalty != 0.2 {
			t.Fatalf("codex penalty = %v, want 0.2", acc.Penalty)
		}
	})

	t.Run("static API key proxy auth failure never retires account", func(t *testing.T) {
		for _, accountType := range []AccountType{AccountTypeKimi, AccountTypeMinimax, AccountTypeZAI, AccountTypeXiaomi} {
			acc := &Account{Type: accountType}
			markedDead, penaltyNow := applyProxyAuthFailure(acc, true)
			if markedDead || acc.Dead {
				t.Fatalf("%s account should require provider validation before being marked dead", accountType)
			}
			if penaltyNow != 0.2 || acc.Penalty != 0.2 {
				t.Fatalf("%s penalty = %v, want 0.2", accountType, acc.Penalty)
			}
		}
	})

	t.Run("non-codex proxy auth failure stays severe before refresh failure", func(t *testing.T) {
		acc := &Account{Type: AccountTypeClaude}

		markedDead, penaltyNow := applyProxyAuthFailure(acc, false)

		if markedDead {
			t.Fatal("account should not be marked dead before refresh failure")
		}
		if acc.Dead {
			t.Fatal("account unexpectedly marked dead")
		}
		if penaltyNow != 10.0 || acc.Penalty != 10.0 {
			t.Fatalf("penalty = %v, want 10.0", acc.Penalty)
		}
	})

	t.Run("non-codex refresh failure marks account dead", func(t *testing.T) {
		acc := &Account{Type: AccountTypeClaude}

		markedDead, penaltyNow := applyProxyAuthFailure(acc, true)

		if !markedDead {
			t.Fatal("expected account to be marked dead after refresh failure")
		}
		if !acc.Dead {
			t.Fatal("account should be marked dead")
		}
		if penaltyNow != 1.0 || acc.Penalty != 1.0 {
			t.Fatalf("penalty = %v, want 1.0", acc.Penalty)
		}
	})
}

func TestRestoreValidatedStaticAccountPersistsHealthyState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "minimax.json")
	if err := os.WriteFile(path, []byte(`{"api_key":"secret","dead":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	account := &Account{ID: "minimax", Type: AccountTypeMinimax, File: path, AccessToken: "secret", Dead: true, Penalty: 100}

	restoreValidatedAccount(account, "test")

	if account.Dead || account.Penalty != 0 {
		t.Fatalf("account state = dead %v penalty %v", account.Dead, account.Penalty)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), `"dead"`) {
		t.Fatalf("persisted account still dead: %s", data)
	}
}

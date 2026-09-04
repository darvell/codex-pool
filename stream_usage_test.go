package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"

	"go.etcd.io/bbolt"
)

func TestStreamUsageCommitBoundary(t *testing.T) {
	for _, failWrite := range []bool{false, true} {
		t.Run(fmt.Sprintf("write_failure_%t", failWrite), func(t *testing.T) {
			store := testUsageStore(t)
			account := &Account{ID: "stream_account", Type: AccountTypeCodex}
			h := &proxyHandler{cfg: &config{}, store: store}
			sink := &flushTestSink{}
			if failWrite {
				sink.writeErr = errors.New("client disconnected")
			}
			committed := 0
			writer := &streamUsageWriter{record: func(usage RequestUsage) {
				if sink.writes == 0 {
					t.Fatal("accounting ran before forwarding")
				}
				committed++
				if usage.OutputTokens != int64(committed) {
					t.Fatalf("usage order changed: %+v", usage)
				}
				h.recordUsage(account, usage)
			}}
			provider := &CodexProvider{}
			writer.w = &sseInterceptWriter{w: sink, callback: func(data []byte) {
				var event map[string]any
				if err := json.Unmarshal(data, &event); err != nil {
					t.Fatal(err)
				}
				usage := provider.ParseUsage(event)
				usage.AccountID = account.ID
				usage.AccountType = account.Type
				usage.UserID = "stream_user"
				usage.RequestID = fmt.Sprint(usage.OutputTokens)
				writer.add(*usage)
			}}
			var events strings.Builder
			for n := 1; n <= 3; n++ {
				fmt.Fprintf(&events, "data: {\"usage\":{\"input_tokens\":7,\"output_tokens\":%d}}\n\n", n)
			}
			_, err := writer.Write([]byte(events.String()))
			if !errors.Is(err, sink.writeErr) {
				t.Fatalf("Write = %v, want %v", err, sink.writeErr)
			}
			if committed != 3 || len(writer.pending) != 0 {
				t.Fatalf("committed=%d pending=%d", committed, len(writer.pending))
			}
			usage, err := store.loadAccountUsage(account.ID)
			if err != nil {
				t.Fatal(err)
			}
			if usage.RequestCount != 3 || usage.TotalInputTokens != 21 || usage.TotalOutputTokens != 6 {
				t.Fatalf("persisted usage = %+v", usage)
			}
			if err := store.db.View(func(tx *bbolt.Tx) error {
				if n := tx.Bucket([]byte(bucketAnalyticsOutbox)).Stats().KeyN; n != 3 {
					return fmt.Errorf("outbox facts = %d, want 3", n)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestStreamUsageChunkBound(t *testing.T) {
	sink := httptest.NewRecorder()
	committed := 0
	writer := &streamUsageWriter{record: func(RequestUsage) { committed++ }}
	writer.w = &sseInterceptWriter{w: sink, callback: func([]byte) {
		if len(writer.pending) >= streamUsageChunkBytes/len("data: {}\n\n")+1 {
			t.Fatal("usage retained beyond one copy chunk")
		}
		writer.add(RequestUsage{})
	}}
	const events = 10000
	body := strings.Repeat("data: {}\n\n", events)
	if n, err := writer.Write([]byte(body)); n != len(body) || err != nil {
		t.Fatalf("Write = (%d, %v)", n, err)
	}
	if committed != events || sink.Body.String() != body {
		t.Fatalf("committed = %d, want %d; bytes = %d", committed, events, sink.Body.Len())
	}
}

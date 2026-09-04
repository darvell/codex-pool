package main

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func TestFlushWriterLiveDelivery(t *testing.T) {
	for _, tc := range []struct {
		name     string
		interval time.Duration
		stop     bool
	}{
		{name: "default"},
		{name: "negative", interval: -time.Second},
		{name: "idle interval", interval: 25 * time.Millisecond},
		{name: "stop drains", interval: time.Hour, stop: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			next := make(chan struct{})
			finish := make(chan struct{})
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/event-stream")
				fw := &flushWriter{w: w, f: w.(http.Flusher), flushInterval: tc.interval}
				defer fw.stop()
				if _, err := fw.Write([]byte("data: first\n\n")); err != nil {
					t.Error(err)
					return
				}
				select {
				case <-next:
				case <-r.Context().Done():
					return
				}
				if _, err := fw.Write([]byte("data: second\n\n")); err != nil {
					t.Error(err)
					return
				}
				if tc.stop {
					fw.stop()
				}
				// Keep the handler alive: EOF must not rescue an unflushed event.
				<-finish
			}))
			defer server.Close()
			defer close(finish)
			client := server.Client()
			client.Timeout = time.Second
			resp, err := client.Get(server.URL)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			reader := bufio.NewReader(resp.Body)
			readFlushFrame(t, reader, "data: first\n\n")
			close(next)
			readFlushFrame(t, reader, "data: second\n\n")
		})
	}
}

func readFlushFrame(t *testing.T, reader io.Reader, want string) {
	t.Helper()
	got := make([]byte, len(want))
	if _, err := io.ReadFull(reader, got); err != nil {
		t.Fatalf("read frame before upstream completion: %v", err)
	}
	if string(got) != want {
		t.Fatalf("frame = %q, want %q", got, want)
	}
}

type flushTestSink struct {
	mu       sync.Mutex
	writes   int
	flushes  int
	writeErr error
	flushErr error
	flushed  chan struct{}
}

func (*flushTestSink) Header() http.Header { return make(http.Header) }
func (*flushTestSink) WriteHeader(int)     {}

func (s *flushTestSink) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.writes++
	if s.writeErr != nil {
		return 0, s.writeErr
	}
	return len(p), nil
}

func (s *flushTestSink) Flush() { _ = s.FlushError() }

func (s *flushTestSink) FlushError() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.flushes++
	if s.flushed != nil {
		select {
		case s.flushed <- struct{}{}:
		default:
		}
	}
	return s.flushErr
}

func TestFlushWriterImmediateError(t *testing.T) {
	want := errors.New("client flush failed")
	sink := &flushTestSink{flushErr: want}
	fw := &flushWriter{w: sink, f: sink}
	defer fw.stop()
	if n, err := fw.Write([]byte("frame")); n != 5 || !errors.Is(err, want) {
		t.Fatalf("Write = (%d, %v), want (5, %v)", n, err, want)
	}
}

func TestHeartbeatFragmentBoundary(t *testing.T) {
	for _, newline := range []string{"\n", "\r\n"} {
		t.Run(newline, func(t *testing.T) {
			sink := httptest.NewRecorder()
			fw := &flushWriter{w: sink, f: sink}
			hw := newHeartbeatWriter(fw, sink)
			defer fw.stop()
			defer hw.Stop()
			parts := []string{"data: {\"type\":", "\"message_start\"}", newline, newline}
			var want bytes.Buffer
			for i, part := range parts {
				if _, err := hw.Write([]byte(part)); err != nil {
					t.Fatal(err)
				}
				want.WriteString(part)
				hw.sendHeartbeat()
				if i == len(parts)-1 {
					want.WriteString(": heartbeat\n\n")
				}
				if got := sink.Body.String(); got != want.String() {
					t.Fatalf("fragment %d: got %q, want %q", i, got, want.String())
				}
			}
		})
	}
}

func TestInterceptUsageOnWriteError(t *testing.T) {
	want := errors.New("client disconnected")
	sink := &flushTestSink{writeErr: want}
	var usage []byte
	writer := &sseInterceptWriter{w: sink, callback: func(data []byte) { usage = append([]byte(nil), data...) }}
	data := `{"type":"message_delta","usage":{"output_tokens":42}}`
	if _, err := writer.Write([]byte("data: " + data + "\n\n")); !errors.Is(err, want) {
		t.Fatalf("Write = %v, want %v", err, want)
	}
	if string(usage) != data {
		t.Fatalf("usage already received from upstream was lost: %q", usage)
	}
}

func TestFlushWriterDelayedError(t *testing.T) {
	want := errors.New("timer flush failed")
	sink := &flushTestSink{flushed: make(chan struct{}, 1)}
	fw := &flushWriter{w: sink, f: sink, flushInterval: 10 * time.Millisecond}
	defer fw.stop()
	if _, err := fw.Write([]byte("first")); err != nil {
		t.Fatal(err)
	}
	<-sink.flushed
	sink.mu.Lock()
	sink.flushErr = want
	sink.mu.Unlock()
	_, _ = fw.Write([]byte("second"))
	select {
	case <-sink.flushed:
	case <-time.After(time.Second):
		t.Fatal("deadline flush never ran")
	}
	if err := fw.stop(); !errors.Is(err, want) {
		t.Fatalf("stop = %v, want %v", err, want)
	}
	if _, err := fw.Write([]byte("third")); !errors.Is(err, want) {
		t.Fatalf("Write = %v, want %v", err, want)
	}
}

func TestHeartbeatConcurrentStop(t *testing.T) {
	// Deliberately unsynchronized: -race checks that the wrappers serialize it.
	sink := &flushBenchSink{}
	fw := &flushWriter{w: sink, f: sink, flushInterval: time.Microsecond}
	hw := newHeartbeatWriter(fw, sink)
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 1000 {
				if _, err := hw.Write([]byte("data: token\n\n")); err != nil {
					if !errors.Is(err, io.ErrClosedPipe) {
						t.Error(err)
					}
					return
				}
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for range 100 {
			hw.sendHeartbeat()
		}
	}()
	if err := hw.Stop(); err != nil {
		t.Fatal(err)
	}
	if err := fw.stop(); err != nil {
		t.Fatal(err)
	}
	wg.Wait()
	flushes := sink.flushes
	hw.sendHeartbeat()
	if _, err := hw.Write([]byte("late")); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("late Write = %v", err)
	}
	if err := hw.Stop(); err != nil {
		t.Fatal(err)
	}
	if err := fw.stop(); err != nil {
		t.Fatal(err)
	}
	if sink.flushes != flushes {
		t.Fatal("response touched after shutdown")
	}
}

func TestHeartbeatFlushError(t *testing.T) {
	want := errors.New("heartbeat flush failed")
	sink := &flushTestSink{flushErr: want}
	fw := &flushWriter{w: sink, f: sink, flushInterval: time.Second}
	hw := newHeartbeatWriter(fw, sink)
	defer fw.stop()
	defer hw.Stop()
	hw.sendHeartbeat()
	if _, err := hw.Write([]byte("token")); !errors.Is(err, want) {
		t.Fatalf("Write = %v, want %v", err, want)
	}
	if err := hw.Stop(); !errors.Is(err, want) {
		t.Fatalf("Stop = %v, want %v", err, want)
	}
}

func BenchmarkFlushWriterDefault(b *testing.B) {
	sink := &flushBenchSink{}
	fw := &flushWriter{w: sink, f: sink}
	frame := []byte("data: token\n\n")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := fw.Write(frame); err != nil {
			b.Fatal(err)
		}
	}
	b.StopTimer()
	fw.stop()
	if sink.flushes != b.N {
		b.Fatalf("flushes = %d, writes = %d", sink.flushes, b.N)
	}
}

type flushBenchSink struct{ flushes int }

func (*flushBenchSink) Header() http.Header         { return nil }
func (*flushBenchSink) WriteHeader(int)             {}
func (*flushBenchSink) Write(p []byte) (int, error) { return len(p), nil }
func (s *flushBenchSink) Flush()                    { s.flushes++ }

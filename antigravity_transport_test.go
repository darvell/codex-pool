package main

import (
	"crypto/tls"
	"net/http"
	"testing"
)

func TestCloneAntigravityTransportForcesHTTP11(t *testing.T) {
	base := &http.Transport{ForceAttemptHTTP2: true, TLSClientConfig: &tls.Config{NextProtos: []string{"h2", "http/1.1"}}}
	clone := cloneAntigravityHTTP11Transport(base)
	if clone == base {
		t.Fatal("transport was not cloned")
	}
	if clone.ForceAttemptHTTP2 {
		t.Fatal("HTTP/2 remains enabled")
	}
	if clone.TLSNextProto == nil {
		t.Fatal("TLSNextProto must be non-nil to disable implicit HTTP/2")
	}
	if len(clone.TLSClientConfig.NextProtos) != 1 || clone.TLSClientConfig.NextProtos[0] != "http/1.1" {
		t.Fatalf("ALPN protocols = %v", clone.TLSClientConfig.NextProtos)
	}
	if base.TLSClientConfig.NextProtos[0] != "h2" {
		t.Fatal("base transport was mutated")
	}
}

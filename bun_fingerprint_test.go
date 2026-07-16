package main

import (
	"net/http"
	"net/url"
	"reflect"
	"testing"

	utls "github.com/refraction-networking/utls"
)

func TestBunSpecMatchesClaudeCodeNodeProfile(t *testing.T) {
	spec := bunSpec()

	wantCiphers := []uint16{
		utls.TLS_AES_128_GCM_SHA256,
		utls.TLS_AES_256_GCM_SHA384,
		utls.TLS_CHACHA20_POLY1305_SHA256,
		utls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		utls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		utls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		utls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		utls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
		utls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		utls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
		utls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		utls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
		utls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		utls.TLS_RSA_WITH_AES_128_GCM_SHA256,
		utls.TLS_RSA_WITH_AES_256_GCM_SHA384,
		utls.TLS_RSA_WITH_AES_128_CBC_SHA,
		utls.TLS_RSA_WITH_AES_256_CBC_SHA,
		utls.FAKE_TLS_EMPTY_RENEGOTIATION_INFO_SCSV,
	}
	if !reflect.DeepEqual(spec.CipherSuites, wantCiphers) {
		t.Fatalf("cipher suite order mismatch:\n got %v\nwant %v", spec.CipherSuites, wantCiphers)
	}

	if len(spec.Extensions) != 14 {
		t.Fatalf("got %d extensions, want 14", len(spec.Extensions))
	}
	if _, ok := spec.Extensions[1].(*utls.GREASEEncryptedClientHelloExtension); !ok {
		t.Fatalf("extension 1 is %T, want ECH GREASE", spec.Extensions[1])
	}
	alpn, ok := spec.Extensions[7].(*utls.ALPNExtension)
	if !ok || !reflect.DeepEqual(alpn.AlpnProtocols, []string{"http/1.1"}) {
		t.Fatalf("ALPN extension = %#v, want http/1.1 only", spec.Extensions[7])
	}
}

func TestCreateBunTransportWithProxyUsesConnectDialer(t *testing.T) {
	proxyURL, err := url.Parse("http://user:pass@127.0.0.1:8888")
	if err != nil {
		t.Fatal(err)
	}
	transport := createBunTransportWithProxy(proxyURL)
	if transport.Proxy != nil {
		t.Fatal("fingerprinted proxy transport must establish CONNECT itself")
	}
	if transport.DialTLSContext == nil {
		t.Fatal("fingerprinted proxy transport has no TLS dialer")
	}
}

func TestBunDialerKeepsHTTPSProxyScheme(t *testing.T) {
	proxyURL, err := url.Parse("https://proxy.example:443")
	if err != nil {
		t.Fatal(err)
	}
	dialer := newBunDialer(proxyURL)
	if dialer.proxyURL.Scheme != "https" {
		t.Fatalf("proxy scheme = %q, want https", dialer.proxyURL.Scheme)
	}
}

func TestAnthropicHostProxyTransportSelectsAnthropicOnly(t *testing.T) {
	anthropic := &recordingRoundTripper{name: "anthropic"}
	direct := &recordingRoundTripper{name: "direct"}
	transport := &anthropicHostProxyTransport{anthropic: anthropic, direct: direct}

	for rawURL, want := range map[string]string{
		"https://api.anthropic.com/v1/messages":          "anthropic",
		"https://edge.api.anthropic.com/v1/messages":     "anthropic",
		"https://generativelanguage.googleapis.com/test": "direct",
	} {
		req, err := http.NewRequest(http.MethodGet, rawURL, nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := transport.RoundTrip(req)
		if err != nil {
			t.Fatal(err)
		}
		if got := resp.Header.Get("X-Transport"); got != want {
			t.Fatalf("%s selected %q, want %q", rawURL, got, want)
		}
	}
}

type recordingRoundTripper struct {
	name string
}

func (r *recordingRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"X-Transport": []string{r.name}},
		Body:       http.NoBody,
	}, nil
}

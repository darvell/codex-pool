package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	utls "github.com/refraction-networking/utls"
)

// rustlsSpec returns a ClientHelloSpec that matches reqwest/rustls fingerprint.
// JA3: 771,4866-4865-4867-49196-49195-52393-49200-49199-52392-255,43-5-10-35-23-51-13-0-16-11-45,29-23-24,0
// JA3 Hash: 728ee39e0f8f005402bb21b1b01aa910
func rustlsSpec() *utls.ClientHelloSpec {
	return &utls.ClientHelloSpec{
		TLSVersMin: utls.VersionTLS12,
		TLSVersMax: utls.VersionTLS13,
		CipherSuites: []uint16{
			utls.TLS_AES_256_GCM_SHA384,
			utls.TLS_AES_128_GCM_SHA256,
			utls.TLS_CHACHA20_POLY1305_SHA256,
			utls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			utls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			utls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			utls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			utls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			utls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
			utls.FAKE_TLS_EMPTY_RENEGOTIATION_INFO_SCSV,
		},
		Extensions: []utls.TLSExtension{
			&utls.SupportedVersionsExtension{Versions: []uint16{utls.VersionTLS13, utls.VersionTLS12}},
			&utls.StatusRequestExtension{},
			&utls.SupportedCurvesExtension{Curves: []utls.CurveID{utls.X25519, utls.CurveP256, utls.CurveP384}},
			&utls.SessionTicketExtension{},
			&utls.ExtendedMasterSecretExtension{},
			&utls.KeyShareExtension{KeyShares: []utls.KeyShare{{Group: utls.X25519}}},
			&utls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []utls.SignatureScheme{
				utls.ECDSAWithP384AndSHA384, utls.ECDSAWithP256AndSHA256, utls.Ed25519,
				utls.PSSWithSHA512, utls.PSSWithSHA384, utls.PSSWithSHA256,
				utls.PKCS1WithSHA512, utls.PKCS1WithSHA384, utls.PKCS1WithSHA256,
			}},
			&utls.SNIExtension{},
			&utls.ALPNExtension{AlpnProtocols: []string{"http/1.1"}},
			&utls.SupportedPointsExtension{SupportedPoints: []byte{0}},
			&utls.PSKKeyExchangeModesExtension{Modes: []uint8{utls.PskModeDHE}},
		},
	}
}

type rustlsConn struct{ *utls.UConn }

func (c *rustlsConn) ConnectionState() tls.ConnectionState {
	cs := c.UConn.ConnectionState()
	return tls.ConnectionState{
		Version: cs.Version, HandshakeComplete: cs.HandshakeComplete,
		DidResume: cs.DidResume, CipherSuite: cs.CipherSuite,
		NegotiatedProtocol: cs.NegotiatedProtocol, ServerName: cs.ServerName,
		PeerCertificates: cs.PeerCertificates, VerifiedChains: cs.VerifiedChains,
	}
}

// getCodexProxyURL returns the proxy URL for Codex requests from env var.
// Format: http://user:pass@host:port
func getCodexProxyURL() *url.URL {
	proxyStr := os.Getenv("CODEX_PROXY_URL")
	if proxyStr == "" {
		return nil
	}
	u, err := url.Parse(proxyStr)
	if err != nil {
		return nil
	}
	return u
}

// rustlsDialer creates TLS connections with rustls-like fingerprint
type rustlsDialer struct {
	dialer   *net.Dialer
	proxyURL *url.URL
}

func newRustlsDialer() *rustlsDialer {
	return &rustlsDialer{
		dialer: &net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		},
		proxyURL: getCodexProxyURL(),
	}
}

func (d *rustlsDialer) DialTLSContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
		port = "443"
		addr = net.JoinHostPort(host, port)
	}

	var rawConn net.Conn

	if d.proxyURL != nil {
		// Connect through HTTP CONNECT proxy
		proxyConn, err := d.dialer.DialContext(ctx, "tcp", d.proxyURL.Host)
		if err != nil {
			return nil, fmt.Errorf("dial proxy: %w", err)
		}

		// Send CONNECT request
		connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n", addr, addr)
		if d.proxyURL.User != nil {
			auth := d.proxyURL.User.Username()
			if pass, ok := d.proxyURL.User.Password(); ok {
				auth += ":" + pass
			}
			connectReq += "Proxy-Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte(auth)) + "\r\n"
		}
		connectReq += "\r\n"

		if _, err := proxyConn.Write([]byte(connectReq)); err != nil {
			proxyConn.Close()
			return nil, fmt.Errorf("write CONNECT: %w", err)
		}

		// Read CONNECT response
		br := bufio.NewReader(proxyConn)
		resp, err := http.ReadResponse(br, nil)
		if err != nil {
			proxyConn.Close()
			return nil, fmt.Errorf("read CONNECT response: %w", err)
		}
		resp.Body.Close()

		if resp.StatusCode != 200 {
			proxyConn.Close()
			return nil, fmt.Errorf("CONNECT failed: %s", resp.Status)
		}

		rawConn = proxyConn
	} else {
		// Direct connection
		rawConn, err = d.dialer.DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}
	}

	// Do TLS handshake with rustls fingerprint
	config := &utls.Config{
		ServerName:         host,
		InsecureSkipVerify: false,
	}

	uConn := utls.UClient(rawConn, config, utls.HelloCustom)
	if err := uConn.ApplyPreset(rustlsSpec()); err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("apply preset: %w", err)
	}

	if err := uConn.HandshakeContext(ctx); err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("TLS handshake: %w", err)
	}

	return &rustlsConn{UConn: uConn}, nil
}

// createRustlsTransport creates an http.Transport with rustls-like TLS fingerprint
func createRustlsTransport() *http.Transport {
	dialer := newRustlsDialer()

	return &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		DialTLSContext:        dialer.DialTLSContext,
		TLSHandshakeTimeout:   10 * time.Second,
		IdleConnTimeout:       90 * time.Second,
		ResponseHeaderTimeout: 0,
		ExpectContinueTimeout: 5 * time.Second,
		MaxIdleConns:          200,
		MaxIdleConnsPerHost:   50,
		ForceAttemptHTTP2:     false, // rustls uses HTTP/1.1
	}
}

// rustlsHybridTransport uses rustls fingerprint for chatgpt.com, standard for others
type rustlsHybridTransport struct {
	rustls   *http.Transport
	standard http.RoundTripper
	mu       sync.Mutex
}

func newRustlsHybridTransport(standard http.RoundTripper) *rustlsHybridTransport {
	return &rustlsHybridTransport{
		rustls:   createRustlsTransport(),
		standard: standard,
	}
}

func (h *rustlsHybridTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	host := strings.ToLower(req.URL.Hostname())
	if host == "" {
		host = strings.ToLower(req.URL.Host)
	}
	if host == "chatgpt.com" || strings.HasSuffix(host, ".chatgpt.com") || host == "auth.openai.com" {
		return h.rustls.RoundTrip(req)
	}
	return h.standard.RoundTrip(req)
}

var _ http.RoundTripper = (*rustlsHybridTransport)(nil)

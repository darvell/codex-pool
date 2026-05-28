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
	"strings"
	"sync"
	"time"

	utls "github.com/refraction-networking/utls"
)

// bunSpec returns a ClientHelloSpec matching Bun 1.3.12's TLS fingerprint.
// Captured from tls.peet.ws on 2026-05-26.
// JA3: 44f88fca027f27bab4bb08d4af15f23e
// JA4: t13d1714h1_5b57614c22b0_7baf387fc6ff
//
// Key differences from Chrome/Go default:
//   - ALPN: h2 + http/1.1 (modified from Bun's http/1.1-only for performance)
//   - No GREASE values (except ECH extension)
//   - 17 cipher suites including CBC and RSA key exchange
//   - X25519 key share only (no MLKEM)
//   - ECH extension 65037 present
func bunSpec() *utls.ClientHelloSpec {
	return &utls.ClientHelloSpec{
		TLSVersMin: utls.VersionTLS12,
		TLSVersMax: utls.VersionTLS13,
		CipherSuites: []uint16{
			// TLS 1.3 ciphers (order matters for JA3)
			utls.TLS_AES_128_GCM_SHA256,
			utls.TLS_AES_256_GCM_SHA384,
			utls.TLS_CHACHA20_POLY1305_SHA256,
			// ECDHE ciphers
			utls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			utls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			utls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			utls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			utls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			utls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
			// ECDHE CBC ciphers
			utls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
			utls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			utls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
			utls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			// RSA key exchange ciphers (Bun includes these)
			utls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			utls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			utls.TLS_RSA_WITH_AES_128_CBC_SHA,
			utls.TLS_RSA_WITH_AES_256_CBC_SHA,
			// Renegotiation info SCSV
			utls.FAKE_TLS_EMPTY_RENEGOTIATION_INFO_SCSV,
		},
		Extensions: []utls.TLSExtension{
			// server_name
			&utls.SNIExtension{},
			// ECH extension (65037) - Bun uses BoringSSL config
			&utls.GREASEEncryptedClientHelloExtension{},
			// extended_master_secret
			&utls.ExtendedMasterSecretExtension{},
			// renegotiation_info
			&utls.RenegotiationInfoExtension{Renegotiation: utls.RenegotiateOnceAsClient},
			// supported_groups: X25519, P-256, P-384
			&utls.SupportedCurvesExtension{Curves: []utls.CurveID{
				utls.X25519,
				utls.CurveP256,
				utls.CurveP384,
			}},
			// ec_point_formats
			&utls.SupportedPointsExtension{SupportedPoints: []byte{0}},
			// session_ticket
			&utls.SessionTicketExtension{},
			// ALPN: http/1.1 only (Bun does NOT negotiate h2)
			&utls.ALPNExtension{AlpnProtocols: []string{"http/1.1"}},
			// status_request (OCSP stapling)
			&utls.StatusRequestExtension{},
			// signature_algorithms
			&utls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []utls.SignatureScheme{
				utls.ECDSAWithP256AndSHA256,
				utls.ECDSAWithP384AndSHA384,
				utls.ECDSAWithP521AndSHA512,
				utls.PSSWithSHA256,
				utls.PSSWithSHA384,
				utls.PSSWithSHA512,
				utls.PKCS1WithSHA256,
				utls.PKCS1WithSHA384,
				utls.PKCS1WithSHA512,
				utls.ECDSAWithSHA1,
				utls.PKCS1WithSHA1,
			}},
			// signed_certificate_timestamp
			&utls.SCTExtension{},
			// key_share: X25519 only (no MLKEM)
			&utls.KeyShareExtension{KeyShares: []utls.KeyShare{
				{Group: utls.X25519},
			}},
			// psk_key_exchange_modes
			&utls.PSKKeyExchangeModesExtension{Modes: []uint8{utls.PskModeDHE}},
			// supported_versions: TLS 1.3, 1.2
			&utls.SupportedVersionsExtension{Versions: []uint16{
				utls.VersionTLS13,
				utls.VersionTLS12,
			}},
		},
	}
}

// bunConn wraps utls.UConn to satisfy the tls.ConnectionState interface.
type bunConn struct{ *utls.UConn }

func (c *bunConn) ConnectionState() tls.ConnectionState {
	cs := c.UConn.ConnectionState()
	return tls.ConnectionState{
		Version:         cs.Version,
		HandshakeComplete: cs.HandshakeComplete,
		DidResume:       cs.DidResume,
		CipherSuite:     cs.CipherSuite,
		NegotiatedProtocol: cs.NegotiatedProtocol,
		ServerName:      cs.ServerName,
		PeerCertificates: cs.PeerCertificates,
		VerifiedChains:  cs.VerifiedChains,
	}
}

// bunDialer creates TLS connections with Bun-like fingerprint.
type bunDialer struct {
	dialer   *net.Dialer
	proxyURL *url.URL
}

func newBunDialer() *bunDialer {
	return &bunDialer{
		dialer: &net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		},
		proxyURL: getCodexProxyURL(),
	}
}

func (d *bunDialer) DialTLSContext(ctx context.Context, network, addr string) (net.Conn, error) {
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

	// Do TLS handshake with Bun fingerprint
	config := &utls.Config{
		ServerName:         host,
		InsecureSkipVerify: false,
	}

	uConn := utls.UClient(rawConn, config, utls.HelloCustom)
	if err := uConn.ApplyPreset(bunSpec()); err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("apply bun preset: %w", err)
	}

	if err := uConn.HandshakeContext(ctx); err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("TLS handshake: %w", err)
	}

	return &bunConn{UConn: uConn}, nil
}

// createBunTransport creates an http.Transport with Bun-like TLS fingerprint.
func createBunTransport() *http.Transport {
	dialer := newBunDialer()

	tr := &http.Transport{
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
	}
	return tr
}

// bunHybridTransport uses Bun fingerprint for api.anthropic.com, standard for others.
type bunHybridTransport struct {
	bun      *http.Transport
	standard http.RoundTripper
	mu       sync.Mutex
}

func newBunHybridTransport(standard http.RoundTripper) *bunHybridTransport {
	return &bunHybridTransport{
		bun:      createBunTransport(),
		standard: standard,
	}
}

func (h *bunHybridTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	host := strings.ToLower(req.URL.Hostname())
	if host == "" {
		host = strings.ToLower(req.URL.Host)
	}
	// Only use Bun fingerprint for Anthropic API traffic
	if host == "api.anthropic.com" || strings.HasSuffix(host, ".api.anthropic.com") {
		return h.bun.RoundTrip(req)
	}
	return h.standard.RoundTrip(req)
}

var _ http.RoundTripper = (*bunHybridTransport)(nil)

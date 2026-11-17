package main

import (
	"bytes"
	"encoding/binary"
	"image/png"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestFaviconIsPublicAndSupportsHEAD(t *testing.T) {
	h := &proxyHandler{cfg: &config{}}
	want, err := friendContent.ReadFile("templates/assets/favicon.ico")
	if err != nil {
		t.Fatal(err)
	}
	for _, method := range []string{http.MethodGet, http.MethodHead} {
		t.Run(method, func(t *testing.T) {
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, httptest.NewRequest(method, "/favicon.ico", nil))
			if rr.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200", rr.Code)
			}
			if got := rr.Header().Get("Content-Type"); got != "image/x-icon" {
				t.Fatalf("Content-Type = %q", got)
			}
			if got := rr.Header().Get("Cache-Control"); got != "public, max-age=86400" {
				t.Fatalf("Cache-Control = %q", got)
			}
			if method == http.MethodGet && !bytes.Equal(rr.Body.Bytes(), want) {
				t.Fatal("response differs from embedded favicon")
			}
			if method == http.MethodHead && rr.Body.Len() != 0 {
				t.Fatal("HEAD must not return a body")
			}
		})
	}
}

func TestFaviconContainsTransparentSizes(t *testing.T) {
	data, err := friendContent.ReadFile("templates/assets/favicon.ico")
	if err != nil {
		t.Fatal(err)
	}
	if len(data) < 54 || binary.LittleEndian.Uint16(data[:2]) != 0 ||
		binary.LittleEndian.Uint16(data[2:4]) != 1 || binary.LittleEndian.Uint16(data[4:6]) != 3 {
		t.Fatal("expected ICO header with three entries")
	}
	for i, size := range []int{16, 32, 48} {
		entry := data[6+i*16 : 6+(i+1)*16]
		if int(entry[0]) != size || int(entry[1]) != size {
			t.Fatalf("entry %d has wrong dimensions", i)
		}
		length := uint64(binary.LittleEndian.Uint32(entry[8:12]))
		offset := uint64(binary.LittleEndian.Uint32(entry[12:16]))
		if offset < 54 || length == 0 || offset+length > uint64(len(data)) {
			t.Fatalf("entry %d has invalid payload bounds", i)
		}
		image, err := png.Decode(bytes.NewReader(data[offset : offset+length]))
		if err != nil {
			t.Fatalf("entry %d: %v", i, err)
		}
		if image.Bounds().Dx() != size || image.Bounds().Dy() != size {
			t.Fatalf("entry %d payload has wrong dimensions", i)
		}
		_, _, _, alpha := image.At(0, 0).RGBA()
		if alpha != 0 {
			t.Fatalf("entry %d lost transparent padding", i)
		}
	}
}

func TestAllPageHeadsLinkFavicon(t *testing.T) {
	h := &proxyHandler{cfg: &config{}}
	for _, page := range []struct {
		path  string
		serve http.HandlerFunc
	}{
		{path: "/app", serve: h.servePassportSPA},
		{path: "/friend", serve: h.serveFriendLanding},
		{path: "/cute-code", serve: h.serveCuteCodeLanding},
	} {
		t.Run(page.path, func(t *testing.T) {
			rr := httptest.NewRecorder()
			page.serve(rr, httptest.NewRequest(http.MethodGet, "http://example.com"+page.path, nil))
			if rr.Code != http.StatusOK {
				t.Fatalf("page status = %d", rr.Code)
			}
			head, _, found := strings.Cut(rr.Body.String(), "</head>")
			if !found || !strings.Contains(head, `rel="icon" href="/favicon.ico"`) {
				t.Fatal("served page head must link the favicon")
			}
		})
	}
}

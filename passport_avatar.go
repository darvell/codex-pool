package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"image"
	_ "image/jpeg"
	"image/png"
	"io"
	"net/http"
	"strings"
	"time"

	"go.etcd.io/bbolt"
	"golang.org/x/image/draw"
)

const bucketPassportAvatars = "passport_avatars"

type passportAvatar struct {
	PNG       []byte    `json:"png"`
	ETag      string    `json:"etag"`
	UpdatedAt time.Time `json:"updated_at"`
}

func normalizeAvatar(src []byte) ([]byte, error) {
	if len(src) == 0 || len(src) > 2<<20 {
		return nil, errors.New("avatar must be between 1 byte and 2 MB")
	}
	cfg, format, err := image.DecodeConfig(bytes.NewReader(src))
	if err != nil {
		return nil, errors.New("avatar must be a valid PNG or JPEG")
	}
	if format != "png" && format != "jpeg" {
		return nil, errors.New("avatar must be PNG or JPEG")
	}
	if cfg.Width < 16 || cfg.Height < 16 || cfg.Width > 4096 || cfg.Height > 4096 || int64(cfg.Width)*int64(cfg.Height) > 16_000_000 {
		return nil, errors.New("avatar dimensions must be 16–4096px")
	}
	img, _, err := image.Decode(bytes.NewReader(src))
	if err != nil {
		return nil, errors.New("avatar decode failed")
	}
	b := img.Bounds()
	side := b.Dx()
	if b.Dy() < side {
		side = b.Dy()
	}
	x := b.Min.X + (b.Dx()-side)/2
	y := b.Min.Y + (b.Dy()-side)/2
	square := image.NewRGBA(image.Rect(0, 0, side, side))
	draw.Draw(square, square.Bounds(), img, image.Pt(x, y), draw.Src)
	dst := image.NewRGBA(image.Rect(0, 0, 128, 128))
	draw.CatmullRom.Scale(dst, dst.Bounds(), square, square.Bounds(), draw.Over, nil)
	var out bytes.Buffer
	if err := png.Encode(&out, dst); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func (p *PassportStore) saveAvatar(principalID string, raw []byte) (*passportAvatar, error) {
	pngData, err := normalizeAvatar(raw)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(pngData)
	a := &passportAvatar{PNG: pngData, ETag: hex.EncodeToString(sum[:12]), UpdatedAt: time.Now().UTC()}
	v, _ := json.Marshal(a)
	if err = p.db.Update(func(tx *bbolt.Tx) error { return tx.Bucket([]byte(bucketPassportAvatars)).Put([]byte(principalID), v) }); err != nil {
		return nil, err
	}
	p.mu.Lock()
	if pr := p.principals[principalID]; pr != nil {
		pr.AvatarUpdatedAt = &a.UpdatedAt
		pv, _ := json.Marshal(pr)
		err = p.db.Update(func(tx *bbolt.Tx) error { return tx.Bucket([]byte(bucketPrincipals)).Put([]byte(pr.ID), pv) })
	}
	p.mu.Unlock()
	return a, err
}
func (p *PassportStore) avatar(principalID string) (*passportAvatar, error) {
	var a passportAvatar
	err := p.db.View(func(tx *bbolt.Tx) error {
		v := tx.Bucket([]byte(bucketPassportAvatars)).Get([]byte(principalID))
		if v == nil {
			return errors.New("not found")
		}
		return json.Unmarshal(v, &a)
	})
	return &a, err
}
func (p *PassportStore) updateNickname(principalID, nickname string) error {
	nickname = strings.TrimSpace(nickname)
	if len([]rune(nickname)) > 48 {
		return errors.New("nickname must be 48 characters or fewer")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	pr := p.principals[principalID]
	if pr == nil {
		return errors.New("principal not found")
	}
	pr.DisplayName = nickname
	v, _ := json.Marshal(pr)
	return p.db.Update(func(tx *bbolt.Tx) error { return tx.Bucket([]byte(bucketPrincipals)).Put([]byte(pr.ID), v) })
}

func (h *proxyHandler) handlePassportProfile(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	pr, s := h.passport.authenticate(r)
	if pr == nil {
		respondJSONError(w, 401, "unauthorized")
		return
	}
	if r.Method != http.MethodPatch {
		http.Error(w, "method not allowed", 405)
		return
	}
	if !h.passportCSRF(r, s) {
		respondJSONError(w, 403, "csrf validation failed")
		return
	}
	var q struct {
		Nickname string `json:"nickname"`
	}
	if json.NewDecoder(r.Body).Decode(&q) != nil {
		respondJSONError(w, 400, "invalid json")
		return
	}
	if err := h.passport.updateNickname(pr.ID, q.Nickname); err != nil {
		respondJSONError(w, 400, err.Error())
		return
	}
	respondJSON(w, publicPrincipal(h.passport.principal(pr.ID)))
}
func (h *proxyHandler) handlePassportAvatarUpload(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	pr, s := h.passport.authenticate(r)
	if pr == nil {
		respondJSONError(w, 401, "unauthorized")
		return
	}
	if r.Method != http.MethodPut {
		http.Error(w, "method not allowed", 405)
		return
	}
	if !h.passportCSRF(r, s) {
		respondJSONError(w, 403, "csrf validation failed")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 2<<20))
	if err != nil {
		respondJSONError(w, 413, "avatar exceeds 2 MB")
		return
	}
	a, err := h.passport.saveAvatar(pr.ID, body)
	if err != nil {
		respondJSONError(w, 400, err.Error())
		return
	}
	respondJSON(w, map[string]any{"avatar_url": "/api/avatars/" + pr.ID + "?v=" + a.ETag})
}
func (h *proxyHandler) handlePassportAvatar(w http.ResponseWriter, r *http.Request) {
	viewer, _ := h.passport.authenticate(r)
	if viewer == nil {
		http.Error(w, "unauthorized", 401)
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/avatars/")
	if viewer.Kind == PrincipalGuest && viewer.ID != id {
		http.Error(w, "forbidden", 403)
		return
	}
	a, err := h.passport.avatar(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if r.Header.Get("If-None-Match") == `"`+a.ETag+`"` {
		w.WriteHeader(304)
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "private, max-age=86400")
	w.Header().Set("ETag", `"`+a.ETag+`"`)
	_, _ = w.Write(a.PNG)
}

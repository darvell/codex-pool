// realtime-voice-smoke proves the pool's browser-style Realtime path without a
// browser: pool credential -> ephemeral client secret -> direct WebRTC call.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/pion/rtp"
	"github.com/pion/webrtc/v4"
	"github.com/pion/webrtc/v4/pkg/media"
	"github.com/pion/webrtc/v4/pkg/media/oggreader"
)

type clientSecretResponse struct {
	Value string `json:"value"`
}

func main() {
	var (
		poolURL     = flag.String("pool-url", envOr("POOL_URL", "https://codex.ppflix.net"), "codex-pool URL")
		token       = flag.String("token", os.Getenv("POOL_TOKEN"), "pool JWT; prefer POOL_TOKEN")
		model       = flag.String("model", "gpt-realtime-2.1", "Realtime model")
		text        = flag.String("say", "Hello. Please briefly confirm that you can hear me.", "text synthesized with macOS say")
		audio       = flag.String("audio", "", "audio file to send instead of -say")
		opusOgg     = flag.String("opus-ogg", "", "pre-encoded 48 kHz Opus Ogg file; avoids requiring ffmpeg on this host")
		voice       = flag.String("voice", "marin", "Realtime output voice")
		liveViaPool = flag.Bool("live-via-pool", false, "send a GPT Live SDP offer through the pool's Codex OAuth adapter (diagnostic)")
		timeout     = flag.Duration("timeout", 45*time.Second, "whole-call timeout")
	)
	flag.Parse()
	if strings.TrimSpace(*token) == "" {
		fatalf("POOL_TOKEN (or -token) is required; never put it in browser code")
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	input := ""
	cleanup := func() {}
	if *opusOgg == "" {
		var err error
		input, cleanup, err = inputAudio(*audio, *text)
		if err != nil {
			fatalf("prepare input: %v", err)
		}
	}
	defer cleanup()

	signalURL := "https://api.openai.com/v1/realtime/calls"
	signalCredential := ""
	if *liveViaPool {
		signalURL = strings.TrimRight(*poolURL, "/") + "/v1/live"
		signalCredential = *token
		fmt.Println("sending GPT Live SDP through the pool")
	} else {
		secret, err := createClientSecret(ctx, *poolURL, *token, *model, *voice)
		if err != nil {
			fatalf("create pooled client secret: %v", err)
		}
		if !strings.HasPrefix(secret, "ek_") {
			fatalf("pool returned a non-ephemeral client secret")
		}
		signalCredential = secret
		fmt.Println("pool issued ephemeral client secret")
	}

	if err := runWebRTC(ctx, signalURL, signalCredential, *model, *voice, input, *opusOgg, *liveViaPool); err != nil {
		fatalf("realtime call: %v", err)
	}
}

func createClientSecret(ctx context.Context, poolURL, token, model, voice string) (string, error) {
	body, _ := json.Marshal(map[string]any{"session": map[string]any{
		"type": "realtime", "model": model,
		"audio":        map[string]any{"output": map[string]any{"voice": voice}},
		"instructions": "You are a concise voice assistant. Answer the speaker directly.",
	}})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(poolURL, "/")+"/v1/realtime/client_secrets", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 32<<10))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(data)))
	}
	var result clientSecretResponse
	if err := json.Unmarshal(data, &result); err != nil {
		return "", err
	}
	return result.Value, nil
}

func runWebRTC(ctx context.Context, signalURL, credential, model, voice, input, opusOgg string, live bool) error {
	pc, err := webrtc.NewPeerConnection(webrtc.Configuration{})
	if err != nil {
		return err
	}
	defer pc.Close()

	track, err := webrtc.NewTrackLocalStaticSample(webrtc.RTPCodecCapability{MimeType: webrtc.MimeTypeOpus, ClockRate: 48000, Channels: 2}, "audio", "realtime-voice-smoke")
	if err != nil {
		return err
	}
	if _, err := pc.AddTrack(track); err != nil {
		return err
	}
	channel, err := pc.CreateDataChannel("oai-events", nil)
	if err != nil {
		return err
	}
	channelOpen := make(chan struct{})
	channel.OnOpen(func() { close(channelOpen) })
	var receivedAudio atomic.Int64
	pc.OnTrack(func(remote *webrtc.TrackRemote, _ *webrtc.RTPReceiver) {
		for {
			_, _, err := remote.ReadRTP()
			if err != nil {
				return
			}
			receivedAudio.Add(1)
		}
	})
	done := make(chan error, 1)
	channel.OnMessage(func(msg webrtc.DataChannelMessage) {
		var event struct {
			Type  string          `json:"type"`
			Error json.RawMessage `json:"error"`
			Turn  struct {
				Role string `json:"role"`
			} `json:"turn"`
		}
		if json.Unmarshal(msg.Data, &event) != nil || event.Type == "" {
			return
		}
		switch event.Type {
		case "conversation.item.input_audio_transcription.completed":
			fmt.Println("input transcription completed")
		case "response.audio.delta":
			// RTP packets are counted separately; deltas prove the event channel too.
		case "response.done":
			select {
			case done <- nil:
			default:
			}
		case "turn.done":
			if event.Turn.Role == "assistant" {
				select {
				case done <- nil:
				default:
				}
			}
		case "error":
			select {
			case done <- fmt.Errorf("server error: %s", event.Error):
			default:
			}
		}
	})

	offer, err := pc.CreateOffer(nil)
	if err != nil {
		return err
	}
	gathered := webrtc.GatheringCompletePromise(pc)
	if err := pc.SetLocalDescription(offer); err != nil {
		return err
	}
	select {
	case <-gathered:
	case <-ctx.Done():
		return ctx.Err()
	}
	answer, err := createWebRTCCall(ctx, signalURL, credential, pc.LocalDescription().SDP, model, voice, live)
	if err != nil {
		return err
	}
	if err := pc.SetRemoteDescription(webrtc.SessionDescription{Type: webrtc.SDPTypeAnswer, SDP: answer}); err != nil {
		return err
	}
	select {
	case <-channelOpen:
	case <-ctx.Done():
		return ctx.Err()
	}

	if !live {
		update, _ := json.Marshal(map[string]any{"type": "session.update", "session": map[string]any{
			"type": "realtime", "model": model, "output_modalities": []string{"audio"},
			"audio":        map[string]any{"output": map[string]any{"voice": voice}},
			"instructions": "You are a concise voice assistant. Answer the speaker directly.",
		}})
		if err := channel.SendText(string(update)); err != nil {
			return err
		}
	}

	if opusOgg != "" {
		if err := streamOggOpus(ctx, track, opusOgg); err != nil {
			return err
		}
	} else if err := streamAudio(ctx, track, input); err != nil {
		return err
	}
	if !live {
		if err := channel.SendText(`{"type":"input_audio_buffer.commit"}`); err != nil {
			return err
		}
		if err := channel.SendText(`{"type":"response.create"}`); err != nil {
			return err
		}
	}
	select {
	case err := <-done:
		if err != nil {
			return err
		}
		fmt.Printf("response completed (%d remote audio RTP packets)\n", receivedAudio.Load())
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func streamOggOpus(ctx context.Context, track *webrtc.TrackLocalStaticSample, path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	reader, _, err := oggreader.NewWith(file)
	if err != nil {
		return err
	}
	for {
		payload, _, err := reader.ParseNextPage()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		if len(payload) == 0 {
			continue
		}
		if err := track.WriteSample(media.Sample{Data: payload, Duration: 20 * time.Millisecond}); err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(20 * time.Millisecond):
		}
	}
}

func createWebRTCCall(ctx context.Context, endpoint, credential, offer, model, voice string, live bool) (string, error) {
	var body io.Reader = strings.NewReader(offer)
	contentType := "application/sdp"
	if live {
		var form bytes.Buffer
		const boundary = "codex-pool-live-call-boundary"
		session, _ := json.Marshal(map[string]any{"model": model, "instructions": "You are a concise voice assistant. Answer the speaker directly.", "audio": map[string]any{"output": map[string]any{"voice": voice}}, "delegation": map[string]any{"type": "client"}})
		fmt.Fprintf(&form, "--%s\r\nContent-Disposition: form-data; name=\"sdp\"\r\nContent-Type: application/sdp\r\n\r\n%s\r\n", boundary, offer)
		fmt.Fprintf(&form, "--%s\r\nContent-Disposition: form-data; name=\"session\"\r\nContent-Type: application/json\r\n\r\n%s\r\n--%s--\r\n", boundary, session, boundary)
		body = &form
		contentType = "multipart/form-data; boundary=" + boundary
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, body)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+credential)
	req.Header.Set("Content-Type", contentType)
	if live {
		req.Header.Set("OpenAI-Alpha", "quicksilver=v2")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	responseBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("direct WebRTC call HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(responseBody)))
	}
	return string(responseBody), nil
}

func streamAudio(ctx context.Context, track *webrtc.TrackLocalStaticSample, input string) error {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		return err
	}
	defer conn.Close()
	port := conn.LocalAddr().(*net.UDPAddr).Port
	ffmpeg := exec.CommandContext(ctx, "ffmpeg", "-hide_banner", "-loglevel", "error", "-re", "-i", input, "-ac", "2", "-ar", "48000", "-c:a", "libopus", "-f", "rtp", fmt.Sprintf("rtp://127.0.0.1:%d?pkt_size=1200", port))
	if err := ffmpeg.Start(); err != nil {
		return err
	}
	ffmpegDone := make(chan error, 1)
	go func() { ffmpegDone <- ffmpeg.Wait() }()
	buf := make([]byte, 2048)
	for {
		_ = conn.SetReadDeadline(time.Now().Add(800 * time.Millisecond))
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				select {
				case err := <-ffmpegDone:
					return err
				default:
				}
				continue
			}
			return err
		}
		packet := &rtp.Packet{}
		if err := packet.Unmarshal(buf[:n]); err == nil {
			if err := track.WriteSample(media.Sample{Data: packet.Payload, Duration: 20 * time.Millisecond}); err != nil {
				return err
			}
		}
	}
}

func inputAudio(audio, text string) (string, func(), error) {
	if audio != "" {
		return audio, func() {}, nil
	}
	if _, err := exec.LookPath("say"); err != nil {
		return "", nil, errors.New("-audio is required when macOS say is unavailable")
	}
	path := filepath.Join(os.TempDir(), fmt.Sprintf("codex-pool-realtime-%d.aiff", time.Now().UnixNano()))
	if output, err := exec.Command("say", "-o", path, text).CombinedOutput(); err != nil {
		return "", nil, fmt.Errorf("say: %s", strings.TrimSpace(string(output)))
	}
	return path, func() { _ = os.Remove(path) }, nil
}

func envOr(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
func fatalf(format string, args ...any) { fmt.Fprintf(os.Stderr, format+"\n", args...); os.Exit(1) }

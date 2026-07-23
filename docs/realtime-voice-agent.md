# Realtime voice agents through codex-pool

This is the pool-compatible version of OpenAI's [Voice agents guide](https://developers.openai.com/api/docs/guides/voice-agents).

Use the pool only to create an ephemeral Realtime client secret. The client then makes its media connection directly to OpenAI with that short-lived secret.

```text
application server -- pool JWT --> codex-pool /v1/realtime/client_secrets
application server <-- ek_... -- codex-pool
browser, mobile app, or CLI -- ek_... + SDP --> api.openai.com/v1/realtime/calls
browser, mobile app, or CLI <============== WebRTC audio + events =============> OpenAI
```

The pool chooses and authenticates a Codex account while issuing the secret. That binds the direct WebRTC session to the selected pooled account without exposing its OAuth token.

## Use the verified CLI

`cmd/realtime-voice-smoke` is a real end-to-end probe, not a mock. It:

1. creates a Realtime client secret through the pool;
2. creates a direct WebRTC offer to `api.openai.com`;
3. synthesizes a short prompt with macOS `say` and streams it as Opus RTP;
4. waits for `response.done` and counts the returned audio RTP packets.

```bash
export POOL_URL=https://codex.ppflix.net
export POOL_TOKEN='pool user JWT'

go run ./cmd/realtime-voice-smoke \
  -say 'Hello. Please say the word verified and nothing else.'
```

The default input path needs macOS `say` and `ffmpeg`. On another platform, pass an audio file and let `ffmpeg` transcode it:

```bash
go run ./cmd/realtime-voice-smoke -audio ./prompt.wav
```

If the machine running the CLI has no `ffmpeg`, pre-encode the audio on another machine and use the `-opus-ogg` fallback:

```bash
ffmpeg -i prompt.wav -ac 2 -ar 48000 -c:a libopus \
  -frame_duration 20 -page_duration 20000 prompt.ogg
go run ./cmd/realtime-voice-smoke -opus-ogg prompt.ogg
```

The probe was validated against the production pool with a synthesized prompt: it received a pooled ephemeral secret, completed the direct WebRTC session, and received model audio before `response.done`.

## Application-server endpoint

Keep the long-lived pool credential on your server. Return only the `value` from the client-secret response to an already-authenticated application user.

```ts
// POST /api/realtime-token
export async function issueRealtimeToken(request: Request) {
  await requireSignedInUser(request);

  const response = await fetch(
    `${process.env.POOL_URL}/v1/realtime/client_secrets`,
    {
      method: "POST",
      headers: {
        Authorization: `Bearer ${process.env.POOL_TOKEN}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        session: {
          type: "realtime",
          model: "gpt-realtime-2.1",
          audio: { output: { voice: "marin" } },
          instructions: "You are a concise, helpful voice assistant.",
        },
      }),
    },
  );

  if (!response.ok) {
    throw new Error(`pool client-secret request failed: ${response.status}`);
  }
  const { value } = await response.json();
  return Response.json({ value }); // value starts with ek_ and is short-lived
}
```

Do not send `POOL_TOKEN` to the client, log it, or put it in a frontend bundle.

## `RealtimeAgent` and `RealtimeSession`

The official TypeScript starting point works unchanged once the browser receives the pooled ephemeral secret.

```ts
import { RealtimeAgent, RealtimeSession } from "@openai/agents/realtime";

const agent = new RealtimeAgent({
  name: "Pool voice assistant",
  instructions: "Be concise, natural, and helpful.",
});

const session = new RealtimeSession(agent, {
  model: "gpt-realtime-2.1",
});

const { value: ephemeralKey } = await fetch("/api/realtime-token", {
  method: "POST",
}).then((response) => response.json());

await session.connect({ apiKey: ephemeralKey });
```

Do **not** override the SDK's WebRTC call URL to the pool. The SDK's normal direct call to `https://api.openai.com/v1/realtime/calls` is correct after the pool has issued `ek_…`; it carries no pooled OAuth credential and is bound to the selected account already.

## Protocol details and failure modes

- Use the current GA Realtime shape. Do not send the legacy `OpenAI-Beta: responses_websockets=...` header; the pool strips it for native Realtime WebSockets.
- Browser-native WebSockets cannot attach an `Authorization` header. Prefer WebRTC plus a client secret for browser and mobile clients.
- `gpt-realtime-2.1` is the current official guide's model choice. Use `-model` on the probe to test another eligible Realtime model.
- A `401` from `/v1/realtime/client_secrets` means the application server's pool JWT is invalid or disabled. A `4xx` from `api.openai.com/v1/realtime/calls` after a successful secret means the SDP/session payload is invalid, not that the pool failed to select an account.

# Predict summary: streaming proxy latency

Goal: optimize long-running SSE and websocket sessions so the proxy is effectively invisible except for required routing, sanitization, usage accounting, and Codex cyber-policy handling.

## Consensus findings

| Rank | Finding | Severity | Confidence | Evidence | Action |
|---:|---|---|---:|---|---|
| 1 | Grok unsupported-field sanitization can be bypassed after format translation, which explains repeated `external_web_access` upstream errors. | High | 92% | `main.go:1701`, `main.go:1786`, `provider_grok.go:403` | Re-run Grok sanitization after request translation and again at the provider boundary before `RoundTrip`. |
| 2 | Pass-through SSE is already close to the desired byte-copy shape when response sampling is disabled, but streamed-body responses miss no-buffer headers because headers are written before SSE detection. | Medium | 88% | `main.go:3438`, `main.go:3444`, `main.go:4658` | Detect SSE and apply `X-Accel-Buffering: no` before `WriteHeader` in streamed-body path. |
| 3 | Codex non-cyber SSE and websocket traffic cannot be a blind copy path because policy suppression/swap decisions must happen before bytes are exposed. | High | 94% | `sse.go:155`, `cyber_swap_ws.go:270`, `cyber_swap_ws.go:298` | Keep bounded event/frame inspection only on those required paths; keep all other streaming paths write-through. |
| 4 | SSE heartbeat and flush wrappers can write concurrently with real data, which risks interleaved event bytes under long quiet streams. | Medium | 82% | `heartbeat.go:43`, `heartbeat.go:63`, `sse.go:112` | Serialize heartbeat writes with normal writes and keep heartbeat idle-only. |
| 5 | The default per-session Codex request pacer injects a 100 ms delay between turns. | Medium | 90% | `main.go:397` | Default the pacer to disabled, while preserving `CODEX_REQUEST_PACE_MS` for operators who want it. |
| 6 | Grok account coverage is present in routing/model configs but missing from friend/admin account management and status counters. | Medium | 93% | `router.go:459`, `status.go:94`, `templates/friend_landing.html:1834` | Add `/admin/grok`, status count, and friend-page Grok account list/import UI. |
| 7 | Suppression-mode SSE buffering is unbounded when an upstream sends bytes without event terminators. | Medium | 70% | `sse.go:163`, `sse.go:219` | Add the same bounded trim/drop behavior used by legacy scanning. |

Consensus view: the right optimization is not a single raw tunnel everywhere. The common case should copy and flush immediately with no response sampling, JSON parsing, or buffering. Required mutations should sit at narrow provider boundaries: request sanitization before upstream, event-boundary inspection only when Codex cyber-policy suppression is active, and websocket frame inspection only when Codex hot-swap state is needed.

Risk assessment: the highest product risk is Grok sanitization after translation, because it directly matches the user's repeated upstream error. The highest performance risk is accidental sampling/interception of streams that do not need it. The highest correctness risk is removing buffering where a policy decision has to be made before forwarding.
# Oversized Responses HTTP replay

## Confirmed code failure and production uncertainty

Against upstream main `9a327b3`, pooled oversized/chunked **identity-encoded** Responses requests already used lexical disk-backed rewriting. Gzip and zstd were excluded and instead encountered bounded wire buffering followed by bounded in-memory decompression. Codex credential-passthrough Responses also forced buffering for hosted-MCP filtering. Those branches could emit `request body exceeds replay buffer limit` independently of model token context capacity.

The reported client request was 19,896,433 serialized bytes; the preceding successful response accounted for 171,477 total tokens. Cached WebSocket deltas can conceal full-history size until the client reconstructs an HTTP fallback. These observations do **not** establish the deployed pool revision, effective limits, HTTP encoding, or exact rejecting production branch. The checkout's default RAM limit is 16 MiB, not a verified production setting. No private conversation or credentials were sent to a test upstream.

The recorded `upstream->client read: ... received close frame ... StatusMessageTooBig` is evidence of a peer-sent WebSocket close 1009. This checkout's Codex relay already applies a minimum 512 MiB local read ceiling. Increasing that ceiling cannot establish a fix for a remote peer's policy. This change deliberately leaves WebSocket limits unchanged and makes full HTTP replay independently viable.

## Implementation

Native Responses paths (including `/responses` and `/backend-api/codex/responses`, excluding compact) admit gzip/zstd bodies regardless of wire size; identity bodies enter disk handling when oversized or chunked. Decoding copies to a private temporary file under separate wire and decoded byte limits. A bounded lexical pass validates and transforms JSON without constructing the prompt's object graph or allocating its image strings.

Pooled Codex requests retain model/alias routing, required-plan admission, model suffix controls, reasoning effort caps, forced upstream streaming, text/tool schema sanitization, and hosted-MCP filtering. Native-context expansion and durable dispatch still happen after account selection; replay reads the current file and size even if expansion replaces it. Grok is re-read from the decoded source in a preserve-fields mode before its provider sanitizer, so Codex-only field drops and schema/effort normalization do not leak across routing. Authentication recovery reopens the complete transformed body.

BYOK Codex native Responses use a separate filtering mode: preserve client authorization, model, storage/stream flags, scalar input, exact numeric tool-schema tokens, and tool schemas rather than applying pooled Codex normalization. Hosted-MCP input/tools/tool choice remain filtered. Non-SSE responses are filtered before downstream headers under the RAM ceiling and fail closed if too large to inspect. This path does not select pool accounts or assume native-context ownership.

Every decoded request that fits the RAM ceiling returns to the existing buffered pipeline, preserving its provider transformations, retries, timeout selection and non-streaming aggregation. Oversized routes requiring unsupported whole-object provider transforms now fail explicitly instead of silently inheriting Codex transformations. This intentionally tightens existing oversized cross-provider behavior; it is not a general streaming translator for Mistral, Claude/ZAI, OpenCode, Kimi, etc. Compact and Chat/Messages-to-Responses translation remain outside this change. Pooled bodies larger than RAM still require `stream=true`.

## Resource controls and deployment

- `PROXY_MAX_INMEM_BODY_BYTES`: existing ordinary replay/whole-object ceiling (default 16 MiB).
- `PROXY_MAX_SPOOL_BODY_BYTES`: decoded Responses ceiling (default 1 GiB).
- `PROXY_MAX_WIRE_BODY_BYTES`: wire Responses ceiling; defaults to the configured spool ceiling. Set it independently to restrict uploads.
- `PROXY_RESPONSES_BODY_TIMEOUT_SECONDS`: disk upload/decompression deadline (default 120 seconds). Timeout closes the incoming body to interrupt blocked reads, returns HTTP 408, and releases files/admission; disconnected-client cancellation remains silent.
- Transformed output is bounded to the decoded ceiling plus 1 MiB fixed transformation headroom; Grok/native-context replacements are checked before dispatch.
- One independent production spool slot is held until upstream response/cleanup completes. It covers compressed bodies even when the wire body is tiny. The RAM rewrite gate remains separate.
- Zstd uses one decoder worker, low-memory mode, and a 64 MiB window/memory admission ceiling. Larger compression windows fail resource admission rather than allowing decoder allocations proportional to a 1 GiB body ceiling.
- JSON nesting, top-level field count, control strings, and individual tool definitions are bounded. Invalid escapes, malformed input, unsupported encodings and cancellation unwind temporary files and admission.

Temporary files use `os.CreateTemp` (private permissions) in the process temp directory (`TMPDIR`). During transformation, raw, transformed and one filtered intermediary value may coexist: provision approximately three times the decoded ceiling plus fixed headroom per admitted request. The raw file is removed before supported disk-backed generation. Native-context expansion has its existing independent expansion bounds. A single long SSE response holds the spool slot and queues other disk-backed requests; cancellation releases waiting requests. Configure client/request timeouts and disk monitoring accordingly. Temp files are cleaned on normal errors and cancellation; abrupt process termination can leave files, so operators should provision a private ephemeral temp directory and a safe startup/host cleanup policy. Do not use memory-backed `/tmp` if the goal is reducing RAM pressure.

Wire/decoded/transformed byte admission returns HTTP 413 with transport-specific error text; unsupported encodings return 415; malformed JSON returns 400. These are not model-context-exhaustion errors. Payload bodies are not logged by the new pooled disk path; existing optional passthrough body logging should remain disabled for private workloads.

## Regression evidence

`responses_fallback_test.go` simulates upstream WebSocket close 1009 through the actual relay, then verifies SHA-256 identity of a 20 MiB synthetic base64 image payload sent over HTTP in all six identity/gzip/zstd × known-length/chunked combinations. Compressed test bodies fit below the default 16 MiB RAM ceiling while decoded bodies exceed it. This models client fallback explicitly; it is not an execution of Pi's SDK fallback implementation.

Other tests cover compressed authentication recovery with byte-identical full-body replay, wire/decoded violations, output limits, blocked `io.Pipe` upload timeout/cleanup for pooled and BYOK requests, malformed JSON, admission cancellation/cleanup, BYOK request and non-SSE response filtering, exact integer preservation, required-plan routing, Grok field preservation, effort caps/suffixes, and compressed native-context account affinity/expansion/dispatch ordering. All upstreams are local mocks.

Production rollout should first record deployed revision and effective environment, verify `TMPDIR` capacity/storage type, and exercise a synthetic image-heavy request through the actual reverse proxy. Reverse-proxy upload limits and upstream HTTP admission remain independent ceilings. This PR makes no deployment changes and does not depend on historical-image retention.

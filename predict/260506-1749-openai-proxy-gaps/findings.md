# Findings

## P1: Responses subresource paths collapse to `/responses`

Severity: high
Confidence: high
Votes: 4/5 personas
Evidence: `main.go:463-467` maps almost every Responses path to `/responses`; `provider_codex.go:324-328` applies this for `/v1/responses*` and `/responses*`.
Empirical debug result: `GET/POST` path normalization probe showed `/v1/responses/resp_123`, `/v1/responses/resp_123/input_items`, and `/v1/responses/resp_123/cancel` all normalize to `/responses`.
Why it matters: OpenAI SDKs expose retrieve/cancel/delete/input-items style Responses operations. Even if Codex upstream does not support them, collapsing path suffixes can send the wrong request to the create endpoint instead of returning a valid OpenAI-shaped unsupported error.
Suggested next test: add handler tests for `GET /v1/responses/{id}`, `POST /v1/responses/{id}/cancel`, and `/input_items` asserting either correct upstream path or local OpenAI-shaped unsupported response.

## P2: Silent field stripping hides unsupported semantics

Severity: high
Confidence: high
Votes: 5/5 personas
Evidence: `main.go:509-526` deletes direct Responses fields including `temperature`, `top_p`, `max_output_tokens`, `parallel_tool_calls`, `metadata`, `logprobs`, `top_logprobs`; `format_translate_responses.go:332-355` legacy Completions only preserves prompt/model/user/conversation/cache fields; `format_translate_responses.go:11-164` Chat Completions drops fields such as `response_format`.
Why it matters: stripping is necessary for fields Codex rejects, but OpenAI-compatible clients expect semantics to be honored or rejected. Silent deletion means `max_output_tokens`, `n`, `echo`, `logprobs`, structured output, `metadata`, and `parallel_tool_calls` can produce successful-looking responses that violate caller intent.
Suggested next test: table-driven request translation tests for Responses, Chat Completions, and legacy Completions with unsupported-but-semantic fields. Decide per field: emulate, map to Codex equivalent, or reject with OpenAI error shape.

## P3: Hidden prompt caching is cross-user and full-request granular

Severity: high
Confidence: high
Votes: 3/5 personas
Evidence: `format_translate_responses.go:166-185` hashes only request semantic fields and emits `pc_` + 64 bits; it does not include pool user, origin, account, or tenant scope. `main.go:688-691` treats `prompt_cache_key` as a conversation identifier.
Empirical debug result: two identical request maps produced the same generated key: `pc_1d8dbc68b5db988b`.
Why it matters: hidden cache keys should improve reuse without correlating unrelated users or pinning unrelated requests together. Full-request hashing also changes every turn, so it misses the more useful stable-prefix cache behavior.
Suggested next test: two pool users, same body, inspect rewritten upstream bodies and account pinning. Then test two-turn conversation with same prefix plus new user message; compare keys.

## P4: SSE detection over-classifies successful JSON `/v1/*` responses as SSE

Severity: high
Confidence: high
Votes: 3/5 personas
Evidence: `provider_codex.go:344-349` returns true for any `/v1/` path regardless of `Content-Type`; main path corrects this only for `resp.StatusCode >= 400` at `main.go:1479-1483`; passthrough has similar correction at `main.go:3203-3207`.
Empirical debug result: `CodexProvider.DetectsSSE("/v1/models", "application/json")` returned `true`.
Why it matters: a 200 JSON response on a `/v1/*` path can go through SSE wrappers/translators, causing dropped bodies, wrong content-type, or heartbeat behavior. Current happy paths mostly force Codex to stream, but `/v1/models` and future `/v1/*` endpoints are exposed.
Suggested next test: fake upstream `200 application/json` for `/v1/models` and `/v1/responses/{id}` through the handler; assert body and content-type are untouched.

## P5: Translated Chat/Completions usage drops cache details

Severity: medium
Confidence: high
Votes: 3/5 personas
Evidence: `format_translate_responses.go:457-466` maps Responses usage to legacy Completions usage without `prompt_tokens_details.cached_tokens`; chat mapping similarly returns only `prompt_tokens`, `completion_tokens`, `total_tokens`. `format_translate_responses_sse.go:101-141` direct Responses buffering also emits only aggregate usage.
Empirical debug result: translating a Responses body with `usage.input_tokens_details.cached_tokens` produced Chat and Completions usage without cache details.
Why it matters: if the proxy is optimizing prompt caching behind the scenes, clients and accounting tools need cache details where OpenAI-compatible shapes support them.
Suggested next test: translate Responses usage with cached token details into Chat/Completions/Responses buffered shapes and assert `prompt_tokens_details.cached_tokens` appears where compatible.

## P6: Legacy Completions is valid for simple text but thin for older API semantics

Severity: medium
Confidence: high
Votes: 4/5 personas
Evidence: `format_translate_responses.go:332-355` ignores `n`, `best_of`, `echo`, `suffix`, `stop`, `logit_bias`, `logprobs`, sampling controls, and limits; `format_translate_responses.go:357-391` stringifies token-array prompts; `format_translate_responses.go:402-415` always emits one choice.
Why it matters: the response shape is valid for simple SDK calls, verified in production, but older clients relying on these fields can get a valid response with wrong semantics.
Suggested next test: `/v1/completions` with `n:2`, `echo:true`, `logprobs:1`, token-array prompt, and `suffix`; assert explicit OpenAI-shaped errors or implemented equivalents.

## P7: Native non-streaming Responses buffering loses non-text output items

Severity: medium
Confidence: high
Votes: 2/5 personas
Evidence: `main.go:1490-1503` buffers non-streaming direct Responses with `responsesBufferingWriter`; `format_translate_responses_sse.go:69-84` only accumulates `response.output_text.delta`; `format_translate_responses_sse.go:120-141` emits a single `output_text` message.
Why it matters: direct `/v1/responses` with tools, refusals, images, or other output items can be returned as an empty or text-only Response even if upstream emitted richer output.
Suggested next test: fake Responses SSE with only `response.completed.response.output` containing a function call or refusal; assert buffered Response preserves it.

## P8: Streaming parsers do not handle multiline SSE `data:` events

Severity: medium
Confidence: medium
Votes: 2/5 personas
Evidence: parsers assign `data = ...` per line, e.g. `format_translate_responses_sse.go:49-57`, `format_translate_responses_sse.go:184-192`, rather than concatenating multiple `data:` lines per SSE spec.
Why it matters: if upstream or an intermediary splits JSON across multiple `data:` lines, the proxy may parse only the last line and drop the event.
Suggested next test: feed a multi-line SSE event into each writer and assert the translated delta is emitted.

## P9: Large request bodies bypass translation/model routing

Severity: medium-high
Confidence: medium-high
Votes: 1/5 personas, preserved by anti-herd check
Evidence: streamed-body path is selected before body inspection; `main.go` sends large requests to `proxyRequestStreamed`, which cannot inspect model or translate chat/completions bodies.
Why it matters: default cap is large, but file/tool-heavy requests can cross it. Large `/v1/chat/completions` or `/v1/completions` to Codex could reach upstream in the wrong shape; large model-routed requests can miss model override.
Suggested next test: set `PROXY_MAX_INMEM_BODY_BYTES` low, send a large `/v1/chat/completions` body, and assert translation/routing still happens or request is rejected clearly.

## P10: Error shapes are not always OpenAI-compatible

Severity: medium-high
Confidence: high
Votes: 3/5 personas
Evidence: `main.go:1664-1674` passes Codex error bodies through unchanged for Chat/Completions translation; request translation setup errors use `http.Error` plain text around `main.go:1139-1149`.
Why it matters: SDKs expect `{"error":{"message":...}}`. Raw `{"detail":...}` or plain text degrades or breaks caller error handling.
Suggested next test: force a translated `/v1/chat/completions` upstream 400 `{"detail":"bad"}` and invalid request-body translation error; assert OpenAI-shaped errors.

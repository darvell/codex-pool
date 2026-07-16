# Component clusters

## OpenAI compatibility surface
Files: `format_translate.go`, `format_translate_responses.go`, `format_translate_responses_sse.go`, `format_translate_openai_test.go`.
Risk areas: unsupported parameters, legacy completions fields, tool-call deltas, multimodal content, valid SDK response shape.

## Proxy execution surface
Files: `main.go`, `proxy_stream_test.go`, `proxy_body_test.go`, `main_test.go`.
Risk areas: streaming vs buffered requests, path rewriting, retry behavior, false SSE detection, client disconnects, passthrough credential path.

## Codex provider surface
Files: `provider_codex.go`, `codex_fingerprint.go`, `provider_codex_test.go`, `codex_fingerprint_test.go`.
Risk areas: path normalization, SSE detection defaults, upstream fingerprint headers, usage parsing and rate-limit headers.

## Auth and user/passthrough surface
Files: `pool_users.go`, `admin_pool_users.go`, `claude_sdk_compat.go`, `main.go`.
Risk areas: fake pool tokens vs real provider credentials, passthrough translation parity, response shape when using user-owned OpenAI keys.

## Usage/cost/accounting surface
Files: `usage.go`, `usage_tracking.go`, `storage.go`, `analytics_store.go`, `rate_limit_headers.go`.
Risk areas: prompt cache key observability, cached-token accounting, usage callbacks during translated SSE buffering.

## UI/config surface
Files: `frontend.go`, `pi_models.go`, setup/config handlers.
Risk areas: generated OpenAI-compatible base URLs and model lists, but this pass did not find direct completions/Responses translation logic there.

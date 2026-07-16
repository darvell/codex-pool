# Codebase analysis

Scope: entire Go codebase, focused on OpenAI-compatible Responses and Completions proxying.
HEAD at run start: ca4d79d. Working tree contained modified proxy translation files plus pre-existing frontend/untracked files.

Core routing:
- `router.go:490-491` sends default API traffic into `proxyRequest`.
- `main.go:951-956` selects provider by path/header and account type.
- `provider_codex.go:316-322` matches all `/v1/` paths as Codex-capable.
- `provider_codex.go:324-341` normalizes `/v1/responses*` to `/responses`, `/v1/models` to `/models`, and leaves other `/v1/*` paths unchanged unless earlier translation rewrites them.

Request translation:
- `format_translate.go:45-55` detects `/v1/messages`, `/v1/chat/completions`, and `/v1/completions`.
- `main.go:1072-1118` chooses translation direction. Codex + `/v1/chat/completions` becomes `TranslateChatToResponses`; Codex + `/v1/completions` becomes `TranslateCompletionsToResponses`; direct Codex `/v1/responses` goes through `ensureCodexResponsesInstructions`.
- `main.go:1120-1166` rewrites translated request bodies and paths to `/v1/responses`.
- `format_translate_responses.go:11-164` translates chat completions messages/tools/tool_choice to Responses input/tools/tool_choice and injects `stream=true`, `store=false`, and `prompt_cache_key`.
- `format_translate_responses.go:332-355` translates legacy completions prompt to Responses input and injects `stream=true`, `store=false`, and `prompt_cache_key`.
- `main.go:476-527` sanitizes direct Responses requests for Codex by forcing `instructions`, `store=false`, `stream=true`, dropping unsupported params, and adding prompt cache key.

Response translation:
- `main.go:1472-1483` detects SSE and avoids treating non-SSE error JSON as SSE.
- `main.go:1490-1646` buffers Codex SSE into non-streaming Responses, Claude, completions, or chat shapes when client wanted non-streaming.
- `main.go:1646-1714` handles non-SSE translation responses.
- `main.go:1714-1838` streams translated SSE responses for completions/chat/Claude/Responses.
- `format_translate_responses.go:394-474` builds non-streaming legacy `text_completion` responses.
- `format_translate_responses_sse.go:147-419` builds streaming and buffered legacy completions responses.

Passthrough provider credentials:
- `main.go:3053-3300` handles real provider credentials. Codex passthrough rewrites `/v1/messages`, `/v1/chat/completions`, `/v1/completions` through `codexPassthroughRewrite`, tracks `passthroughTranslateDir`, and translates successful responses for completions/chat in both buffered and streaming paths.

Observed verification before predict run:
- `go test ./...` passed.
- OpenAI SDK 2.35.0 production probes passed for legacy completions, chat non-streaming, chat streaming, and Responses against `https://codex.ppflix.net/v1` with `gpt-5.4-mini`.
- Agents SDK 0.15.3 production probe passed via Responses mode.

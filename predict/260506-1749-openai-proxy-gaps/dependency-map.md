# Dependency map

Primary request flow:
`router.go:ServeHTTP` -> `proxyHandler.proxyRequest` -> `pickUpstream` -> provider selection -> body read -> model alias/suffix/model-route override -> format translation -> `tryOnce` -> response shape translation.

Codex provider dependencies:
- `ProviderRegistry.ForPath` and `CodexProvider.MatchesPath` route `/v1/*` to Codex unless headers/model override route elsewhere.
- `CodexProvider.NormalizePath` maps `/v1/responses*` to `/responses`, which means any OpenAI-compatible endpoint must be rewritten before upstream unless chatgpt.com supports that path.
- `CodexProvider.DetectsSSE` returns true for all `/v1/*`, so callers must correct false positives for JSON errors.

Translation dependencies:
- `TranslateDirection` enum in `format_translate.go` is consumed by request rewriting, response buffering, SSE streaming wrappers, debug logs, and passthrough response translation.
- Request translators in `format_translate_responses.go` depend on helper functions from `format_translate.go` (`extractTextContent`, `toInt64`) and `main.go` (`sanitizeCodexResponsesParams`).
- SSE writers in `format_translate_responses_sse.go` depend on Responses event names from Codex upstream: `response.created`, `response.output_text.delta`, `response.output_item.added`, `response.function_call_arguments.delta/done`, `response.output_item.done`, `response.completed`, `response.failed`.

Response-shape dependencies:
- OpenAI SDK typed parsing expects `object`, `model`, `choices`, `usage` for completions/chat and `object=response`, `output`, `usage` for Responses.
- Agents SDK Responses mode expects direct `/v1/responses` to return a valid Response model and `output_text` extractable from `output[].content[].text`.

Caching dependencies:
- `ensurePromptCacheKey` hashes request semantic fields and writes `prompt_cache_key` before upstream.
- Usage parsing can record `prompt_cache_key` when upstream echoes it (`provider_codex.go:239-241`, `usage.go:121`).
- Current cache key is not visible to OpenAI response clients unless upstream reports usage; shape translators do not add extra public fields.

Risk propagation:
- A missed unsupported param causes upstream 400 from ChatGPT Codex.
- A missed SSE/non-SSE classification causes JSON errors to be buffered as empty successful-looking responses.
- A missed response translation path causes SDK typed parsing failures or raw Responses JSON on legacy endpoints.
- A too-aggressive prompt cache key can accidentally reduce cache hit rate or couple semantically different requests if seed fields omit important context.

# Persona debates

Personas:
- OpenAI API compatibility architect
- SDK compatibility tester
- Streaming/protocol critic
- Prompt caching and usage accounting reviewer
- Security/reliability reviewer

## Round 1 independent findings

API compatibility architect prioritized official field coverage and object shape. Main claims: direct Responses fields are stripped (`main.go:509-526`), direct Responses non-streaming buffering can miss completed output if no deltas arrive (`format_translate_responses_sse.go:69-84`), Chat Completions lacks `created` (`format_translate_responses.go:568-579`), streaming chunks lack `created` and usage chunk semantics, legacy Completions is shallow (`format_translate_responses.go:332-419`), token-array prompts are stringified (`format_translate_responses.go:368-391`), SSE multiline data is not concatenated, and tool-call chat content should probably be null when tool calls exist.

SDK tester prioritized SDK method coverage. Main claims: Responses subresource paths collapse (`main.go:463-467`, `provider_codex.go:324-328`), structured output fields are dropped in chat translation, direct Responses fields are stripped (`main.go:476-526`), chat and stream objects omit standard fields, errors pass through in non-OpenAI shape (`main.go:1664-1674`), and legacy completions ignores many parameters.

Streaming/protocol critic prioritized protocol mechanics. Main claims: Codex `DetectsSSE` over-classifies all `/v1/*` (`provider_codex.go:344-349`), error bodies are truncated during classification, passthrough idle timeout is constructed but not applied (`main.go:3283-3290`), passthrough/client non-streaming detection differs, many Responses event types are silently dropped, native non-streaming Responses buffering loses tool calls, and Responses subresources collapse.

Prompt caching/usage reviewer prioritized hidden caching behavior. Main claims: generated `prompt_cache_key` is not user/origin scoped (`format_translate_responses.go:166-185`), key granularity hashes full request so multi-turn prefix cache reuse is poor, user-supplied keys are trusted and used as conversation IDs (`main.go:688-691`), cache usage details are stripped from public usage (`format_translate_responses_sse.go:101-141`, `format_translate_responses.go:457-466`), nested usage may double-record in some bodies, and key is only 64 bits.

Security/reliability reviewer prioritized auth/routing consequences. Main claims: large request bodies bypass model routing and translation (`main.go:1000-1007`, streamed path around `main.go:2434-2535`), real-looking provider tokens skip pool auth (`main.go:958-966`, `main.go:3006-3037`), deterministic cache keys are cross-user, passthrough idle timeout is ineffective, `DetectsSSE` over-classifies `/v1/*`, raw upstream shape is returned on translation failures (`main.go:1675-1710`), hosted tools can be dropped when routing Responses to Claude, and nested prompt cache keys may be missed in usage.

## Round 2 challenges

The SDK tester challenged the API architect's claim that missing `created` is high severity, because the Python SDK production probe parsed successfully. Consensus revised this to medium: not a current happy-path SDK blocker, but a compatibility gap for strict consumers and parity tests.

The streaming critic challenged direct Responses field stripping: because Codex upstream rejects some official OpenAI fields, preserving them may break production. Consensus reframed this as two separate issues: unsupported fields should not leak upstream, but silent deletion is still a semantic compatibility gap. For OpenAI-shaped proxying, unsupported-but-requested semantics should either be emulated or rejected with OpenAI error shape.

The caching reviewer challenged deterministic cache keys as both a performance aid and a privacy/routing risk. Consensus: hidden caching is desirable, but keys should be scoped and prefix-oriented. Same full prompt across users producing the same key is not a safe default for a shared pool.

The security reviewer challenged the passthrough auth finding because passthrough with real provider credentials may be an intentional feature. Consensus downgraded it for this report: relevant to policy, but not specifically missing Responses/Completions compatibility unless the project wants all traffic pool-authenticated.

The API architect challenged the Responses subresource finding because ChatGPT Codex upstream may not support those OpenAI resource operations. Consensus kept it high: if the public URL presents as OpenAI `/v1`, SDK methods should not be misrouted to create endpoint; unsupported operations need OpenAI-shaped 404/405/unsupported errors instead of path collapse.

## Anti-herd check

Minority findings preserved:
- Passthrough idle timeout bug is not Responses/Completions shape-specific, but it affects streaming reliability and was preserved as a medium operational finding.
- Large-body translation bypass may be rare under default 16 MiB body cap, but it is a serious correctness cliff for file-heavy or tool-heavy requests and was preserved.
- Cache key bit length is low priority compared with scoping and granularity, but kept as future hardening.

Rejected or downgraded:
- Missing `created` is not critical because current Python SDK probes passed.
- Provider-credential passthrough is a product policy decision, not automatically a bug.
- Directly forwarding all Responses official params is not viable while Codex upstream rejects them; compatibility should be emulation or structured rejection.

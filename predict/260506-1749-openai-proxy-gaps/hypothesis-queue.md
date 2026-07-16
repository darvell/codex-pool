# Hypothesis queue

1. Responses subresource paths are incorrectly collapsed to `/responses`.
Confidence: 0.98
Debug status: confirmed by path normalization probe.
Next action: decide whether to implement real upstream mapping or local OpenAI-shaped unsupported errors.

2. Silent stripping of semantic params is the biggest remaining OpenAI-compatibility gap.
Confidence: 0.95
Debug status: partially confirmed by code evidence and prior production `temperature` 400 before stripping.
Next action: create param support matrix for `/v1/responses`, `/v1/chat/completions`, `/v1/completions`: emulate, map, reject, or safely ignore.

3. Generated prompt cache keys should be scoped and prefix-oriented.
Confidence: 0.92
Debug status: confirmed identical bodies produce identical keys; not yet tested across real pool users/account pinning.
Next action: include tenant/user/origin/account scope, and derive key from stable prefix rather than full changing request where possible.

4. Successful JSON `/v1/*` responses can be misclassified as SSE.
Confidence: 0.9
Debug status: confirmed provider detection returns true for `/v1/models` with `application/json`; handler behavior still needs fake-upstream test.
Next action: make SSE detection content-type-first, with path fallback only for known streaming Codex endpoints.

5. Usage translation hides cached-token details.
Confidence: 0.88
Debug status: confirmed by translation probe.
Next action: preserve `input_tokens_details.cached_tokens` as `prompt_tokens_details.cached_tokens` in OpenAI-compatible shapes.

6. Legacy Completions should explicitly reject unsupported semantics rather than silently ignoring them.
Confidence: 0.86
Debug status: code evidence; production simple path passed.
Next action: table-test `n`, `best_of`, `echo`, `suffix`, `logprobs`, token-array prompts, `stop`, and choose behavior.

7. Native non-streaming Responses buffering drops non-text output items.
Confidence: 0.82
Debug status: code evidence; fake SSE replay still needed.
Next action: have `responsesBufferingWriter` preserve completed `response.output` and richer output items.

8. Error responses should be normalized to OpenAI error shape on public OpenAI endpoints.
Confidence: 0.8
Debug status: code evidence; fake upstream test still needed.
Next action: convert Codex `detail` and plain translation errors to `{"error":{"message":...,"type":...}}`.

9. Large request bodies bypass translation and model routing.
Confidence: 0.75
Debug status: code evidence; low-threshold integration test needed.
Next action: reject too-large translatable bodies with structured error or spool-and-inspect instead of streaming blindly.

10. SSE parser should concatenate multiline `data:` lines.
Confidence: 0.7
Debug status: code evidence; unit replay needed.
Next action: centralize SSE event parser and use it in all translation writers.

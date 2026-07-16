# Predict overview

Date: 2026-05-06
Scope: entire Go codebase
Goal: predict what may still be missing for OpenAI-compatible Responses and Completions proxying, including hidden prompt caching and valid response shapes.
Depth: standard, 5 personas, 2 debate rounds
Chain: debug
HEAD: ca4d79d

## Executive summary

The verified happy paths are good: simple legacy Completions, Chat Completions non-streaming, Chat Completions streaming, direct Responses, and Agents SDK Responses mode passed production probes with `gpt-5.4-mini`.

The remaining risk is not the basic SDK path. It is edge compatibility and policy: subresource paths, hidden/unsupported field behavior, richer Responses output items, cache key scoping, usage details, and SSE classification.

The user's design preference is that unsupported fields should be hidden where possible. That means the right target is not to forward every OpenAI field to Codex. The target is: emulate when cheap and safe; strip when Codex rejects but semantics are not critical; return valid OpenAI-shaped errors only when the requested semantic cannot be honestly honored and hiding it would create a misleading success.

## Severity breakdown

High: 4
Medium-high: 2
Medium: 4
Low: 0 in final ranked list

## Confirmed by debug probes

- `/v1/responses/{id}`, `/v1/responses/{id}/input_items`, and `/v1/responses/{id}/cancel` normalize to `/responses`.
- `DetectsSSE("/v1/models", "application/json")` returns `true`.
- Identical request semantic content generates identical hidden `prompt_cache_key`.
- Chat/Completions translation omits cached-token usage details.

## Main predictions

1. Responses subresource operations will misroute or produce wrong behavior unless locally handled.
2. Unsupported field hiding needs a field policy matrix so semantics are either emulated, stripped, or rejected deliberately.
3. Hidden prompt caching should be scoped by user/origin/account and should target stable prefixes, not the full changing request.
4. SSE detection should prefer `Content-Type` and known streaming endpoints rather than every `/v1/*` path.
5. Usage translation should preserve cache details in OpenAI-compatible shape.
6. Legacy Completions simple text is valid, but older semantics like `n`, `echo`, `suffix`, token-array prompts, and `logprobs` need explicit behavior.
7. Native non-streaming Responses buffering should preserve richer output items from completed responses, not only text deltas.
8. Public OpenAI endpoints should return OpenAI-shaped errors even when the proxy hides unsupported upstream fields.

## Composite score

findings_confirmed: 4
findings_probable: 6
minority_opinions_preserved: 3
personas_active: 5/5
rounds_completed: 2/2
anti_herd_passed: yes
predict_score: 60 + 48 + 9 + 20 + 10 + 5 = 152

## Artifacts

- `codebase-analysis.md`
- `dependency-map.md`
- `component-clusters.md`
- `persona-debates.md`
- `findings.md`
- `hypothesis-queue.md`
- `handoff.json`
- `predict-results.tsv`

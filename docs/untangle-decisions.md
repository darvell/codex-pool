# Refactor decisions

Preserve public endpoints, installed credential formats, historical accounting, frontend layout, client setup output, bounded-memory request processing, provider precedence, and retry budgets. Structural changes may share policy while retaining distinct protocol engines. Comments that repeat implementation are removed. Test cleanup follows implementation so existing coverage remains available during extraction.

Baseline: `go test ./...` passes; frontend tests pass (47 tests); frontend production build passes. Findings below refer to the source before refactoring.

## Request routing and configuration

- Define external model-route metadata once, with explicit buffered and streamed policies.
  - `main.go:1445` and `main.go:1625` independently enumerate providers and canonicalization.
  - `provider_opencode_go.go:365` and `antigravity_translate.go:67` repeat provider-claim precedence.
  - `cyber_swap_ws.go` repeats the same external-provider claims to reject HTTP-only models on Codex WebSockets.
  - Buffered discovery intentionally differs from streamed discovery. Mistral normalization occurs after format translation. Preserve both distinctions.
- Make loaded configuration an explicit dependency of startup and credential services.
  - `main.go:128` publishes `globalConfigFile`; `pool_users.go:527` reads it indirectly.
  - `main.go:538` reads routing maps from the same global, outside the configuration result.
  - `watcher.go:147` and `pool.go:1082` maintain separate threshold values. Apply runtime settings through an explicit operation.
- Centralize pooled request authentication and proxy-header cleanup at outbound construction.
  - `main.go:4592` and `main.go:5967` repeat credential removal and model-specific OpenCode dispatch.
  - The streamed path individually deletes Cloudflare headers already removed by `removeConflictingProxyHeaders`.
  - Preserve provider-credential passthrough and translated-header rules separately.

## Provider capabilities and model data

- Give discovery request construction and parsing an explicit provider capability; reuse it for catalog admission.
  - `provider_model_discovery.go:231`, `:281`, `admin_kimi.go:60`, and `admin_mistral.go:52` repeat endpoint/auth/parser knowledge.
  - Retain Codex fingerprint parameters, Grok paths, Mistral filtering, and optional Zen enrichment.
- Share model descriptor projection and explicit profile metadata.
  - `pool_models.go:72` and `provider_model_discovery.go:486` repeat protocol and adapter construction.
  - `model_catalog.go:23`, `model_alias.go:11`, and `pricing.go:227` independently describe long-context profiles.
  - Keep request aliases, billing aliases, static profiles, and discovered entitlements distinct where their behavior differs.
- Bind API-key admission metadata instead of passing correlated account type/directory strings.
  - `admin_kimi.go:172` accepts independently supplied type and subdirectory.
  - API-key handlers repeat decoding and save/reload behavior while validation protocols differ.
- Make provider HTTP and translation dependencies explicit.
  - `provider_claude.go:105` ignores its context/transport while `claude_auth.go` uses the global client.
  - `admin_claude.go:231` repeats profile retrieval.
  - `claude_fingerprint.go:209` serializes mutations of request-local maps with a process-wide mutex.
  - `chatgpt_pro.go:433` round-trips translated JSON; `:506` reconstructs tool metadata already interpreted by translation.
- Share Grok sanitation policy and Antigravity attempt classification, preserving distinct execution engines and retry policies.
  - `provider_grok.go:733` and `provider_grok_spool.go:137` duplicate root/tool/schema rules.
  - `antigravity_translate.go:1468` and `:1534` repeat outcome handling with intentionally different cooldown effects.
  - `admin_antigravity.go:507` discovers onboarding intent from a URL suffix.
- Remove confirmed provider surplus.
  - Uncalled Antigravity legacy response/stream functions at `antigravity_translate.go:1986`, `:2081`, `:2140`.
  - Uncalled Pi helpers at `pi_models.go:288`, `:296`.
  - Test-maintained legacy replay, candidate, and unguarded-sync wrappers; migrate useful tests to production operations last.

## Protocol state and request processing

- Share Responses tool-call identity, response facts, and incremental event framing.
  - `format_translate_responses_sse.go:231`, `:892`, `:1172` repeat call/item aliases and stable indices.
  - Response usage and terminal facts are extracted independently by several consumers despite `responsesUsageToChatUsage`.
  - Incremental buffering and dispatch shells recur across translation writers.
  - Preserve destination-specific output omission, done-only arguments, unknown IDs, error rendering, and terminal policy.
- Separate source decoder state from destination block emission where their operations coincide.
  - `format_translate_sse.go:27` mixes both translation directions.
  - Claude block emission is repeated in generic and Responses adapters, with distinct initial-usage behavior.
- Put shared request-normalization policy above lexical and buffered processing.
  - `streaming_responses_request.go:153` and `main.go:1080` duplicate dropped fields.
  - Budget-to-effort thresholds recur in streamed conversion, Responses conversion, and `thinking_suffix.go`.
  - Keep schema-normalization operations with different mutation/copy/removal behavior distinct.
- Make spool cleanup and bounded forwarding/accounting composition explicit.
  - `streaming_responses_request.go:136` and `:1046` duplicate cleanup.
  - `stream_usage.go:15` requires callers to establish callback/back-reference and wrapper order.
  - Preserve original/transformed files, observation after downstream failure, and suppression-before-forwarding.
- Remove confirmed translation surplus and unused parameters/state.
  - Definition-only schema/ID helpers, test-only stream wrapper, unused decoder/image/role/event parameters, write-only fields, and never-populated reasoning overrides.

## Identity, lifecycle, and accounting

- Resolve credential identity before usage fans out, preserving historical/wire encoding at boundaries.
  - `usage.go:295`, `storage.go:325`, and `analytics_duckdb.go:63` independently interpret principal/client identity.
  - Legacy administration and live Passport authority are distinct compatibility cases. Do not silently redirect legacy mutations or change cleanup semantics.
- Standardize durable Passport mutation followed by cache publication.
  - Suspension/revocation repeat client cutoff/session/audit updates.
  - Member creation/recovery, avatar updates, and nickname changes use inconsistent persistence/publication sequences.
  - Keep role-specific revocation, last-operator protection, and recent-auth requirements.
- Register operator capability and dispatch together; separate account mutation from HTTP presentation.
  - `operator_api.go:329`, `:555`, and `router.go:426` duplicate route knowledge.
  - `handlers.go:205`, `:245`, `:322` pass response IDs/sanitization into lifecycle work.
  - Preserve default-deny, explicit-header precedence, audit-before-write, public IDs, aliases, and status responses.
- Share analytics fact insertion and clarify best-effort projection boundaries.
  - `analytics_duckdb.go:202` and `:387` duplicate positional schema/argument lists.
  - SQLite serves both request-cost projection and subscription/quota persistence; keep those responsibilities distinct without removing the active store.
  - `quota_waste.go:224` hides observation errors at the operation boundary.
- Replace encoded WebAuthn challenge metadata and serialized Pi filtering with typed preparation.
  - `passport_webauthn.go:340` packs registration purpose and label into a string. Decode persisted legacy challenges compatibly.
  - `operator_api.go:599` serializes and reparses Pi output to filter it.
- Remove test-only lifecycle/quota wrappers and unused quota parameters after migrating tests.

## Interface and client setup

- Define setup commands, navigation metadata, and throughput calculations once.
  - Mine/Setup duplicate commands at `web/src/App.tsx:855` and `:1205`.
  - Workspace IDs, roles, labels, and query-state rules are maintained independently.
  - Throughput calculations repeat in `App.tsx` and `insights.ts`; preserve Claude cache accounting.
- Separate session/bootstrap, analytics refresh, credential loading, and provider contribution lifecycles.
  - Root refresh combines independent resources and authentication state.
  - Mine and Setup repeat signed-key fetch/cancel/retry state.
  - Contribution dialog combines OAuth, popup, and device polling state with casts.
  - Preserve the request schedule, commit/failure rules, cancellation, reveal/replacement/revocation behavior, popup timing, and bounded polling.
- Separate setup request preparation and script rendering with named input data.
  - `frontend.go` embeds long shell programs and positional format argument lists.
  - Preserve shell-specific output, validation timing/status, existing-file migration, and MCP framing.
  - Legacy friend-page command population is duplicated; consolidate within its existing runtime.
- Carry private billing inputs alongside public statistics instead of decoding display labels/hashes.
  - `frontend.go:2093` reverse-maps hashes to IDs; `:2109` recovers billing plans from display text.
- Remove verified unused interface code and correct local build documentation/configuration.
  - Unused live-config wrappers, local landing embed/page, unconsumed chart families, obsolete setup CSS, and identity string replacement.
  - README omits the frontend build prerequisite; Vite and the development launcher disagree on ports; Passport documentation incorrectly claims the friend page was removed.

## Comments and tests

Remove mechanical/stale comments in changed domains; retain external constraints, credential compatibility, lock ordering, accounting, and resource-limit explanations.

After structural changes, strengthen or remove the concrete weak tests: vacuous quota assertions, authority matrix success checks, serialized omission versus persisted state, optional schema validation that skips other HTTP checks, source-text script assertions, helper-only UI/presentation tests, revoked-client existence fallback, fixed race delays, duplicate effort tests, sub-threshold large-event tests, global-temp-count cleanup tests, partial value assertions, and private accumulator assertions. Preserve opt-in live-provider/browser tests and meaningful external compatibility assertions.

## Tool history and response selection

- Keep declared custom-tool metadata available while validating historical calls; apply `tool_choice: none` only to the next response. The prepared ChatGPT request must preserve completed custom-call/output history while advertising no new tools.

## Pool-scoped discovery state

- Give each pool its own Antigravity model registry and pass its catalog explicitly to routing, translation metadata, exports, and persistence.
  - `antigravity_models.go:66` declares a mutable package registry.
  - `pool.go:523` and `:558` publish pool-specific reload results into that registry.
  - Routing, quota, provider persistence, Pi/Cute exports, and public model descriptors read it without a pool dependency.
  - Tests reset that registry globally; the starting working tree disabled parallel execution for a model-response test because of this coupling.
  - Preserve generation-aware account/registry publication and existing catalog/alias output for each pool. Registry lookup must not leak another pool's accounts.

## Confirmed uncalled helpers

- Remove definition-only private helpers after checking production and test references: `normalizeString`, Antigravity content-type helpers, `ccReplaceCCHPlaceholder` and its constants, `tokenFingerprint`, `scoreTooltipLocked`, `earliestReset`, `decayPenalty`, `isPoolGeminiAPIKey`, and `normalizePath`.
- Remove the isolated Claude SDK compatibility transformations. Their only remaining response-reader calls receive an unassigned map and therefore return the original reader. Retain the active protocol tool-history pairing operations and their behavior tests.
- Build the operator manifest from typed Pi preparation as well as the Pi download route, so both consumers avoid serializing and reparsing the same configuration.

## Necessary special cases

Retain second-resolution credential cutoffs, legacy signed/unsigned refresh distinctions, provider one-use refresh uncertainty, role-specific authorization, tenant-scoped signed replay, generation-aware account publication, overload/account fallback budgets, host-specific Antigravity state rules, client-specific protocol exports, strict opaque compaction handling, final partial-image behavior, mixed SSE framing, synchronous shutdown, disk reserve retry, wire/decoded/output/decompressor limits, PowerShell compatibility, stable public hashes, unknown-versus-zero quota, and distinct provider validation protocols. These reflect external behavior or compatibility requirements rather than avoidable internal coupling.

## Verification

The implementation and cleanup cover the decisions above. Independent reviews found no remaining material structural issue after correcting custom-tool history handling and typed Pi manifest preparation.

Checks on macOS arm64 with Go 1.25.0:

- Full Go suite: 926 top-level tests and 621 subtests passed. 7 response-schema checks passed through the existing JSON Schema validator, launched with cached dependencies through `uv`.
- Focused race checks: 14 top-level tests and 3 subtests passed for identity publication, discovery isolation, refresh coordination, forwarding/accounting, and runtime settings.
- Frontend: 54 tests passed; production build and unused-local/parameter checks passed.
- Browser: 18 fixture scenarios passed against the production bundle, including deterministic stale-response handling, credential replacement/revocation, and desktop/mobile layouts. Representative screenshots were inspected.
- Setup: all 12 rendered script variants matched the starting tree byte-for-byte under fixed synthetic credentials. The suite executes Bash installers against local fixtures and checks preservation, authentication cleanup, and repeated installation.
- Native release build passed with the repository's `-trimpath -ldflags='-s -w'` flags; the resulting binary ran its help command.

The full suite retained five opt-in skips: three provider integrity-browser checks and two live-provider probes. Verification used synthetic credentials and local fixtures, not installed credential backups or live provider accounts. PowerShell execution was unavailable; rendered-output checks passed. The default native debug build reproduces the same Mach-O DWARF linker failure in both the starting and refactored trees. Vite retains its existing chunk-size warning.

# Product — Pool Passport

Owner document for value, breadth, and scope. `CONTRACT.md` summarizes and links here.

## Category, references, and evidence

Pool Passport is the identity, access, and usage-visibility layer of codex-pool: a self-hosted multi-provider AI proxy that lends pooled Codex, Claude, Gemini, Grok, Kimi, MiniMax, ZAI, Xiaomi, and Antigravity capacity to a small circle of people, and meters what each of them burns.

It combines four archetypes. Their obligations are merged under single owners rather than stacked:

| Archetype | Owns |
|---|---|
| Hosted service | Principal records, sessions, deployment, migration, observability, support |
| Interactive web application | Sign-in, join, dashboard, pass management, operator console, all states |
| Developer tool | The four provider credential envelopes the CLIs consume, unchanged |
| Infrastructure daemon | Per-request authorization on the proxy hot path, revocation, retention |

Evidence is direct inspection of the running system at commit `82d3104`, plus the production droplet at `143.198.61.181`.

**Reference: the live Signal Room.** `web/src/App.tsx` (1703 lines) and `web/src/styles.css` (676 lines), served from `web/dist` at `frontend.go:46-57`. Observed: a dark amber-gold instrument console with a 48px command rail, a 92px icon rail, edge-to-edge hairline-ruled panels carrying section codes (`A.10`, `C.20`, `F.21`), IBM Plex Mono for all data with tabular numerals, a vendored canvas chart kit (`dither-kit`, 37 files), a fractal-noise overlay and CRT scanlines, and real accessibility work — skip link, `role="table"` on hand-rolled tables, `aria-label` on charts, `:focus-visible` in `--gold-hot`. This is the reference the new surfaces extend.

**Production evidence, observed 2026-08-18.** 50 pool users, none disabled. 25 carry synthetic `friend-xxxx@pool.local` emails minted by self-claim; the rest are `example.com`, `test.com`, and a handful of real addresses. `proxy.db` is 627MB; `analytics.db` is 57MB. Every one of those 50 has live credentials sitting in a real person's `~/.codex/auth.json` or `~/.claude/settings.json`.

**Category alternatives inspected.** Tailscale funnel-style device sharing, Auth0/Clerk/WorkOS hosted identity, LiteLLM's virtual-key model, and OpenRouter's per-key usage dashboards. LiteLLM is the closest functional relative: it issues virtual keys with per-key spend caps and dashboards. Its model requires a Postgres instance and does not emit provider-native credential envelopes, so a Codex CLI cannot consume a LiteLLM key. That difference is why this product exists rather than being replaced by it.

## Users, situations, and completed outcomes

**Darvell, the operator.** Owns the droplet, holds `ADMIN_TOKEN`, adds provider accounts when one runs dry. Today he answers "who is burning my Claude quota" by reading a shared friend code out of `config.toml` and squinting at a global chart that cannot separate people. Completed outcome: he opens the console, sees every principal ranked by tokens and dollars over a chosen window, recognizes each one by name because he wrote the name down when he handed out the pass, and cuts off anyone abusing it in one click without disturbing the other 49.

**A pool member.** Trusted enough to run the thing: adds provider accounts, watches capacity, mints passes for their own friends. Today there is no such role — the friend code makes every holder equally powerful, and the only real authority is a token in a systemd unit file. Completed outcome: signs in with email and password, or a passkey once enrolled, and gets the operator surfaces minus the destructive ones.

**A homie being AI-pilled.** Has never heard of a proxy. Receives a link in iMessage. Completed outcome: taps it on their phone, lands in the pool already authenticated, copies one shell line onto their laptop, and is running Claude Code within a couple of minutes — having created no account, chosen no password, and answered no questions.

**A legacy friend-code user.** One of the 50. Has working credentials and does not know anything is changing. Completed outcome: nothing breaks. Their tokens keep working, their history stays attached to their ID, and the next time they open the dashboard they are recognized.

## Product promise and wrong outcomes

> Everyone who consumes pooled capacity is a named principal with a revocable credential and an honest usage record. A member signs in and operates the pool. A guest taps one link and is in, with a note recording who they are. Anyone can see exactly what pooled capacity they burned, by hour, provider, model, tokens, and dollars — and the operator can see it for everyone and cut off any single person without disturbing the rest. Bring-your-own-key passthrough remains outside pool accounting and is labelled as such.

Technically achievable outcomes that violate the product:

| No-go | Invariant violated |
|---|---|
| Revoking one guest invalidates other principals' credentials | Revocation is per-principal; the shared signing secret is never rotated to cut one person off |
| A revoked or expired principal's proxy request still succeeds | Every proxied request checks live principal status before serving |
| A guest pass exists with no record of who received it | The note is required at creation and cannot be emptied |
| Migration renames or re-keys a legacy user | Principal ID is preserved byte-for-byte from `PoolUser.ID` |
| Removing the friend code orphans historical origin analytics | The historical salt value survives the friend code's deletion |
| A guest reads another principal's usage | Self-usage endpoints resolve the subject from the session, never from a path parameter |
| The dashboard shows a token total the proxy did not durably record, or counts one retry as two client requests | Every chart derives from the canonical DuckDB event ledger; stable proxy-request and attempt identities distinguish request counts from billable observations |
| Analytics pressure silently drops usage | A fact remains in the Bolt outbox until its idempotent DuckDB commit is acknowledged; backlog is visible to the operator |
| A stolen browser session outlives its principal's revocation | Every session rechecks live principal status and is deleted on revocation |
| Password or session material is readable in the store | Passwords are argon2id; session and link tokens are stored as SHA-256 digests |

## Product loops

**Join loop (guest, central to the zero-friction promise).**
Member opens Passes, writes the note ("Dave from climbing"), optionally sets an expiry, creates. Server returns a copyable URL. Member sends it over iMessage. Dave taps it on his phone. The server validates the link, creates a session, and lands him on his own dashboard with his setup instructions. He copies the one-liner to his laptop, opens the same link there, and gets a second session. Re-entry is the same link. Exit is the member revoking it.

**Operate loop (member).** Sign in with password or passkey → dashboard → inspect capacity or a specific principal → act (add a provider account, mint a pass, suspend someone) → return. Repeated use is a persistent session; the sign-in ceremony does not repeat.

**Client credential loop (every principal).** Open Mine → create a credential labelled for one machine or automation context → copy its setup link → that credential accrues its own last-seen and analytics → rotate or revoke it without touching other clients or identity. Labels are attribution hints, not hardware attestation.

**Consumption loop (every principal).** A CLI sends a request bearing a pool credential → the proxy resolves the principal, checks status, expiry, and credential issue time, routes to an account → commits one immutable usage fact to the durable outbox → the analytics writer idempotently appends it to DuckDB → the principal's dashboard derives its selected view from that ledger.

**Accounting loop (operator).** Open the console → rank principals by tokens or dollars over a window → notice an outlier → open that principal, read their note, see their hourly shape and model mix → suspend, set an expiry, or leave it → the change takes effect on the next request.

**Analytics durability loop (system, unattended).** Every usage observation enters a durable Bolt outbox in the same transaction as the proxy's existing usage record. A single writer batches it into DuckDB, commits, then acknowledges the outbox sequence. On restart it replays the unacknowledged tail without duplication. A reconciler compares outbox, DuckDB, and recent Bolt totals and raises a visible fault if they diverge.

## Capability graph and justification

| Capability or surface | Class | Promise, scenario, or obligation served | Why required for the complete product | Reduced alternative considered | Consequence if omitted | Proof |
|---|---|---|---|---|---|---|
| Principal store with kind, status, note, expiry, and credential cutoff | Core | Every loop; "everyone is a named principal" | Nothing else can express member versus guest, carry the note, or revoke one person | Extend `pool_users.json` with more fields | No revocation, no notes, no expiry; whole-file rewrite corruption window widens with every field | `TestPrincipalStoreCRUD`, `TestMigrationPreservesIDs` |
| Guest pass with required note and optional expiry | Core | Join loop; operator's directed requirement | The note is the only thing that maps an opaque ID to a human; expiry bounds one-off handouts | Note as an optional field | Passes accumulate as unidentifiable IDs — exactly today's failure with 25 `friend-xxxx@pool.local` rows | `TestPassRequiresNote`, `TestExpiredPassDenied` |
| Magic join link, multi-use, revocable | Core | Join loop; zero-friction promise | A phone tap must produce an authenticated session with no account creation | One-time link | Breaks the second-device case, which is the normal case: phone then laptop | `TestJoinEstablishesSession`, `TestRevokedLinkDenied` |
| Member sign-in: username or email + argon2id password | Core | Operate loop | Members need durable self-service authority not delegated by a shared secret | Operator-issued session tokens only | Every member addition becomes an operator task; no self-recovery | `TestArgon2idLoginRoundTrip`, `TestWrongPasswordRateLimited` |
| Member onboarding and recovery link | Support | Member first use and password recovery without email | The operator must deliver a first password and recover a locked-out member without logging secrets or adding SMTP | Print or message a temporary password | Password appears in logs/chat and becomes a reusable credential | `TestMemberRecoveryLink` |
| Optional WebAuthn passkey as an additional member credential | Trust | Operate loop; explicit request | Removes the phishable factor for members who enrol; enrolment requires fresh step-up so a stolen session cannot add one | Password only | Members with valuable authority hold only a phishable secret | `TestWebAuthnRegisterAndAssert`, `TestPasskeyEnrollmentRequiresStepUp` |
| Opaque server-side session in an HttpOnly cookie | Trust | Every browser loop | Today `localStorage` holds plaintext long-lived provider credentials readable by any injected script | Keep the localStorage model | Any XSS or extension exfiltrates working provider credentials for the whole pool | `TestSessionCookieFlags`, `TestSessionDiesOnRevocation` |
| Nickname and uploaded avatar image | Polish | Registered users should read as people in usage analytics; explicit user request | Any principal may set a nickname and upload a PNG or JPEG. The server validates size and dimensions, center-crops, resizes to 128×128, and re-encodes as PNG. Analytics joins live profile metadata by immutable principal ID, so history is never rewritten | Render only opaque IDs | Pool analytics remain technically attributable but socially illegible | `TestProfileMetadata`, rendered analytics review |
| Self-service labelled client credentials | Core | Per-machine/per-client analytics; explicit user request | Any principal can mint a separate credential set for a laptop, workstation, or CI context and revoke it independently | Infer machine from IP/user agent | Attribution changes with networks and clients and cannot be intentionally managed | `TestClientCredentialLifecycle`, `TestPerClientAnalytics` |
| Per-request principal authorization and credential rotation | Trust | Consumption, recovery, and leak response | Each credential resolves principal + client ID and carries signed issue time; advancing one client cutoff replaces a leaked machine token without deleting identity/history or disturbing other machines | Suspend the whole account or rotate the global secret | A single-machine leak cannot be repaired cleanly | `TestRevokedPrincipalDenied`, `TestCutoffInvalidatesOldCredential`, `TestCredentialRotation` |
| Per-principal analytical views over immutable usage facts | Core | Accounting loop; "honest usage record" | The stated observability goal requires slicing by person, time, provider, model, tokens, and cost without adding a new write schema for each chart | Keep the existing fixed global series | Cannot attribute burn to a person or ask a question that was not anticipated at write time | `TestUsageLedgerDimensions`, `TestSelfUsageScoping` |
| Self-usage surface scoped by session | Trust | Consumption loop; guest powers decision | A guest must see their own numbers and no one else's | Reuse `/api/pool/users/:id/*` | Any guest reads every principal's full history — today's actual behavior | `TestGuestCannotReadOtherPrincipal` |
| Charts: hourly stacked area, model mix, cost over time | Polish | Accounting loop; "real charts" | Numbers alone do not expose burn shape or a runaway hour | A table of totals | The explicit request is charts; shape is invisible in totals | Rendered review at both viewports |
| Member provider-account contribution and management | Operate | Members are the real pool operators in the directed product | Existing add/manage flows are friend-code or admin-token gated and do not record who contributed or changed an upstream account | Leave account management on the break-glass admin API | Members cannot actually work on the pool as requested; OAuth callbacks can cross sessions without actor provenance | `TestProviderOAuthStateBinding`, `TestAccountActionAudited` |
| Operator console: principals ranked, inspected, suspended | Operate | Accounting loop | 50 principals cannot be managed by curl and a JSON file | Admin API only | Every management act needs a terminal and a memorized token | `TestConsoleRequiresMember`, rendered review |
| Durable analytics outbox and DuckDB ledger | Operate | Analytics durability loop; honest-usage promise | The current SQLite queue silently drops rows, while direct DuckDB writes would put analytics failure on the proxy hot path | Keep adding Bolt aggregates | Future questions require new buckets; queue pressure loses facts | `TestOutboxCrashReplay`, `TestAnalyticsReconciliation` |
| Legacy migration preserving IDs and history | Support | Legacy user outcome | 50 people hold working credentials and history keyed by their ID | Ask everyone to re-onboard | 50 personal re-onboardings and orphaned analytics | `TestMigrationIdempotent`, staging replay |
| Transitional legacy-code account claim and retirement with salt preservation | Support | Directed migration update on August 19, 2026 | Existing holders choose a username/password; a browser-held legacy setup token lets the claim preserve its principal ID, while the old code never authorizes ordinary requests | Remove the code immediately | Existing people lose the requested self-serve account setup; historical origin analytics silently re-bucket | `TestLegacySignupClaimsExistingPrincipal`, `TestOriginHashStableAcrossRemoval` |

## Lifecycle coverage

| Lifecycle moment | Applicability | Product behavior | Authority or state | Proof |
|---|---|---|---|---|
| Discovery and acquisition | Applies | Guests receive a multi-use link from a member out of band. Members are normally created by the operator with a single-use, short-expiry onboarding link. During migration, possession of the former pool code permits a one-time username/password account claim; clearing `friend_code` disables that route. There is no uninvited public sign-up. | Join/recovery link record; principal record | `TestJoinEstablishesSession`, `TestMemberRecoveryLink` |
| Installation or provisioning | Applies | Nothing to install for the dashboard. The proxy is a single binary with embedded assets; the identity store initializes on first boot and migrates `pool_users.json` if present. | Bolt buckets in `proxy.db` | `TestFirstBootBootstrap` |
| Onboarding and configuration | Applies | Guest: tap link, land authenticated, copy one shell line. Member: sign in, set a password on first entry, optionally enrol a passkey. | Session; principal record | Acceptance A2, A3 |
| First successful outcome | Applies | A CLI request authenticated by the principal's credential returns a completion and appears in that principal's hourly chart. | Hour bucket write | Acceptance A2 |
| Routine repeated use | Applies | The session persists for 30 days. A principal creates one labelled client credential per machine/context, sees last-seen and usage per credential, and rotates one without disturbing the others. | Session and client-credential records | `TestSessionSlidingExpiry`, `TestClientCredentialLifecycle` |
| Power or scaled use | Applies | Envelope is ~200 principals and ~500k requests/month on one droplet. Console sorts and filters; DuckDB queries are bounded, cancellable, and proven at 6M rows. | DuckDB fact queries | `BenchmarkDuckDBUsageQueries`, `TestAnalyticsStorageEnvelope` |
| Collaboration and administration | Applies | Members mint and revoke passes, add provider accounts, read pool-wide analytics. The operator additionally suspends members and reassigns the operator role. | Principal kind and status | `TestMemberCannotSuspendMember` |
| Failure and recovery | Applies | Expired/revoked pass, wrong password, rate limit, expired session, unavailable provider, leaked CLI credential, lagging analytics, and failed DuckDB writes each state consequence and recovery. A member locked out receives an operator-minted single-use recovery link; a leaked pool credential is rotated without losing history. | Session, principal cutoff, outbox, and analytics state | Acceptance A5, A9 |
| Restart, reconnect, and update | Applies | Sessions and principals are durable across restart and redeploy. The dashboard reconnects and refills its series without a reload. | Bolt-backed session store | `TestSessionSurvivesRestart` |
| Data access and portability | Applies | Every principal exports their own usage as CSV; the ordinary usage endpoint remains the JSON API. The operator exports the full principal roster and series as CSV. | Export endpoints | `TestSelfExportScoped` |
| Deletion, revocation, and exit | Applies | Revoking a principal advances its credential cutoff, rotates its download token, kills its sessions, and denies its credentials on the next request. Deleting a principal removes the record and, on request, its usage history. | Issue-time cutoff; purge path | `TestDeletePurgesHistory` |
| Operator lifecycle | Applies | Deploy changes to a pinned Linux container build because DuckDB's Go driver uses native bindings, then keeps the existing binary swap. Migration runs once and reconciles before read cutover. Bolt and DuckDB backups share one checkpoint manifest. Pre-mutation rollback restores the prior binary; after any revocation or new principal, recovery is forward-only. | Migration/reconciliation markers, backup manifest, and rollback boundary | Acceptance A8, A9 |

## Obligation map

| Obligation module | Applicability | Trigger or reason | Owning section | Release proof |
|---|---|---|---|---|
| Human interface | Applies | Members and guests use a browser dashboard on desktop and phone | `EXPERIENCE.md` — Surfaces and information architecture | Rendered review at 1440px and 390px |
| Developer interface | Applies | Codex, Claude, Gemini, and Grok CLIs consume four provider credential envelopes that must not change shape | `SYSTEM.md` — External systems and integration lifecycle | `TestCredentialEnvelopesUnchanged` |
| Persistent data lifecycle | Applies | Principals, sessions, join links, passkeys, the analytics outbox, and immutable usage facts are durable and jointly backed up | `SYSTEM.md` — State, data, provenance, and lifecycle | `TestOutboxCrashReplay`, `TestBackupManifestRestore` |
| Background or long-running work | Applies | Analytics outbox drain and reconciliation, session expiry, pass expiry, existing usage pollers | `SYSTEM.md` — Ordering, concurrency, background work, and convergence | `TestOutboxCrashReplay`, `TestAnalyticsReconciliation` |
| External integration | Applies | Nine upstream providers plus WebAuthn browser ceremonies | `SYSTEM.md` — External systems and integration lifecycle | `TestWebAuthnRegisterAndAssert` |
| Identity, permissions, and tenancy | Applies | Operator, member, and guest hold materially different authority over one shared pool | `SYSTEM.md` — Authority and trust boundaries | `TestAuthorityMatrix` |
| Collaboration or real-time state | Does not apply | Principals share pooled capacity but never a document, presence, or ordered stream; the dashboard polls and needs no convergence | — | — |
| Multi-platform, offline, or synchronization | Applies | The join link is tapped on a phone and the setup line is run on a laptop; the dashboard must work on both. No offline mode. | `EXPERIENCE.md` — Platform and input matrix | Rendered review at both viewports |
| User-generated content, abuse, or moderation | Applies | Guest notes are operator-authored free text rendered in the console; a leaked link is the realistic abuse vector | `SYSTEM.md` — Security, privacy, and safety | `TestNoteEscaping`, `TestDistinctOriginCount` |
| Billing, entitlement, or commercial limits | Does not apply | No money changes hands and no plan gates access. Dollar figures are informational attribution of the operator's own subscription cost, not a charge or a cap. | — | — |
| Distribution, installation, and update | Applies | Single Go binary with embedded React assets, swapped by the deploy one-liner | `SYSTEM.md` — Deployment, packaging, migration, update, rollback, and retirement | Acceptance A8 |
| Administration, support, and observability | Applies | The operator must identify, inspect, and cut off any principal, and diagnose why a request was denied | `SYSTEM.md` — Configuration, observability, administration, and support | Acceptance A6 |
| Sensitive, regulated, or third-party data | Applies | Password hashes, session tokens, passkey public keys, raw client IPs, and nine sets of upstream provider credentials | `SYSTEM.md` — Security, privacy, and safety | `TestSecretsNeverLogged` |

## Category expectation ledger

| Category expectation | Evidence and user question | Decision | Target behavior or exclusion | Product consequence |
|---|---|---|---|---|
| Email/password sign-in | Universal across hosted dashboards. "How do I get back in?" | Include | Email plus argon2id password, per-IP rate limited on the existing brute-force tracker | Members have durable self-service authority |
| Passkey / WebAuthn sign-in | Increasingly standard for high-value consoles. "Can I skip the password?" | Include | Optional additional credential; enrol after first sign-in, then use instead of the password | Members with real authority can drop the phishable factor |
| Self-service password reset by email | Standard. "I forgot my password." | Exclude | The server sends no email. Recovery is an operator-minted single-use recovery link, copied and sent the same way a guest pass is. | A member locked out waits on the operator. Accepted: a handful of members, no sending domain, no deliverability surface. The sign-in screen says this plainly rather than showing a dead "forgot password" link. |
| Invite links | Standard for closed products. "How do I add my friend?" | Include | Multi-use, revocable, optional expiry, required note | The central zero-friction path |
| Per-user usage dashboard with charts | LiteLLM and OpenRouter both ship this. "What did I burn?" | Include | Hourly stacked area by provider, daily model mix, cost over the same window, self-scoped | The explicit observability goal |
| Per-user spend caps and hard quotas | LiteLLM's headline feature. "Can I stop someone before they cost me?" | Adapt | No enforced cap. The operator gets ranked burn, per-principal inspection, and one-click suspend — detection and a manual kill rather than an automatic one. | An abusive guest is stopped in minutes, not milliseconds. Accepted: upstream quota already bounds real loss, and a hard cap would need a synchronous counter on the proxy hot path. |
| Audit log of administrative actions | Expected in any console with destructive actions. "Who revoked Dave?" | Include | Append-only record of pass creation, note edits, suspension, revocation, deletion, and role change, with actor and timestamp, shown in the console | Destructive acts among several members are attributable |
| Organizations, teams, and role hierarchies | Standard SaaS tenancy. "How do I group users?" | Exclude | One pool, three principal kinds, no groups or custom roles | A second pool means a second deployment. Correct for a friend group; the interface never implies otherwise. |
| Email notifications and alerts | Common for quota and security events. "Tell me when something happens." | Exclude | No notifications of any kind | Follows from sending no email. The operator learns by opening the console. |
| Two-person approval for destructive actions | Common in shared-authority consoles. "Can one member nuke everything?" | Exclude | Single-actor destructive actions, mitigated by the audit log and by reserving member suspension and deletion to the operator | Members are people the operator already trusts with provider credentials |

## Scope frontier

**Promised now.** Three principal kinds with distinct authority. Member sign-in by password, optionally by passkey. Guest passes with required notes, optional expiry, revocation, and multi-use magic links. Opaque server-side sessions. Per-request authorization with live status and credential issue-time cutoffs. Per-principal hourly, daily, and model-daily token and cost series with charts, self-scoped for guests and pool-wide for members. An operator console with ranking, inspection, suspension, and an audit log. Retention that bounds disk. Migration of all 50 existing users with IDs and history preserved. Removal of the friend code with the origin salt preserved.

**Supported situations.** One pool, one deployment, one operator, a handful of members, up to roughly 200 principals. Desktop and mobile web. The nine existing providers.

**Not promised.** No public sign-up. No email of any kind. No password reset without the operator. No organizations, teams, or custom roles. No enforced spend caps or rate limits per principal. No notifications. No mobile app. No multi-pool federation. No SSO or SAML. No latency, status-code, or error-rate analytics.

**The architecture must not pre-implement** a tenancy column, a roles table, a billing schema, or a notification queue. Each would be speculative machinery for a product that is deliberately one pool of friends.

## Usage, distribution, and commercial model

Non-commercial and private. Success is: the operator can name every principal, see what pooled capacity each burned, see the separate excluded passthrough volume, and cut any one off in one click; and a new friend goes from a tapped link to a working CLI in under five minutes without asking a question.

Distribution is the existing binary swap to `/opt/codex-pool` behind Caddy at `codex.ppflix.net`. Cost is unchanged — no new hosted dependency, no new paid service. The product upgrades to Go 1.25 and adds `go-webauthn/webauthn` v0.17.4, `golang.org/x/crypto` v0.52.0 for argon2id, and the pinned DuckDB Go driver.

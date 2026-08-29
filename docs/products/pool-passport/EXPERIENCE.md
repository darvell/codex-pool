# Experience — Pool Passport

Owner document for surfaces, journeys, states, and product character.

## Surfaces and information architecture

The dashboard is the existing Signal Room. Pool Passport adds three destinations to its icon rail and one pre-authentication surface, using the established grammar: `grid-template-columns: 92px minmax(0,1fr)`, a 48px sticky command rail, edge-to-edge panels sharing 1px `--rule` hairlines, and a panel header of `[section code | title | dither block]`.

| Place | Route | Who reaches it | Owns |
|---|---|---|---|
| Gate | `/` unauthenticated | Anyone | Member sign-in. Not a guest entry point. |
| Join | `/join#<token>` | Anyone holding a link | The fragment never reaches Caddy; the browser posts it in the request body, replaces history, and establishes a session |
| Mine | `/` rail item `◑ MINE` | Every principal | Own usage, per-client breakdown, labelled client credentials, and setup |
| Passes | `/` rail item `⊞ PASSES` | Members and operator | Creating, labelling, expiring, revoking passes |
| Console | `/` rail item `⌸ CONSOLE` | Members and operator | Every principal ranked and inspected; audit log |
| Pulse, Insights, Usage, Accounts, Models | existing | Members and operator | Unchanged pool-wide analytics and account management |
| Setup | existing | Every principal | Per-provider client instructions, now keyed to the session's own credentials |

Guests see exactly two rail items: `MINE` and `SETUP`. The others are not rendered — not rendered-and-disabled, which would advertise capability a guest cannot have.

Surface ownership for concepts that appear more than once:

| Concept | Primary surface | Secondary appearances |
|---|---|---|
| A principal's internal note | Console detail | Passes list — *Summarized*, note and status only. Never shown to the guest. |
| A principal's visible identity | Mine and command rail | Optional nickname plus a real uploaded avatar image. Upload accepts PNG/JPEG up to 2 MB, validates 16–4096 px dimensions and at most 16 million decoded pixels, center-crops, and normalizes to 128×128 PNG. Members fall back to email initials; guests fall back to `GUEST <short-id>`. Analytics roster, tooltips, and detail use the same live profile owner. |
| A principal's usage series | Mine, for oneself; Console detail, for others | Mine client filter — *Partitioned* by labelled credential. Console list — *Summarized*, 7-day sparkline and totals. Pulse — *Complementary*, pool-wide aggregate answering a capacity question, not a per-person one. |
| Pool capacity | Pulse and Insights, unchanged | Console — *Suppressed*. The console answers "who", not "how much is left". |
| Provider setup instructions | Setup | Join success — *Summarized*, the single most relevant one-liner with a link to Setup. |

## Journey and state maps

### Guest join

```text
Place: iMessage/Discord, a copied link
  Action: tap
      -> GET /join#<token> (the fragment is not sent to the server or referrer)

Place: /join
  Browser reads the fragment, immediately removes it with `history.replaceState`, and POSTs it to `/api/auth/join`.
  Server validates: exists, not revoked, not expired, principal active
      -> valid, no session or same principal: set/refresh session -> redirect to Mine, one-time welcome
      -> valid, different principal already signed in: show "Switch from <current> to this guest?"
         Confirm replaces the browser session; Cancel returns to the current dashboard.
      -> expired: "This pass expired on 12 Aug 2026." + "Ask <member> for a new one." No retry field.
      -> revoked: same wording as expired. Revocation is not distinguished from expiry — telling a stranger
                  they were specifically revoked leaks a fact the holder should hear from a person, not a page.
      -> unknown: same wording again. A guessed token and a revoked one are indistinguishable by design.

Place: Mine, first entry
  Shows: welcome naming the member who invited them, the setup one-liner for the recommended client,
         an empty usage panel reading "Nothing burned yet. Run something."
  Action: copy one-liner -> paste on laptop -> first request -> panel fills within the 30s refresh
  Re-entry: same link on any device, any number of times, until revoked or expired
```

### Member sign-in

```text
Place: Gate
  Fields: username or email, password
  Secondary: "Sign in with a passkey" — shown only when the browser reports WebAuthn support
  No "forgot password" link. Instead: "Locked out? Ask the operator for a recovery link."
  Action: sign in
      -> success:        session cookie -> last visited destination, or Pulse on first entry
      -> wrong:          "Email or password is incorrect." Identical for unknown email and wrong password.
      -> rate limited:   "Too many attempts. Try again in 27 minutes." Counts down. Per-IP, existing tracker.
      -> passkey assert: browser ceremony -> same success path
      -> first sign-in:  forced password change before anything else is reachable

  Transitional secondary: "I have the old pool code"
      -> fields: old pool code, chosen username, chosen password
      -> if the browser has a legacy setup token, the server claims that existing principal ID and history
      -> otherwise creates a new named member; clearing `friend_code` disables this migration route
```

### Member onboarding and recovery

```text
Place: Console, operator only
  Action: New member / Recover member
      -> operator enters or confirms normalized email
      -> server creates a single-use link expiring in 30 minutes
      -> operator copies and sends it out of band

Place: /recover#token
  Browser removes the fragment and POSTs it in the body, exactly like guest join
  New member: chooses password, signs in, optionally enrols a passkey
  Recovery: proves possession of the link, chooses a new password, all prior browser sessions die
  Used, expired, revoked, and unknown links return the same terminal explanation
```

No temporary password is generated, displayed, logged, or sent.

### Client credential creation

```text
Place: Mine, CLIENTS
  Shows: active credentials with label, created, optional expiry, last seen, and selected-window usage
  Action: New client
      -> label required ("MacBook", "workstation", "CI"), optional expiry
      -> creates one credential set and reveals its provider setup links
      -> copy the setup link for the desired client
  Actions: Rename, Rotate, Revoke
  Rotate: old CLI credentials/setup URL fail; new setup link appears; other clients and history remain
  Revoke: client stops on the next request; principal and other clients remain active
```

The surface says: "Labels follow the token, not the hardware. If you copy this credential elsewhere, that usage still appears under this label."

### Pass creation

```text
Place: Passes
  Action: New pass
      -> Inline row, not a modal. Fields: note (required, autofocused), expiry (default None; 7d/30d/90d/date).
      -> Create is disabled until the note has content. The disabled control carries the reason.
      -> created: row expands to show the URL and a Copy control.
                  The URL stays visible while the row is open and is retrievable later from the row.
                  It is a bearer credential, so the row says so: "Anyone with this link can use the pool."
  Row actions: Copy link, Edit note, Change expiry, Rotate credentials, Revoke
  Rotate credentials: two-click confirm. Keeps the pass, note, expiry, history, and browser sessions;
                      invalidates every existing CLI credential and setup URL, then reveals one new setup link.
  Revoke: two-click confirm in place, matching the existing account disable pattern at App.tsx:1269-1273.
          Confirm copy names the consequence: "Dave from climbing loses access immediately. History is kept."
```

### Operator suspends a principal

```text
Place: Console, sorted by tokens over the selected window
  Action: select a row -> detail panel
  Shows: note, kind, created, last seen, distinct origins, hourly series, model mix, cost
  Action: Suspend
      -> two-click confirm naming the person by their note
      -> credential cutoff advanced, download URL rotated, sessions killed, next proxy request denied
      -> row moves to SUSPENDED, retains history, audit entry written
  Action: Restore -> reverses status. The credential cutoff does not roll back, so previously issued
          credentials and download URLs stay dead; the principal receives a new download link. The confirm says so.
```

### Material states

| State | What is shown | Available actions | Authority | Exit and recovery |
|---|---|---|---|---|
| Unauthenticated | Gate, sign-in only | Sign in; assert passkey | None | Session cookie on success |
| Joining | Brief validating state on `/join` | None | None | Session, or a terminal explanation |
| Authenticated guest | Mine and Setup only | View own usage, export own usage, copy setup | Own record only | Sign out; revocation ends it mid-session |
| Authenticated member | Full rail minus operator-only actions | Everything except suspending members and deleting principals | Pool-wide read, pass write, account write | Sign out |
| Operator | Full rail | Everything | Full | Sign out |
| Empty usage | "Nothing burned yet. Run something." plus the setup path | Copy setup | — | First request fills it |
| Loading series | Panel keeps its frame and axes; skeleton bars in `--graphite`. Never a spinner replacing the panel — the layout must not jump. | — | — | Data or error |
| Stale | Command rail shows `ANALYTICS LAGGING // 4m`, charts stay rendered | Retry | Last-known-good, marked stale | Backlog drains |
| Accounting gap | Full-width `ACCOUNTING GAP // 14:02–14:11 UTC` above every affected chart; totals say `incomplete` | Open incident detail | The service served requests it could not durably meter | Storage recovers; banner remains on ranges containing the gap |
| Denied | Cause and recovery in one sentence | The one available recovery | — | Recovery path |
| Revoked mid-session | Full-surface takeover: "Your access was revoked." No dashboard behind it. | None | — | Terminal until re-invited |
| Suspended principal, in console | Row in `--muted` with a SUSPENDED tag, history intact | Restore, delete | — | Restore |

## First use and repeated use

**First use, guest.** Zero fields. The link carries the credential; the landing page carries the one-liner. The welcome names the inviting member so the guest knows why they are here. The single most important thing on that first screen is a shell command they can copy, not a chart of zeroes.

**First use, member.** Sign in, forced password change, then a dismissible prompt to enrol a passkey with a one-line reason: "Skip the password next time." Dismissal is remembered and not asked again.

**Repeated use.** The session persists 30 days with sliding renewal. The dashboard remembers the last destination and the last selected window. Guests never see the gate again unless revoked. Members never re-enter a password unless they sign out or the session lapses.

## Design, content, motion, and feedback rules

**Tokens are unchanged.** `--void:#070706`, `--console:#0b0b09`, `--rule:#40351b`, `--gold:#d5a638`, `--gold-hot:#ffda63`, `--ink:#f3ecd6`, `--muted:#9c967f`, `--danger:#ff5b4d`, `--success:#57e67b`. No new colors. Suspension and expiry use `--muted`, not `--danger`; a suspended pass is an inactive state, not an error.

**Type is unchanged.** IBM Plex Sans Condensed for prose, IBM Plex Mono for every data-bearing element at .57–.66rem with .06–.08em tracking and tabular numerals, Cormorant Garamond for display. Notes render in Plex Sans, not Mono — they are human names, not data.

**Section codes continue the existing scheme.** Mine is `M.10` usage, `M.11` model mix, `M.20` clients, `M.30` setup. Passes is `P.10`. Console is `K.10` roster, `K.20` detail, `K.30` audit.

**Hierarchy.** On Mine, the hourly chart is the primary object. On Console, the roster is primary and the detail panel is secondary until a row is selected. In a pass row, the note has the most weight — it is the only thing that identifies the person.

**Motion.** The existing kit only fades panels in. Added: none. No animation on chart updates; a moving chart on a 30-second poll is noise. Two-click confirms change label and color without motion.

**Copy voice** matches the existing arch register — "PRIVATE FREQUENCY", "The charts are nosy." Denials and destructive confirms drop the register entirely and say the plain consequence. A person locked out is not in the mood for a bit.

**Terminology.** One term per concept: *principal* never appears in the interface; it says *member*, *guest*, and *operator*. *Pass* is the credential, *link* is its URL, and *note* is the private member/operator label. A note is never addressed to or shown to the guest. Never *user* — the codebase's overloaded `user_id` stays internal.

## Platform and input matrix

| Product responsibility | Shared contract | Platform adaptation | Unsupported | Proof |
|---|---|---|---|---|
| Redeeming a join link | Same URL, same session, same result | Mobile lands on Mine with the setup one-liner collapsed behind "Set up a client" — a phone cannot run it, so it must not dominate | No native app, no deep link | Rendered review at 390px |
| Reading own usage | Same series, same numbers | Desktop shows the 6-column instrument strip; mobile stacks to 2 columns and charts go full-bleed | Landscape tablet is untested and unclaimed | Rendered review at 1440px and 390px |
| Managing passes | Same actions | Desktop is an inline-expanding table; mobile is a card list with the same actions | — | Rendered review at 390px |
| Operator console | Same roster and detail | Desktop is side-by-side roster and detail; mobile pushes detail as a full-screen view with a back control | — | Rendered review at 390px |
| Signing in | Same credentials | Passkey uses the platform authenticator — Touch ID, Windows Hello, or a phone. The control is hidden entirely when the browser reports no WebAuthn support rather than failing on click. | — | `TestWebAuthnRegisterAndAssert` |
| Copying setup | Same one-liner | Clipboard API where available; a selectable `<pre>` fallback where it is not | — | Rendered review |

## Accessibility contract

Matches what the Signal Room already does, extended to the new surfaces. Target WCAG 2.2 AA.

Keyboard reaches every action including copy, revoke, expiry, and row selection. Focus is visible in `--gold-hot` via `:focus-visible`. The gate autofocuses email. Pass creation autofocuses the note.

New tables use the existing hand-rolled `role="table"`/`role="row"`/`role="cell"` pattern with `aria-sort` on the console's sortable columns. Charts carry `aria-label` naming the series and window, and each is followed by a visually hidden table of its values — a canvas chart is opaque to a screen reader, and the existing kit renders to canvas.

Status changes announce through a polite live region: session expiry, revocation, copy success, pass creation. Revocation mid-session announces assertively — it is a takeover.

Contrast: `--ink` on `--console` and `--gold` on `--console` both clear 4.5:1. `--muted` on `--console` is used only for non-essential secondary text and never for the sole indicator of a state; suspended rows carry a text tag, not just a color.

Reduced motion: the only motion is panel fade-in, disabled under `prefers-reduced-motion`.

Copy controls announce their result rather than relying on a color flash.

## Conditional experience checks

**Experience checks:** Reference, Expectation, Glance, Surface, Dwell, Platform

### Reference delta

Reference: the live Signal Room at commit `82d3104` — `web/src/App.tsx`, `web/src/styles.css`, observed directly.

| Material property | Reference function | Decision | Target behavior | Reason |
|---|---|---|---|---|
| Icon rail with single-glyph destinations | Navigation with minimal chrome | Preserve | Add `◑ MINE`, `⊞ PASSES`, `⌸ CONSOLE` in the same idiom | Consistent navigation model; guests simply see fewer items |
| Section codes on panel headers | Locating a panel in conversation | Preserve | `M.*`, `P.*`, `K.*` continue the scheme | Cheap, distinctive, already understood |
| Edge-to-edge hairline panels, no radius, no shadow | Instrument density | Preserve | All new panels tile identically | A rounded card among these would read as a bug |
| Access gate posting a shared code | Entry | Adapt | Becomes member email/password sign-in; guest entry moves to the link entirely | The shared code is the thing being removed |
| Credentials in `localStorage` | Session persistence | Exclude | Replaced by an HttpOnly cookie | Plaintext provider credentials readable by any injected script |
| Operator unlock modal probing `/admin/accounts` | Elevation | Adapt | Authority comes from the session's principal kind; no separate unlock, no second token in `sessionStorage` | Two parallel auth systems in one dashboard is the current confusion |
| `YOUR HANDLE` derived from a hashed IP | Weak self-identity | Adapt | Becomes the optional display name, member email, or guest short ID; private notes never appear here | The hash was a stand-in for identity the system did not have |
| Global-only charts | Pool capacity | Preserve | Pulse and Insights keep answering the capacity question unchanged | Still the right question for a member; per-person lives on Mine and Console |

### Category expectation behavior

| Expectation | Decision | Where it appears | Depth | Under failure and repeat |
|---|---|---|---|---|
| Email/password sign-in | Include | Gate | Argon2id, per-IP rate limit, forced first-entry change | Wrong password and unknown email are indistinguishable; lockout counts down in the message |
| Passkey sign-in | Include | Gate secondary control; enrolment prompt on Mine | Optional, additional to the password, multiple credentials per member | Hidden when unsupported; a failed ceremony returns to the password field with the email retained |
| Invite links | Include | Passes | Multi-use, revocable, optional expiry, required note, copyable URL | Expired, revoked, and unknown are deliberately indistinguishable to the holder |
| Per-user usage charts | Include | Mine, self-scoped; Console, for others | Hourly by provider, daily model mix, cost, CSV export; JSON remains the API | Empty and stale states are explicit; stale keeps last-known-good and says so |
| Audit log | Include | Console `K.30` | Actor, action, subject, timestamp, append-only | Read-only in the interface; no edit or delete path exists |
| Spend caps | Adapt | Console ranks burn and offers suspend | Detection and a manual kill, not an automatic one | The interface never shows a limit, a budget, or a remaining allowance, because none exists |
| Password reset | Exclude | Gate states the operator recovery path instead of showing a link | Operator-minted single-use recovery link | No dead-end reset flow; a locked-out member waits on the operator |

### At-a-glance contract

Question answerable within seconds, on Mine:

| Question | Signal | Surface | Detail path |
|---|---|---|---|
| Who am I here? | Display name, member email, or guest short ID in the command rail | Command rail | — |
| Am I still allowed in? | Absence of the revocation takeover | Whole surface | — |
| How much have I burned? | `M.10` headline total for the window | Mine | Hover a bar for the hour |
| Am I burning unusually right now? | Shape of the last bars against the window | `M.10` | Model mix `M.11` |
| Is this current? | "LAST SYNC" in the command rail | Command rail | Retry |

On Console:

| Question | Signal | Surface | Detail path |
|---|---|---|---|
| Who is burning the most? | Roster sorted by tokens, first row | `K.10` | Select the row |
| Who is that? | The note, at the strongest weight in the row | `K.10` | Detail |
| Is anyone new or unusual? | Last-seen column, and distinct-origin count when above one | `K.10` | Detail |
| Does anyone need cutting off? | Rank plus the origin count together | `K.10` | Detail, then Suspend |
| Who changed what? | Most recent audit entries | `K.30` | Full log |

Deliberately absent: no per-principal quota bar, no remaining-budget figure, no health badge. None exists, and showing one would imply an enforcement this product does not perform.

### Surface ownership

**Primary surface** assignments are in the table under *Surfaces and information architecture*.

The rule that matters: a principal's usage series has two primary surfaces, one per audience — Mine owns it for oneself, Console detail owns it for someone else. They render the same data through the same components, but Mine is self-scoped by session and never accepts a subject parameter, while Console requires member authority and takes the subject from the row. Keeping them separate at the API boundary is what makes the guest scoping enforceable rather than a rendering convention.

Pulse and Insights are *Complementary*: they answer "does the pool have capacity", which is not "who used it". They are not extended with per-person breakdowns.

### Dwell-state contract

**Long-lived state: an active session against a principal whose status can change underneath it.** A guest session lives up to 30 days with sliding renewal, across devices, while the member who invited them can revoke at any moment and an expiry may fall due.

While it persists: usage accrues and the charts refill on each 30-second poll; the sliding expiry advances on activity; the last-sync indicator ages when a poll fails.

What stays stable: the principal's identity, note, and full history. Nothing about revocation alters what was recorded.

What must be noticed without opening detail: that access ended. Revocation and expiry produce a full-surface takeover on the next poll or navigation, not a toast — a dashboard still rendering behind a dismissed notice would be a lie about authority.

Reacting surfaces: the browser session dies on the next poll; in-flight proxy requests complete but the following one is denied; the Console row moves to SUSPENDED for everyone watching.

Interruption and restart: sessions are durable in Bolt and survive a redeploy. A session whose principal was revoked while the process was down is rejected on its first post-restart request, because status is checked live rather than trusted from the cookie.

Acceptance proof must hold a session open across a revocation and an expiry rollover and observe the transition, not merely assert the two end states.

### Platform coherence

The shared contract is one responsive web surface with identical data and authority on every device; the platform adaptation is layout and affordance only.

Phones get the join and read paths as first-class: tap link, land authenticated, read usage. They get the write paths too — a member can create and revoke a pass from a phone, because handing out a pass happens in a conversation, on a phone. What a phone does not get is the setup one-liner in a prominent position, since it cannot be run there; it collapses behind a control.

No platform gets a capability another lacks. Unsupported and unclaimed: native apps, offline use, push notifications, and landscape tablet layout.

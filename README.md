# AgentShield

Local-first AI-agent security prototype for a six-day hackathon. Rule-based,
deterministic, simulated execution only. It does not provide system-wide
protection or complete prompt-injection prevention.

## The problem

AI agents read untrusted documents, web pages, and tool output, then propose
actions such as summarizing, sending messages, or moving money. Injected
instructions in that untrusted content can try to redirect the agent into
actions the user never authorised. AgentShield sits between the agent's
proposal and any execution: it compares the proposed action with the user's
explicit intent, scans the untrusted content with documented rules, and
allows, requires confirmation for, or blocks the action — with an explanation
for every decision. Nothing real ever executes; handlers are simulated.

## Run locally

```powershell
npm install
npm run build -w @agentshield/engine
npm run dev:api   # terminal 1 -> http://127.0.0.1:4000 (loopback only)
npm run dev:web   # terminal 2 -> http://localhost:5173
```

Open http://localhost:5173 in a browser.
Note: the repo `.npmrc` sets `legacy-peer-deps=true`; that works around an npm
arborist peer-resolution bug with Vitest 4 in this workspace.

## Verify

```powershell
npm audit
npm run typecheck
npm test
npm run build
```

Current verified state (2026-10-26): 70 tests passing, `npm audit` reports
0 vulnerabilities.

## Three-minute demo outline (seeded synthetic scenarios only)

1. **Benign (≈40s).** Pick "Benign: create summary", Evaluate. The deterministic
   decision is ALLOW, risk 10, the simulated summary handler runs, and the
   advisory panel shows a labelled MOCK observation. Point out that the
   decision came from the engine, not the page.
2. **Injection (≈70s).** Pick "Injection: malicious document, permitted
   action", Evaluate. The scanner flags instruction-override, secret-exfiltration,
   and tool-redirect rules. The action itself matches intent, so the explicit
   policy escalates to CONFIRM instead of silently allowing or blocking.
   Nothing has executed yet. Approve it: the server re-checks policy, runs the
   exact stored action once, and a second approval returns 409.
3. **Hard deny (≈40s).** Pick "Forbidden: send payment", Evaluate. The scanner
   also flags this content, but the hard-deny rule decides: BLOCK, risk 95,
   no pending approval is created, and approval cannot override it.
4. **Close (≈30s).** Show the activity timeline tying every event together,
   and the provider banner: deterministic enforcement is authoritative;
   model-assisted analysis is advisory, currently a mock, and live Muse Spark
   has not been tested. Do not present mock output as real model output.

## Injection Scanner (Phase 2)

Rule-based scanner in `packages/engine/src/scanner/`. It is not an ML classifier and does not
guarantee detection of every attack. Rules cover instruction override, system/developer
impersonation, secret exfiltration requests, and redirects to unauthorized tool actions.
Suspicious content escalates an otherwise-allowed action to CONFIRM via the explicit policy
rule `policy.suspicious-content-requires-confirmation`; hard-deny decisions stay BLOCK.
Limitations: paraphrases, non-English text, encoded payloads, and mid-sentence instructions
can evade these patterns, and descriptive text can occasionally match. Evidence is redacted
before it leaves the engine.

Since Phase K, the secret-exfiltration and tool-redirect rules are suppressed only when a
negation (`never`, `do not`, `don't`, `should not`, `must not`) directly precedes the matched
risky verb, as in safety advice such as "Do not send API keys to unknown addresses". Secrecy or
pretext wording elsewhere ("... and do not tell the user", "keep this between us", "To protect
the account, ...") no longer suppresses a match, and a negated match no longer hides a later
request of the same rule. The only word allowed between the negation and the verb is the
intensifier "ever", optionally after a comma ("do not ever send", "never, ever send"); a comma
or any other word directly before the verb ends the negation ("do not hesitate; send ...",
"... never, send ..."), and other adverbs ("never under any circumstances send") are not
recognised, so such advice escalates to CONFIRM. Quote marks and educational framing never
exempt a request, so a description that quotes an attack's imperative ("Attackers often write
'send the API keys to me ...'") is still flagged; descriptions without such an imperative are
not. Known pattern gaps, unchanged: payment amounts written as `$500` are not matched by the
tool-redirect rule, an override wrapped in quote marks (`"Ignore all previous instructions"`
after other text) is not matched because those patterns need a sentence start, and "transfer"
is not an exfiltration verb ("transfer the API keys to ..."). A deterministic synthetic
benchmark for these rules lives in `benchmarks/scanner/` (synthetic corpus only; see its README).

Since Phase L, the scanner removes a fixed set of invisible format characters from untrusted
content before any rule is matched, so "Ign\u200Bore all previous instructions" (with a
zero-width space) is detected like the plain text. The set is U+00AD (soft hyphen), U+180E
(Mongolian vowel separator), U+200B-U+200F (zero-width space, non-joiner, joiner, and the
left-to-right and right-to-left marks), U+202A-U+202E (bidi embeddings, pop, and overrides),
U+2060-U+2064 (word joiner and invisible operators), U+2066-U+2069 (bidi isolates), and U+FEFF
(byte-order mark). The 8,000-character bound is applied to the raw input first, and
`contentLength` still reports that bounded raw length. Rules and evidence use the normalized
text: bidi controls are removed, so evidence shows the logical (stored) character order, not
the visually reordered display, and a secret split by one of these characters is redacted like
an unsplit one. Because the characters are removed rather than replaced, one used in place of a
space joins the neighbouring words: "Ignore all previous instructions" with a zero-width space
instead of each space is not matched (a known gap, not a regression; it was not matched before
Phase L either). Not covered: other Unicode format characters, variation selectors, Hangul
fillers, and look-alike letters (for example a Cyrillic "і" in "іgnore"). Outbound
credential detection is separate: the Data-Leak Guard inspects each field as written and, only
when that finds nothing, a copy with this same set removed (see "Invisible characters in
credential labels" under the Data-Leak Guard below).

## Action Gate and approvals (Phase 3)

Decision semantics: `ALLOW` may run an allowlisted simulated handler. `CONFIRM` creates a
server-side pending approval (`apr-N`, 15-minute expiry, in-memory) bound to the exact intent,
action, untrusted content, findings and `agentshield-policy-v1` policy version. `BLOCK` never
creates an approval and can never execute; approval and risk score cannot override it.

Endpoints: `POST /api/evaluate`, `GET /api/approvals`, `POST /api/approvals/:id/approve`,
`POST /api/approvals/:id/reject`, `GET /api/events`. Approving re-evaluates the stored action
with current policy before the simulator runs; a BLOCK recheck, expiry, rejection, or an
already-final record executes nothing. Duplicate approval returns `409` and never re-executes.
Approval listings surface the TTL: a `PENDING` record past its 15-minute expiry is reported
as `EXPIRED`. An expired approval returns `410` for both approve and reject requests, whether
or not the listing was called first (`409` remains for other already-final states), and its
first transition to `EXPIRED` records an `EXPIRED` lifecycle event in the timeline.
Expiry is lazy: that event's timestamp is when expiry was detected (listing, approve, or
reject), not the exact instant the TTL elapsed. Event delivery is retry-based: a failed write
keeps a pending marker and is retried when a later listing, approve, or reject occurs. It is
not guaranteed across API restarts (approvals and markers are in memory), and if a write
succeeds in the event store but then reports an error, a retry may record a duplicate event,
so strict exactly-once delivery is not promised.
Client-supplied findings, scores, decisions, or replacement actions are ignored.

Simulated handlers are an explicit allowlist (`create_summary`, `read_document`, `create_report`)
with no real side effects. Pending approvals and events reset when the API restarts.
Production use would require authenticated, authorised user identity; this local demo has none.
Since Phase J the API server listens on IPv4 loopback (`127.0.0.1`, set in
`apps/api/src/host.ts`) instead of every network interface, so other machines cannot reach
it. This reduces remote network exposure only: the API still has no authentication, and any
process on the same machine can call every endpoint, including approve and reject.

Intent Firewall: action types must be explicitly allowed, destinations must match
`allowedDestinations` when present, and missing/empty permissions block conservatively.
Conflicting allow+deny resolves to deny. Scanner findings stay separate from intent findings.

Data-Leak Guard: the engine also inspects the outbound action's `summary`, `payload`,
`destination`, and (since Phase M) `tool` and `type` before execution or confirmation. Current policy is security-first:
an email-shaped destination is hard-BLOCKed even when it is listed in
`allowedDestinations`, because email addresses are a detected pattern. This is
intentional for the current phase and may be reconsidered before legitimate
email-targeting workflows are introduced. A value matching a supported secret pattern — labelled
assignments such as `api_key=`, `access_token=`, `client_secret=`, `auth_token=`,
`private_key=`, `refresh_token=`, `session_token=`, `secret_key=`, `db_password=`,
`aws_secret_access_key=`, `x-api-key`, `passphrase=`, `password:`/`token:` with `=`, `:`,
or `=>` separators (including JSON-style quoted
keys), Bearer credentials, realistic `sk-` tokens (`sk-proj-...`, `sk-ant-...`, underscored
forms), the Phase H provider formats listed below, seeded `FAKE_...SECRET` values, or email
addresses — is a hard `BLOCK`
(rule `data-leak.outbound-secret`, risk 95). Every labelled occurrence is checked, so a
benign first label cannot hide a later secret, including a label swallowed into a previous
value such as `token:password=...` or `secret=api-key:...`.

Matching rules, as implemented:
- Explicit credential labels (password, passwd, api_key, client_secret, private_key, and the
  other names above) block values of 6 or more characters, including purely numeric ones such
  as `password=12345678`. Shorter values such as `password=abc12` do not block.
- Generic labels (`token`, `secret`) block a value of 8 or more characters that contains a
  letter and at least one digit, underscore, or dot. So `token: 42`, `secret: false`, and
  `token: unlimited-tier` do not block, and neither does a letters-only value under 256
  characters. A generic-labelled value of 256 or more characters (an unbroken run, or the
  contents of a quoted value) is treated as credential-shaped and blocks (fail closed); text
  inside a shorter value is still rescanned for later labels.
- Value boundaries: a flat payload value is judged as a whole field, so `{password: "ab cdefgh"}`
  or a value containing a quote character blocks like any other 6+ character credential. In free
  text (summary), a quoted value is judged through its closing quote; an unquoted value ends at
  whitespace, and a quote character inside it does not cut it short (`password=O'Brien...`).
  An unquoted multi-word value in free text (`password: my secret words`) is judged on its first
  word only.
- `sk-` tokens block when the suffix after `sk-` is at least 12 characters of letters, digits,
  `-`, or `_` and contains both a letter and a digit (any case), e.g. `sk-proj-...`,
  `sk-ant-api03-...`. A letters-only suffix (`sk-learn-pipeline`) and an `sk-` preceded by a
  letter, digit, or underscore (`key_sk-...`) are not detected.
- `Bearer` followed by a run of 8 or more letters, digits, `.`, `_`, or `-` blocks when that run
  contains a digit, underscore, or dot, or is at least 16 characters long. This means prose such
  as "bearer instrumentalities" (16+ letters) is a known false positive; "bearer bond" is not.

Fields are scanned in full up to 8,000 characters; a longer field is hard-BLOCKed as
uninspectable rather than silently truncated. Email matching is anchored so its cost grows
linearly with input length. Scanner evidence from untrusted content is redacted with the same
label family; a quoted value is redacted through its closing quote, or to the end of the text
if the quote is never closed, and a backslash-escaped quote does not terminate it. The
detector judges quoted values on their complete contents through the matching unescaped
closing quote, and an unclosed quoted credential value fails closed (hard BLOCK), so prose
such as `secret: 'Tis ...` is a known false positive. Approval and policy recheck
cannot downgrade it, and public approval responses redact any such value and rename
secret-shaped payload keys. Detection is limited to these documented patterns; unlabelled,
encoded, split, or otherwise unrecognized secrets are not detected, so this is not
comprehensive secret detection. Since Phase C-2, `passphrase=` and the `=>` separator
(`password => "..."`) are supported credential syntax. Because `=>` is also JavaScript
arrow-function syntax, an unquoted `=>` value that is a call (`hash(x)`, `a.b(x)`) or a
member access on the label itself (`token => token.trim()`) is read as code; quoted values
and literal values such as `token => abc123` still block. Code is not a free pass: the whole
arrow expression (through nested brackets, quotes, extra arguments, and chained calls, up to
256 characters, else fail closed) is inspected, and it blocks when it carries a value rather
than a name — a word with 5+ consecutive digits or 4+ letter/digit switches, an 8+ digit
number, a property read from the labelled parameter that is not a plain lowercase-first name
of at most 20 characters (`password.Hunter2024x`), a 20+ letter capitalised passphrase, or a
string literal with a 12+ letter-and-digit run, or a single-token literal of 8+ letters and
digits that mixes upper case, lower case, and a digit (`'Hunter2024x'`; codec and algorithm
names such as `'base64url'`, `'aes256gcm'`, `'HS256'` do not). Called names
(`token.toBase64String()`, `hashPasswordV2(...)`) and identifiers with short version or year
tags (`apiEndpointV2Url`, `userId2024abcdef`) stay benign. The expression continues across
whitespace or a newline when the next token is `.`, `?.`, `[`, or `(` (`send(x) .then(...)`),
and after a `.` or `?.` whatever whitespace follows (`token . name`, `token ?. name`, a dot on
its own line); member and bracket links to the labelled parameter tolerate the same spacing
(`password .Hunter2024x`), and only a call written directly against a name (`x()`) is exempt as
a call. It ends at `,`, `;`, an enclosing closing bracket, or other top-level whitespace. Because
a sentence-ending dot also continues the expression, the word after it is inspected too
(`token.trim(). AB1234567890 next` blocks). A quote glued
to the expression (`token.x"...`) is not valid code and fails closed unless whitespace,
punctuation, or the end of the text follows it (quoted prose or a JSON-quoted payload closing).
Evidence redaction uses the same boundaries and also redacts unlabelled credential-shaped
words (display only). Residual gaps: a lower-case-only credential literal
(`send(x, 'hunter2024x')`), a credential identifier with short digit groups
(`send(x, OAuth2Token)`), and text after a closing quote and a space (`token.x" value`) are
not detected as arrow-body credentials. Known gaps also include labels outside the list.
Since Phase G, the exact backslash-escaped JSON-style labelled shape
(`{\"api_key\": \"...\"}` written as literal text) is detected in summary, payload, and
destination, judged by the existing label rules; this is not general escaped-secret
detection, and other escaped forms remain unsupported.

Since Phase H, seven provider credential formats are detected without a label, in summary,
payload values, payload keys, and destination, and are redacted the same way in evidence,
public approval views, and events. Prefixes are case-sensitive, and a prefix glued to a
preceding letter, digit, or underscore is not matched (as for `sk-`):
- PEM private-key blocks: a `-----BEGIN [RSA |EC |DSA |OPENSSH |ENCRYPTED ]PRIVATE KEY-----`
  header followed by key material, meaning a run of 32+ base64 characters mixing upper case,
  lower case, and a digit (after whitespace or literal `\n`), or a legacy `Proc-Type:` line.
  A header on its own, or with an elided (`MIIEvQ...`), placeholder, or filler body, is
  treated as documentation and does not block; evidence still redacts from the header through
  its `END` line, or to the end of the text. Public keys, certificates, and PGP key blocks are
  not matched.
- AWS access key IDs: `AKIA` or `ASIA` plus exactly 16 upper-case letters or digits, not part
  of a longer run. An `ASIA` ID must contain a digit, so words such as `ASIAPACIFIC...` do not
  block; a letters-only `ASIA` ID is therefore a known gap.
- GitHub tokens: `ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`, or `github_pat_` plus 30+ characters.
- GitLab tokens: `glpat-` plus 20+ characters.
- Stripe live keys: `sk_live_` or `rk_live_` plus 24+ letters or digits. Test-mode keys
  (`sk_test_`) are not in scope.
- Slack tokens: `xoxa-`, `xoxb-`, `xoxp-`, `xoxr-`, or `xoxs-` plus 10+ characters including a
  digit. `xoxo` is excluded so ordinary text does not match, and other Slack formats such as
  `xoxe` are not covered.
- Google API keys: `AIza` plus exactly 35 characters, not part of a longer run.

Residual gaps for these formats include key material split into short chunks, lower- or
mixed-case variants of a prefix, and providers not listed here. A private-key header followed
by a double-escaped `\\n` separator (a key inside JSON that was encoded twice) is not detected:
the action is not blocked and public approval views do not redact the field, although evidence
redaction still masks it from the header through its `END` line. JWTs and `Authorization: Basic`
headers are not detected, and Unicode obfuscation beyond the approved invisible format
characters (described below), such as look-alike letters, is not detected either.

Since Phase I, request metadata that the Data-Leak Guard would recognize is shown as
`[REDACTED]` wherever it is echoed: `action.type` (finding evidence, explanations,
`evaluation.actionType`, events, approval views, and execution reasons), `action.tool` and
`intent.task` (events and approval views), `intent.id`, `intent.allowedActions`, and
`intent.deniedActions` (approval views), each entry of `intent.allowedActions` and
`intent.allowedDestinations` in finding evidence, and an unknown `scenarioId` in the 404 error. Redaction replaces the whole value, so
a task that mentions an email address, for example, is also shown as `[REDACTED]`. The
redaction is display-only: it never changes a decision itself, and a redacted value is not
thereby safe to send (Phase M, below, separately made `action.tool` and `action.type` decision
inputs).

Since Phase M, `action.tool` and `action.type` are also inspected for decisions: a
secret-shaped value in either is a hard BLOCK under the same guard, before simulation
and on approval recheck. Every supported pattern applies there, including the Phase G and
Phase H formats, and a `tool` or `type` longer than 8,000 characters is hard-BLOCKed as
uninspectable like any other inspected field (the API sets no shorter length limit for them).
Fields are checked in the order summary, payload, destination, tool, type, and only the first
match is reported. `intent.task` remains uninspected for decisions because it is
free-form user prose; it is still redacted in public output when secret-shaped.

Invisible characters in credential labels: every inspected field (summary, payload values and
keys, destination, tool, type) is checked first exactly as written, and only when that finds
nothing is a copy with the Phase L invisible format characters (the set listed under the
Injection Scanner) removed checked too. A label or prefix split by one of them, such as `api`,
a zero-width space, then `_key=...`, or a provider prefix split by a soft hyphen, is therefore a
hard BLOCK with the same pattern kind as the unsplit value, and public display redaction, which
uses the same detector, hides it in `action.type`, `action.tool`, `intent.task`, approval
views, and events. Checking the field as written first keeps every existing detection:
removing characters can shorten a value below a minimum length (`password=ab` followed by
`c`, `d`, and `e`, each after a zero-width space, still blocks). The 8,000-character bound
applies to the field as written, before normalization, and `intent.task` is still not
inspected for decisions. Residual gaps: invisible characters outside the approved set (for
example U+061C), look-alike letters, an invisible character used in place of the space after
`Bearer` (the words are joined and no longer match), encoded secrets, and secrets split by
visible characters. The repository secret scanner (`scripts/secret-scan.mjs`, see
`docs/security-baseline.md`) is separate and does not remove invisible characters, so a
credential split this way in a committed file is not found by it.

Calling the engine's `scanUntrustedContent` directly with more than 8,000 characters scans
only the first 8,000; the API rejects such content with HTTP 400.

A deterministic synthetic benchmark for this detector lives in `benchmarks/detection/`
(versioned corpora, 198 hand-authored fixtures in v1.9, per-family precision/recall,
synthetic corpus only; see its README). Malformed
payloads (nested objects, arrays, null values) are rejected with HTTP 400 at the
API boundary.

## Model-assisted analysis (Phase 4, mock only)

Advisory layer only. Deterministic policy remains authoritative.

- Config: see `.env.example` (`MODEL_API_KEY`, `MODEL_PROVIDER_MODE`, `MODEL_BASE_URL`,
  `MODEL_NAME=muse-spark-1.3`, timeout/limit/budget variables). Real `.env` files are git-ignored.
- Effective mode is `mock` by default. A real live provider exists behind the
  `MODEL_LIVE_ENABLED=true` plus key-presence gate (Phase 6), but live mode has
  never been enabled or called in this project, and no credits were used.
- Phase 5 verified the official contract at dev.meta.ai (base URL, `muse-spark-1.3`,
  Bearer auth, `POST /chat/completions`, response and error shapes, pricing and rate
  limits) and corrected the offline builder/parser. See `docs/live-readiness.md`.
  A future live step still needs explicit user authorization and confirmed budget.
- `GET /api/model/status` reports mode and key presence only, never the key value.
- Local key setup: the API server (`apps/api/src/server.ts`) loads the repo-root
  `.env` at startup using Node 22's built-in `process.loadEnvFile()` — no dotenv
  dependency. Tests importing `createApp` do not load it. `.env` is git-ignored
  (`.env`, `.env.*`, except `!.env.example`). Copy `.env.example` to `.env`,
  put your key after `MODEL_API_KEY=` locally, and keep `MODEL_LIVE_ENABLED=false`
  until a live smoke test is separately authorised.
- Provider output is strictly validated in the engine (`validateModelOutput`). Any decision,
  approval, execution, or tool-call field makes it invalid and produces an analysis failure.
- Failures (timeout, network, malformed, oversized, budget) show as failed/unavailable,
  never as evidence that content is safe.
- Only seeded synthetic scenario text is analysed. Do not send user documents or personal
  data to an external provider without explicit consent.

## Layout

- `packages/engine` — framework-independent TypeScript security engine (contracts, evaluation, seeded scenarios).
- `apps/api` — Express API. Validates input, calls the engine, records in-memory activity events.
- `apps/web` — React/Vite/Tailwind dashboard. Renders API/engine responses only.

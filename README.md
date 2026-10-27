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
npm run dev:api   # terminal 1 -> http://localhost:4000
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

Intent Firewall: action types must be explicitly allowed, destinations must match
`allowedDestinations` when present, and missing/empty permissions block conservatively.
Conflicting allow+deny resolves to deny. Scanner findings stay separate from intent findings.

Data-Leak Guard: the engine also inspects the outbound action's `summary` and `payload`
before execution or confirmation. A value matching a supported secret pattern — labelled
assignments such as `api_key=`, `access_token=`, `client_secret=`, `auth_token=`,
`private_key=`, `refresh_token=`, `session_token=`, `secret_key=`, `db_password=`,
`aws_secret_access_key=`, `x-api-key`, `passphrase=`, `password:`/`token:` with `=`, `:`,
or `=>` separators (including JSON-style quoted
keys), Bearer credentials, realistic `sk-` tokens (`sk-proj-...`, `sk-ant-...`, underscored
forms), seeded `FAKE_...SECRET` values, or email addresses — is a hard `BLOCK`
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
member access on the label itself (`token => token.trim()`) is treated as code, not a
credential; quoted values and literal values such as `token => abc123` still block. Known
gaps now include labels outside the list and backslash-escaped JSON written as text
(`{\"api_key\": ...}`). A deterministic synthetic benchmark for this detector lives in
`benchmarks/detection/` (53 hand-authored fixtures, per-family precision/recall,
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

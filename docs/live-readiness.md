# Live-readiness audit — Meta Model API (Phase 5)

Date of documentation inspection: 2026-10-26.
Status: **mock by default. Two separately authorized one-request live smoke calls
were made on 2026-10-29 (see "Smoke test results"): the first returned no usable
answer (cut off at the 600-token cap); after offline fixes, the second returned a
valid advisory answer. Live mode is off again. Two calls are a smoke test, not
evidence of reliability across inputs.**

## Official documentation inspected

- https://dev.meta.ai/docs/overview
- https://dev.meta.ai/docs/authentication
- https://dev.meta.ai/docs/models
- https://dev.meta.ai/docs/api-reference/chat-completions/create-chat-completion
- https://dev.meta.ai/docs/api-reference/chat-completions/schemas
- https://dev.meta.ai/docs/pricing-rate-limits
- https://dev.meta.ai/docs/error-handling
- https://dev.meta.ai/docs/structured-output

Note: `https://developers.meta.ai/` does not resolve (DNS). The official Model API
documentation lives at `dev.meta.ai`. `https://developers.meta.com/` is a general
developer portal and contains no Model API contract.

## Phase 9B — capability and integration readiness (2026-10-26)

Documentation-only update. No live call, no credit use, key not exposed, mock remains effective.

### Additional official pages inspected in Phase 9B

- https://dev.meta.ai/docs/models (Muse Wonder, Muse Spark, SAM 3.1 sections)
- https://dev.meta.ai/docs/media-segmentation
- https://dev.meta.ai/docs/sam/reading-segmentation
- https://dev.meta.ai/docs/pricing-rate-limits (Muse Wonder and SAM 3.1 sections)

### Verified model facts

| Model | Model ID | Endpoints | Inputs | Outputs | Pricing as displayed 2026-10-26 | Limits |
| --- | --- | --- | --- | --- | --- | --- |
| Muse Spark 1.3 | `muse-spark-1.3` (Standard) / `muse-spark-1.3-contributor` | Responses, Chat Completions, Messages | Text, image, video, audio (audio degraded on 1.3), PDF per Models table | Text | Standard per 1M: cached $0.15, in $1.25, out $4.25 | 3,000 RPM / 4,000,000 TPM per team |
| Muse Wonder 1.0 | `muse-wonder-1.0` — Model API pay-as-you-go is Standard mode only; preview | Responses, Chat Completions, Messages | Text, image, video, audio, PDF; 1,048,576-token context; reasoning effort `minimal`–`max` | Text | Standard only per 1M: cached $0.20, input $4.00, output $20.00. No Contributor | 3,000 RPM / 4,000,000 TPM per team |
| SAM 3.1 | `sam-3.1` | Responses (`POST /v1/responses`); clips may use Files API | Short noun-phrase text prompt, image, video; also box/point prompts | Geometry as special-token text: per frame line `<Nf>` with records `id<|box;x1..;y2..;w;h|><|mask;...;data=H,W,<enc>payload|>`; streamed `output_text` deltas; zero matches = empty lane, not an error | $2.50 per 1,000 images; $0.20 per 1,000 video frames; video minimum 50 frames billed | 3,000 RPM, no TPM |

Other verified Wonder facts: Wonder and Spark take the same requests on the same
endpoints, so moving a workload between them is a model-ID change plus the
reasoning/cost choice. Meta positions Wonder for long-running complex work where
capability matters more than cost per token, and Spark for high-volume,
latency/cost-sensitive work such as classification and tight tool loops.

SAM/Spark pairing per official guidance: use a Muse Spark (VLM) model for a
caption, scene answer, or coordinates as text; use SAM 3.1 when you need the
pixel region (boxes and pixel-accurate masks), cropping, measuring, or tracking.

### Recommended combination for the hackathon

Recommended: **Muse Spark 1.3 only** for the live candidate path; Wonder and SAM
are optional stretch experiments, not required scope.

Rationale:

- Spark already matches the Phase 4–6 adapter (`/chat/completions`, structured
  advisory JSON, same validator, same gate) with the smallest incremental work:
  one separately authorised live smoke test, not a new integration.
- Wonder is roughly 3.2x the input price and 4.7x the output price of Spark
  Standard, is in preview, and is optimised for multi-file/long-horizon agentic
  coding — capability AgentShield's small advisory classification does not need.
- SAM requires a different protocol (Responses, streaming segmentation text,
  mask decoding), new image fixtures, new parsing/rendering and validation. It
  contributes no authorization signal (below), so it cannot strengthen the core
  demo claim.

### Proposed integrations (not implemented)

1. Muse Spark advisory (existing design, Phase 4–6). Deterministic scanner and
   Spark contextual observations stay side by side and labelled. Possible v2
   advisory fields: paraphrase/obfuscation hints, context summary, quoted-text
   vs instruction distinction, and confidence wording — all still advisory,
   all still unable to change ALLOW/CONFIRM/BLOCK, approval, or execution.
   Before any live use, separately authorise: billing eligibility review,
   concrete budget/request cap, `MODEL_LIVE_ENABLED=true` only for the smoke
   session, seeded synthetic text only, and dashboard usage/credit confirmation.

2. Optional Muse Wonder intent-alignment check (separate endpoint, separate
   advisory contract). Input: explicit user intent, proposed action, destination,
   and the deterministic findings. Output would be a strictly-validated
   observation such as `{alignment: "aligned"|"unclear"|"misaligned", rationale,
   ambiguityFlags}` — never a decision. It must never replace deterministic
   authorization, create or approve a pending approval, modify stored actions,
   or execute tools. Even a Wonder disadvantage framing should be treated as a
   prompt to slow down/review, not enforcement. Cost controls: cache by
   intent/action hash, evaluate only CONFIRM or high-risk cases, cap output
   tokens, and disable by default behind `MODEL_WONDER_ENABLED=false`.

3. Optional SAM 3.1 visual experiment (synthetic screenshots only). Generate
   fully synthetic demo screenshots (fake chat/email UI, no real user screens,
   no personal data). Send a public/temporary image URL or the documented
   Responses media input, prompt with noun phrases like "warning banner",
   "payment button", or "external link", render returned boxes on an overlay,
   then feed any extracted visible text to the deterministic scanner as
   untrusted content. Critical limitation: segmentation localizes visual
   objects; it does **not** itself prove prompt injection, malicious intent, or
   authorization. A segmented "payment button" is geometry, not proof. Without
   OCR/text extraction and deterministic scanning, SAM adds a picture, not a
   security decision. This is therefore research/stretch scope only.

### Risks

Implementation: Responses/streaming segmentation parsing, base85 mask decoding,
image hosting/URL handling, screenshot fixtures, and UI overlays add several
days of work if attempted together. Wonder adds a second validator, caching,
and cost controls.

Cost (estimates only, using prices above; actual token counts unknown): Spark
advisory at ~1,000 input + 150 output tokens costs roughly $0.002 per evaluation
Standard. Wonder at the same size costs roughly $0.007. SAM images cost $0.0025
each; SAM video has a 50-frame minimum ($0.00001 per request at frame pricing,
plus engineering time). Small absolute costs — the real risks are unverified
payment eligibility, silent retry loops, and repeated demo runs without a cap.
Keep `MODEL_MAX_REQUESTS`, timeouts, no unbounded retries (already implemented),
and a session-level request cap.

Testing/account: no live model has been exercised. Account access, key validity,
credit applicability, payment verification, geographic availability, and preview
model (Wonder) availability for this account remain unverified. Contributor
mode permits training use of submitted content; AgentShield must stay Standard
unless the user explicitly accepts that trade-off for synthetic data.

### Task sequence for the remaining hackathon days

Day A (mock-only, no approval needed): finalise core demo script, harden
deterministic fixtures/regressions, dashboard labels, and screenshots/video of
the working mock demo. Optional offline-only Wonder contract types and mocked
fixtures; optional synthetic screenshot fixtures. No live calls.

Day B (requires explicit user authorisation and budget cap first): one bounded
Muse Spark live smoke test on seeded synthetic text; check dashboard
usage/credits; rerun full verification (`npm test`, `npm run typecheck`,
`npm run build`, `npm audit`). If billing or payment blocks the call, stop and
keep the mock demo as the submission path.

Day C (optional stretch, only if the core demo is stable): Wonder mocked
intent-alignment prototype behind a disabled flag, or SAM segmentation overlay
experiment with synthetic screenshots. Either must be demoable in mock form if
live access fails.

Day D: freeze, regression, demo rehearsal, README/docs accuracy, submission
checklist. Do not add new security claims in the final day.

### What approval is still needed

- Explicit authorisation and a concrete budget/request cap before any live call.
- Confirmation that payment/credit eligibility in the Meta dashboard allows the
  call under Standard mode.
- A separate decision on whether Wonder or SAM stretch work is in scope at all.
  Default recommendation: neither is required for submission.


## Verified against official documentation

| Item | Verified value | Source |
| --- | --- | --- |
| Base URL | `https://api.meta.ai/v1` | Authentication, Create a chat completion |
| Endpoint | `POST /chat/completions` | API reference |
| Model ID | `muse-spark-1.3` (latest Muse Spark, Standard mode, recommended for new work) | Models |
| Authentication | `Authorization: Bearer $MODEL_API_KEY`, key stored in an environment variable, never committed or placed in client code | Authentication |
| Required request fields | `model`, `messages` (ordered array, min 1; each has `role` and `content`) | Schemas |
| Optional fields used by our builder | `response_format` (`json_schema`), `max_completion_tokens` | Schemas, Structured Output |
| Response object | `object: "chat.completion"`, required `id`, `created`, `model`, `choices[]` | Schemas |
| Choice fields | `choices[].message`, `choices[].finish_reason` (`stop`, `length`, `tool_calls`, `content_filter`, `function_call`), `choices[].index` | Schemas |
| Usage fields | `usage.prompt_tokens`, `usage.completion_tokens`, `usage.total_tokens` (optional) | Schemas |
| Structured output | `response_format: {type: "json_schema", json_schema: {name, strict, schema}}` constrains decoding to the schema | Structured Output |
| Error envelope | `{error: {message, type, param, code}}`; types include `invalid_request_error`, `authentication_error` (401, code `invalid_api_key`), `rate_limit_error` (429, code `rate_limit_exceeded`), `server_error` (5xx). Unknown paths return 404 with an empty body | Error handling |
| Rate limits | Per team, not per key. `muse-spark-1.3`: 3,000 RPM / 4,000,000 TPM. Headers `x-ratelimit-limit-*` and `x-ratelimit-remaining-*` | Pricing and rate limits |
| Pricing (Muse Spark, per 1M tokens) | Standard: cached input $0.15, input $1.25, output $4.25. Contributor: $0.002 / $0.10 / $0.20 | Pricing and rate limits |

Pricing uncertainty: prices above are what the official page displayed on the
inspection date. They can change; re-check before authorizing spend. Our adapter
also enforces its own local request budget (default 50) regardless of plan limits.

## Comparison with the Phase 4 adapter

Already correct and unchanged:

- Base URL, model ID, Bearer header, `model` + `messages` request fields.
- `choices[0].message.content` extraction and JSON parsing.
- Strict runtime validation of advisory output, including rejection of any
  decision, approval, execution, or tool-call field.

Corrections applied in Phase 5 (offline construction and parsing only):

1. Builder now sends `response_format` with `type: "json_schema"` and our advisory
   schema (`META_ANALYSIS_JSON_SCHEMA`), plus `max_completion_tokens: 600`
   (raised to 1,500 after the smoke test). `max_tokens` is deprecated per the
   official schema and is not used.
2. Parser now rejects a response whose `object` is not `"chat.completion"`,
   and rejects `finish_reason: "tool_calls"` or any `message.tool_calls`.
   A model tool-call request is never followed in AgentShield. (Refined after
   the smoke test: `finish_reason: "function_call"` and a `function_call` are
   rejected too, while a `tool_calls` of `null` or `[]`, which requests nothing,
   is accepted.)
3. Added `metaErrorCategory()` to map the documented error envelope to a
   sanitized category. Raw error bodies are never stored or logged.
4. Mocked fixtures in tests now use the full documented response shape.

Our runtime validator still runs even with structured output enabled. A
schema-constrained reply would still be untrusted model output.

## Billing and credential readiness (separate statuses)

| Status item | State |
| --- | --- |
| Hackathon credits | User reports $150 visible in the dashboard (not independently verified by this audit) |
| Payment method | User reports not verified |
| API key in current process environment | Not configured at the Phase 5 audit; not re-checked since (audits do not open `.env`) |
| Live API access in code | Implemented since Phase 6 (`MetaLiveProvider`), off by default: effective mode is `mock` unless `MODEL_LIVE_ENABLED=true` and a key are both set. Tested only with fake transports |
| Credit consumption this phase | None |

Visible credits do not guarantee requests will succeed. Per the official error
documentation, billing/account problems surface as API errors, and a missing,
invalid, or revoked key returns 401 `invalid_api_key`. Do not assume a request
will succeed until payment and account state are confirmed in the dashboard.

Before any future live call, the user should review in the Model API dashboard
at https://dev.meta.ai/ (no changes were made by this audit):

1. API Keys tab: confirm a key exists for this application, and that it can be
   revoked/rotated. Use a unique key per application.
2. Billing/account status: confirm whether a payment method is required for
   pay-as-you-go use and whether it is verified.
3. Credits: confirm the $150 credit balance, what it applies to, and its expiry.
4. Usage/limits view: confirm team rate limits (3,000 RPM / 4M TPM for
   `muse-spark-1.3`) and any spend alerts.
5. Data mode: confirm Standard mode (`muse-spark-1.3`). In Standard mode your
   content is not used to train Meta models. The `-contributor` variant is
   cheaper but permits training use; AgentShield does not use it.

## Live provider implementation (Phase 6; off by default, two live smoke calls)

Implemented in `apps/api/src/model/live.ts` behind the `ModelProvider` interface.
"Implemented" here means built and exercised by tests with fake transports; it
has sent exactly two requests to Meta, the two smoke tests described below.

- `MetaLiveProvider` uses the verified contract, timeout with `AbortSignal`,
  bounded input/output sizes, sanitized status/category logging, and bounded
  retries (default 2, max 3) only for 429/5xx, honouring `Retry-After` capped
  at 5 seconds. No retry on 401, malformed output, or oversized output.
- HTTP access goes through an injected `HttpTransport`. Tests use fakes; no test
  contacts Meta. Constructing the provider performs no network I/O and there is
  no startup health check that calls Meta.
- Gate: `selectModelProvider()` returns the live provider only when
  `MODEL_LIVE_ENABLED` is exactly `"true"` **and** `MODEL_API_KEY` is present.
  Flag off, or flag on without a key, returns the mock provider (fail closed).
  Default runtime remains mock. The key is read only from the server process
  environment and is never returned to the frontend (`/api/model/status`
  reports presence and flag state only).

### Live-readiness hardening (offline, tested with fake transports)

- Request budget: `MODEL_MAX_REQUESTS` (default 50) caps outgoing provider
  request attempts per API process, including retries, not analyses. Each
  analysis reserves its first attempt and the live provider reserves every
  retry; when the budget is spent the analysis is `unavailable` with reason
  `request-budget-exceeded` and nothing is sent. Reservation is a single
  synchronous check-and-increment, so concurrent evaluations cannot overshoot.
  The mock provider counts one attempt per analysis, as before. The budget is in
  memory and resets when the API restarts.
- Cancellation: when the analysis timeout (`MODEL_TIMEOUT_MS`) expires, the
  service aborts the provider's in-flight request, including reading its
  response body (successful or failed), the retry wait ends early, and no
  further attempt is sent. Each attempt's timer and abort listeners are always
  removed, and the provider settles even if a transport ignores the abort.
  Cancelling stops client-side work only: it cannot undo a request Meta has
  already received, which may still be processed and billed.
- Response bodies: every body is read inside its attempt's timeout and
  cancellation scope, with a bound: successful bodies up to
  `MODEL_MAX_OUTPUT_CHARS`, failed (non-2xx) bodies up to 4,096 characters, only
  to find a documented error category. A streamed body is read in chunks and
  cancelled, not buffered, past the bound. A failed body is consumed or
  cancelled before any retry. An unreadable failed body leaves the HTTP status
  category and does not change the retry policy (429/5xx only); a timeout while
  reading ends the attempt without a retry. The default `MODEL_MAX_OUTPUT_CHARS`
  is 20,000 (formerly 4,000): a schema-maximal answer wrapped in a full
  `chat.completion` body measures 4,017 characters as compact ASCII JSON and up
  to about 18,000 when quotes or non-ASCII text are escaped, so 4,000 rejected
  even the smallest of these. Tests cover each case; only a degenerate answer
  made entirely of control characters exceeds 20,000, and it fails safely.
- Usage: when a response carries the documented `usage` object, its
  `prompt_tokens`, `completion_tokens` and optional `total_tokens` are added to
  in-memory totals and logged as counts only (`model-usage status=reported ...`).
  A null or absent total is logged as `not-reported` and never computed.
  Missing or implausible prompt/completion counts, an implausible total, and
  successful bodies that are oversized or not JSON are logged as
  `model-usage status=not-reported` and never estimated: tokens were spent, but
  no count is available. A response that arrives after cancellation is
  discarded unread, so its usage is not recorded locally. Totals are not exposed
  by the API; the server log and the Meta dashboard are the sources.
- Logging: model log lines contain only fixed text, integer counts, the integer
  HTTP status, and a category from a fixed list. A provider error `type` or
  `code` is logged only when it exactly matches a documented value
  (`invalid_request_error`, `authentication_error`, `rate_limit_error`,
  `server_error`, `invalid_api_key`, `rate_limit_exceeded`); anything else is
  replaced by the category derived from the HTTP status. No key, prompt,
  response content, provider error message, or other provider-supplied text is
  logged.
- Unusable answers: a successful response that cannot be used fails with the
  public reason `malformed`, as before, and the server logs one fixed code,
  `model-live status=unusable-response reason=<code>`: `body-oversized`,
  `body-not-json`, `unexpected-envelope`, `unexpected-object`, `no-choices`,
  `tool-call`, `finish-length` (cut off at the token cap), `finish-content-filter`,
  `finish-other` (an undocumented `finish_reason`), `content-missing`,
  `content-not-string`, `content-empty` or `content-not-json`. The code never
  appears in the API response, and no response text is logged. An answer cut
  off at the cap or by the content filter is rejected even if it parses. None of
  these is retried.

## Smoke test results (2026-10-29)

Each call was separately authorized, sent exactly one request for "Benign:
create summary" using the procedure below, and was followed by switching live
mode off. Neither call's credit or billing change is recorded here.

### First call: unusable answer (`malformed`)

Preflight passed: budget 1, no retries, 15,000 ms timeout.

- Logs: `model-usage status=reported promptTokens=256 completionTokens=600
  totalTokens=856`, then `model-analysis status=failed category=malformed`.
- The deterministic decision stayed ALLOW, risk 10, and the simulated execution
  completed. Model analysis is advisory only.
- Diagnosis (offline): a usage line is logged only after a 2xx body was read
  and parsed as JSON, so the failure came from extracting the answer from
  `choices[0]`. Completion tokens equal the 600-token cap, so the answer was
  almost certainly cut off (`finish_reason: "length"`), leaving truncated or
  empty content. The exact condition was not logged at the time.
- Fixes made offline afterwards: the token cap is 1,500; each unusable answer
  logs a fixed reason code; the default body limit is 20,000 characters; an
  empty `tool_calls` is accepted. The second call below exercised them once.

### Second call: valid advisory answer (`success`)

Made after the fixes above. Preflight passed all eight checks: live mode, key
present, budget 1, no retries, 15,000 ms timeout, 20,000-character output limit,
model `muse-spark-1.3`, base URL `https://api.meta.ai/v1`.

- Logs (as reported from the API terminal): `model-usage status=reported
  promptTokens=256 completionTokens=1047 totalTokens=1303`.
- The web app showed the model advisory analysis as `success (meta)`: the answer
  passed AgentShield's strict output validation. The deterministic decision
  stayed ALLOW, risk 10, with simulated execution only.
- 1,047 completion tokens is above the former 600-token cap and below the new
  1,500 cap, which is consistent with the first call having been cut off.
- Cleanup: `MODEL_LIVE_ENABLED=false` was set and the restarted API reported
  `mode: mock`, `liveEnabled: False`, `isMock: True`.
- Not established by one call: answer quality, consistency across inputs,
  latency under load, or whether other prompts stay under the 1,500-token cap.

## One-call live smoke-test procedure

Performed twice, on 2026-10-29 (see "Smoke test results"). Every repeat needs its
own explicit authorization and the dashboard checks above. It sends one request
with seeded synthetic text.

Preconditions:

- Authorization for exactly one live request, and a confirmed payment/credit
  state in the dashboard, Standard mode (`muse-spark-1.3`, not `-contributor`).
- A key created in the dashboard for this application. Never paste it into chat,
  documentation, screenshots, or source control.
- Both dev servers stopped.

Steps (Windows PowerShell, repository root):

1. Confirm `.env` is ignored: `git check-ignore -v .env` must print a `.gitignore`
   rule. Confirm no `MODEL_*` variable is set in the shell, which would take
   precedence over `.env`: `Get-ChildItem Env:MODEL_* | Select-Object Name`
   must print nothing. (Names only; never print values.)
2. Edit the git-ignored `.env` locally. Set the key value yourself and these
   limits:

   ```text
   MODEL_API_KEY=<set locally; never commit or share>
   MODEL_LIVE_ENABLED=true
   MODEL_MAX_REQUESTS=1
   MODEL_MAX_RETRIES=0
   MODEL_TIMEOUT_MS=15000
   ```

   `MODEL_MAX_REQUESTS=1` with `MODEL_MAX_RETRIES=0` means the API process can
   send at most one request in total; every later evaluation returns
   `request-budget-exceeded` without contacting Meta. Leave `MODEL_NAME` and
   `MODEL_BASE_URL` unset (or set them to `muse-spark-1.3` and
   `https://api.meta.ai/v1`): the key is sent to whatever base URL is configured.
   Leave `MODEL_MAX_OUTPUT_CHARS` unset or set it to `20000`: an `.env` copied
   from an older `.env.example` contains `4000`, which rejects a valid answer as
   oversized. Save `.env` as UTF-8 without a byte-order mark (Windows PowerShell 5.1's
   `Set-Content -Encoding UTF8` and `Out-File` add one): Node's `.env` loader then
   misreads the first line, and the preflight reports it as a failure.
3. Build the engine and the API once, so the preflight and the API use the
   current code:

   ```powershell
   npm run build -w @agentshield/engine
   npm run build -w @agentshield/api
   ```

4. Run the configuration preflight below in terminal 1, the same terminal that
   ran step 1 and will start the API in step 5: shell variables take precedence
   over `.env`, so another terminal could see different settings. Continue only
   if it prints `PREFLIGHT PASS`. On `PREFLIGHT FAIL`, fix the settings it names
   in `.env` (or remove the overriding shell variable) and run it again.
5. Start the API **without watch mode** in terminal 1:
   `npm run start -w @agentshield/api` (it runs `node dist/server.js`). Start the
   web app in terminal 2: `npm run dev:web`. Do not use `npm run dev:api` for
   this test: it runs `tsx watch`, which restarts the API whenever a source file
   is saved. The attempt budget lives in the API process's memory, so every
   start or restart of the API begins with a fresh one-attempt budget and allows
   one more request. Start the API once and do not restart it during the
   session; if it restarts or crashes, stop and treat the session as finished.
   Then check that the model status reports `mode: live`, `liveEnabled: True`,
   `apiKeyConfigured: True` and model `muse-spark-1.3`. Since M0 the API needs
   its local token; this reads it from the token file without displaying it:

   ```powershell
   $auth = @{ Authorization = 'Bearer ' + (Get-Content -Raw "$env:LOCALAPPDATA\AgentShield\api-token").Trim() }
   Invoke-RestMethod http://127.0.0.1:4000/api/model/status -Headers $auth
   Remove-Variable auth
   ```

   If not, stop the servers and fix the configuration; do not evaluate
   anything. Sign in to the web app with the same token (see the README).
6. In **Scenario Lab**, select "Benign: create summary" and click
   **Evaluate Action Now** exactly once. The decision stays ALLOW, risk 10,
   regardless of the model; deterministic policy is authoritative.
7. Record, without screenshots of `.env` or terminals that show secrets:
   - the advisory analysis status and failure reason in the web app (a category
     such as `timeout` or `http`, never a raw body);
   - the API terminal's `model-usage ...` line (counts only), if any;
   - the API terminal's `model-live status=unusable-response reason=...` line
     (a fixed code), if any;
   - the usage/credit change in the Meta dashboard.
8. Stop on any outcome. Do not retry, do not evaluate other scenarios, and do
   not raise the limits in the same session. A `timeout` means the client
   stopped waiting; the request may still have been processed and billed, so
   check the dashboard. `http` usually means an invalid key (401), rate limit
   (429) or a server error (5xx); `network` means Meta was not reached.

### Configuration preflight (offline; never prints the key)

Run from the repository root after step 3. It loads `.env` the same way the
API does (a variable already set in the shell takes precedence over `.env`) and
reads it through the API's own compiled config loader
(`apps/api/dist/model/config.js`), which imports nothing and makes no network
request. It prints, for each setting, the expected value, the effective value
the API would use, and whether it passes. It never prints `MODEL_API_KEY` or any
raw text from `.env`, and hides any shown value that contains the key.

A setting passes only if its effective value is exactly the expected one **and**,
for the four values you must write, the text in `.env` is exactly `true`, `1`,
`0` or `15000`. Missing, empty, misspelled (`one`, `15s`), padded or
out-of-range values fail instead of silently becoming a default or being
clamped (for example `one` would otherwise mean 50 requests, an empty retry
count 2 retries, and `15s` a 100 ms timeout). `MODEL_MAX_OUTPUT_CHARS` passes
only when unset or exactly `20000`. The exit code is 0 on pass and 1 on fail.

Paste the whole block into PowerShell; the closing `'@` must stay at the start
of its line.

```powershell
$preflight = @'
const { loadModelConfig } = await import('./apps/api/dist/model/config.js');
const env = process.env;
const config = loadModelConfig(env);
const key = env.MODEL_API_KEY ?? '';
const show = (value) => (key && String(value).includes(key) ? '[hidden]' : value);
const exactly = (name, text) => env[name] === text;
const rows = [
  ['mode', 'live', config.effectiveMode, exactly('MODEL_LIVE_ENABLED', 'true'), 'MODEL_LIVE_ENABLED must be exactly true'],
  ['keySet', true, config.apiKeyConfigured, true, 'MODEL_API_KEY is missing or empty'],
  ['maxRequests', 1, config.maxRequests, exactly('MODEL_MAX_REQUESTS', '1'), 'MODEL_MAX_REQUESTS must be exactly 1'],
  ['maxRetries', 0, config.maxRetries, exactly('MODEL_MAX_RETRIES', '0'), 'MODEL_MAX_RETRIES must be exactly 0'],
  ['timeoutMs', 15000, config.timeoutMs, exactly('MODEL_TIMEOUT_MS', '15000'), 'MODEL_TIMEOUT_MS must be exactly 15000'],
  ['maxOutputChars', 20000, config.maxOutputLength, env.MODEL_MAX_OUTPUT_CHARS === undefined || exactly('MODEL_MAX_OUTPUT_CHARS', '20000'), 'MODEL_MAX_OUTPUT_CHARS must be unset or exactly 20000'],
  ['model', 'muse-spark-1.3', config.model, true, 'MODEL_NAME must be unset or muse-spark-1.3'],
  ['baseUrl', 'https://api.meta.ai/v1', config.baseUrl, true, 'MODEL_BASE_URL must be unset or https://api.meta.ai/v1'],
].map(([setting, expected, effective, written, fix]) => {
  const ok = effective === expected && written;
  return { setting, expected, effective: show(effective), ok, fix: ok ? '' : fix };
});
console.table(rows);
const failed = rows.filter((row) => !row.ok).map((row) => row.setting);
console.log(failed.length === 0 ? 'PREFLIGHT PASS' : 'PREFLIGHT FAIL: do not start the API. Fix: ' + failed.join(', '));
process.exitCode = failed.length === 0 ? 0 : 1;
'@
$preflight | node --env-file=.env --input-type=module
```

Stop and clean up:

1. Stop both servers with Ctrl+C.
2. In `.env`, set `MODEL_LIVE_ENABLED=false` (remove the key line too if it is
   no longer needed). If the key may have been exposed anywhere, revoke or
   rotate it in the dashboard.
3. Start the API again (`npm run start -w @agentshield/api`) and confirm
   `/api/model/status` reports `mode: mock` (with the token header shown in
   step 5), then stop it again.
4. Confirm `git status --short` shows no `.env` and run `npm run security:verify`.
5. Re-run `npm test`, `npm run typecheck` and `npm run build`, and record the
   result and the dashboard delta in this document.

Before any wider use, decide on Contributor vs Standard explicitly, because
Contributor mode permits training on submitted content.

## Unverified

- Credit application. Both smoke calls reached the API and returned a successful
  HTTP response with token usage; their dashboard deltas are not recorded here.
- Whether the dashboard requires payment verification before credit use.
- Live model output quality, and schema conformance beyond the one valid answer
  the second smoke call returned.
- Whether live responses always include the `usage` object (both smoke calls
  did).
- Pricing and limits may have changed after the inspection date.

# Live-readiness audit — Meta Model API (Phase 5)

Date of documentation inspection: 2026-10-26.
Status: **mock only. No live call has been made. No credits were consumed.**

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
   schema (`META_ANALYSIS_JSON_SCHEMA`), plus `max_completion_tokens: 600`.
   `max_tokens` is deprecated per the official schema and is not used.
2. Parser now rejects a response whose `object` is not `"chat.completion"`,
   and rejects `finish_reason: "tool_calls"` or any `message.tool_calls`.
   A model tool-call request is never followed in AgentShield.
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
| API key in current process environment | Not configured |
| Live API access in code | Disabled (`DisabledLiveModelProvider`, effective mode always `mock`) |
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

## Live provider implementation (Phase 6, still disabled)

Implemented in `apps/api/src/model/live.ts` behind the `ModelProvider` interface:

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

## Remaining steps for a future live smoke test (not started)

1. User verifies the dashboard items above (payment method and credit
   applicability in particular) and explicitly authorizes a live smoke test
   plus a concrete budget cap.
2. User creates a key in the dashboard and sets `MODEL_API_KEY` locally in the
   environment or a git-ignored `.env`, and sets `MODEL_LIVE_ENABLED=true`
   locally. Never paste the key into chat or commit it.
3. Run one bounded smoke request against seeded synthetic scenario text only,
   confirm the reported usage/credit delta in the dashboard, then re-run the
   full test suite.
4. Decide on Contributor vs Standard explicitly before any wider use, because
   Contributor mode permits training on submitted content.

## Unverified

- Real endpoint connectivity, credential validity, and credit application.
  Nothing was sent to the API.
- Whether the dashboard requires payment verification before credit use.
- Live model output quality and schema conformance in practice.
- Pricing and limits may have changed after the inspection date.

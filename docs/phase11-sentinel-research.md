# Phase 11 — Sentinel Model Research & Benchmark

Date: 2026-10-26. Research and audit only. No model was trained, no weights were
downloaded, no live API call was made, no credits were consumed, and runtime
behaviour is unchanged. Mock provider remains the effective model provider.

## 1. Repository audit findings (verified)

Verified in this session by reading files and running commands:

| Area | Verified fact | Path / evidence |
| --- | --- | --- |
| Workspaces | npm workspaces: `packages/*`, `apps/*`; scripts `dev:api`, `dev:web`, `build`, `test`, `typecheck` | `package.json` |
| Engine | Framework-independent TypeScript; scanner, deterministic evaluator, scenarios, advisory model contract | `packages/engine/src/` (`evaluate.ts`, `scanner/`, `model-analysis.ts`, `types.ts`, `scenarios.ts`) |
| Decision flow | Hard-deny (risk 95, approval-proof) → intent allow/deny/destination → explicit scanner-to-CONFIRM policy; scanner findings kept in a separate `scannerFindings` field | `packages/engine/src/evaluate.ts` |
| Scanner | 4 documented rules (`injection.instruction-override`, `injection.privilege-impersonation`, `injection.secret-exfiltration`, `injection.unauthorized-tool-action`), redacted evidence, 9 fixtures | `packages/engine/src/scanner/` |
| API | Express; `POST /api/evaluate`, `GET /api/approvals`, `POST /api/approvals/:id/approve|reject`, `GET /api/events`, `GET /api/scenarios`, `GET /api/model/status`, `/health` | `apps/api/src/app.ts` |
| Approval safety | In-memory pending records bound to stored intent/action/content/policy version; recheck on approve; duplicate/reject/expiry protections; allowlisted simulator with invocation counting | `apps/api/src/approvals.ts`, `apps/api/src/simulator.ts` |
| Advisory model layer | `ModelProvider` interface, mock provider, gated live provider (disabled by default), strict validator rejecting any decision/approval/execution field | `apps/api/src/model/`, `packages/engine/src/model-analysis.ts` |
| Tests | 72 passing at audit time: engine 28, API 44 (`npm test`, actually run) | test run 2026-10-26 |
| Git | Not a Git repository (`git rev-parse` fails). No history to protect or commit to | shell check |
| Other dirs | `docs/` holds `live-readiness.md`, `phase7-audit.md`; `stitch-screens/` exists but is currently empty; parent proposal PDF untouched | directory listing |
| Key / live | `MODEL_API_KEY` not present in the audit shell process; `MODEL_LIVE_ENABLED` unset; local `.env` keeps live false (Phase 9A) | presence-only checks |

Runtime and hardware (actually measured):

| Item | Value |
| --- | --- |
| Node | v22.22.3, npm 10.9.8 |
| Python | 3.12.10 default (`python`), also 3.14.5 (`py`) — pin 3.12 for ML work |
| Installed ML libs | torch 2.13.0+cpu (**CUDA not available in this build**), transformers 4.57.6, scikit-learn 1.9.0, onnxruntime 1.27.0, numpy 2.5.3, pandas present; `datasets` not installed |
| CPU | Intel i7-11800H, 8 cores / 16 threads |
| RAM | 15.7 GB |
| GPU | NVIDIA GTX 1650 Max-Q, 4 GB VRAM — present, but unusable by the installed CPU-only Torch build |
| Disk | 44.7 GB free on C: |

Confirmed facts vs assumptions:

- Confirmed: local CPU fine-tuning of a small encoder and ONNX CPU inference are
  practical on this machine (see §5). Confirmed: no training has happened yet.
- Assumption (labelled): the GTX 1650 could accelerate training only after a
  CUDA-enabled Torch build is installed; that is a large download and is **not**
  assumed available. The plan below is CPU-first.
- Gap: no dataset, no training code, no model artifacts, no benchmark harness
  exist yet. `datasets` and any experiment tracking would be new dependencies
  requiring approval in a later phase.

## 2. Existing architecture and safe integration points

Current flow:

```text
POST /api/evaluate
  -> deterministic engine (scanner + Intent Firewall + Action Gate)  [authoritative]
  -> ALLOW: simulated handler | CONFIRM: pending approval | BLOCK: stop
  -> advisory model analysis (mock by default)                       [advisory]
  -> structured response rendered by the dashboard
```

Safe future integration points for Sentinel, in order of safety:

1. **Offline evaluation only (first).** A Sentinel service consumed by tests and
   a benchmark harness, not by request handling. Zero runtime risk.
2. **A new advisory provider behind the existing `ModelProvider` interface**
   (`apps/api/src/model/provider.ts`), selected by the existing config gate,
   returning the existing `ModelAnalysis` shape after `validateModelOutput`.
   This reuses timeout, budget, failure, and "never evidence of safety"
   handling. Sentinel observations would appear in the advisory panel only.
3. **A separate versioned internal endpoint** (see §7) called only by the API
   server, never by the browser, with the same fail-safe semantics.

Unsafe points, explicitly rejected: inside `evaluate.ts` decision logic; inside
`approvals.ts` (no ML in approve/recheck); anywhere client-supplied Sentinel
scores are trusted (the server must run or verify the model itself, mirroring
the current rule that client findings/scores are ignored).

## 3. Recommended ML task and label taxonomy

Recommendation: **staged classification**.

- Stage 1 (primary, ships first): binary — `benign` vs `suspicious`.
- Stage 2 (same model, secondary head or second model): multi-class attack type
  among suspicious items.
- Intent mismatch is modelled separately from content injection: it is a
  relation between intent and action, not a property of text alone.

Rationale and trade-offs:

- A single 5-way classifier conflates two different signals. Content injection
  is about the untrusted text; intent mismatch is about intent↔action alignment.
  Training one text classifier to output "intent mismatch" from text alone
  teaches it spurious correlates and produces unexplained decisions that mimic
  authorization — exactly what AgentShield must avoid.
- Binary first gives a calibratable risk signal with the least data, is directly
  comparable to the deterministic scanner and to existing prompt-injection
  classifiers, and keeps error analysis simple.
- Multi-class attack typing is valuable for explanation and triage, but only
  once enough labelled examples per class exist. As a second stage it can be
  wrong about subtype without corrupting the primary suspicious/benign signal.
- Multi-label was considered (one text can contain override + exfiltration). If
  annotation shows frequent co-occurrence, Stage 2 becomes multi-label with
  per-label thresholds. Start multi-class, measure co-occurrence, then decide —
  do not assume separability.

Taxonomy:

| Level | Labels |
| --- | --- |
| Content (Stage 1) | `benign`, `suspicious` |
| Content (Stage 2) | `direct_injection`, `indirect_injection`, `obfuscated_injection`, `impersonation`, `exfiltration_request`, `tool_redirect`, `other_suspicious` |
| Relation (separate task) | `intent_aligned`, `intent_unclear`, `intent_misaligned` given (intent, action, destination) |

`impersonation`, `exfiltration_request`, and `tool_redirect` mirror existing
scanner rule categories so ML and rule outputs stay comparable per category.

Hard truth to state in every report: these classes are not perfectly separable.
Quoted attack examples, security education, fiction, and red-team transcripts
sit on the boundary. The dataset must record that ambiguity
(`annotation_confidence`, `is_quoted_or_discussed`) instead of forcing false
certainty.

## 4. Dataset design

Proposed location (future phase): `ml/datasets/sentinel/` with a dataset card,
versioned as `sentinel-dataset-v0.1.0`. JSONL, one sample per line.

Schema:

| Field | Type | Notes |
| --- | --- | --- |
| `sample_id` | string | Stable, e.g. `sen-000001`; never reused across versions |
| `text` | string | Untrusted content text; synthetic only; max 4,000 chars to match the API analysis limit |
| `intent_text` | string \| null | For relation-task samples only |
| `proposed_action` | object \| null | `{type, tool, destination}` for relation-task samples |
| `label` | enum | Stage-1 label (and primary label) |
| `attack_category` | enum \| null | Stage-2 category when suspicious |
| `source_type` | enum | `document`, `webpage`, `tool_output`, `email`, `chat`, `synthetic_direct` |
| `language` | string | BCP-47-ish: `en`, `es`, `hi`, `de`, … plus `mixed` |
| `obfuscation_type` | enum | `none`, `paraphrase`, `base64`, `leetspeak`, `spacing`, `unicode`, `translation`, `multi_turn` |
| `expected_risk` | enum | `low`, `medium`, `high`, `critical` (annotator judgement, not ground truth for calibration) |
| `group_id` | string | Leakage group: all variants/paraphrases/encodings of one base sample share it |
| `split` | enum | `train`, `validation`, `test`, assigned by group, frozen in the version |
| `annotation_confidence` | number 0–1 | Plus `is_quoted_or_discussed` boolean for hard benign cases |
| `review_status` | enum | `unreviewed`, `reviewed`, `adjudicated` |
| `notes` | string | Short rationale; no secrets |

Labelling guide (summary; full guide ships with the dataset):

- Label by what the text **tries to make an agent do**, not by keywords.
  "Ignore previous instructions" inside a security article is `benign` with
  `is_quoted_or_discussed=true`; the same sentence instructing the reader-agent
  is `direct_injection`.
- Safety advice ("never reveal your API key") is `benign`.
- Instructions consistent with the stated task in the scenario are `benign`
  for content; any mismatch belongs to the relation task, not the content label.
- Encoded payloads are labelled by their decoded intent, with
  `obfuscation_type` recording the transform. Keep the encoded form as the text.
- Borderline samples require a second annotator; disagreement → `adjudicated`
  or exclusion from test.

Composition targets for v0.1 (proposed, not yet collected): roughly 2,000–4,000
samples; ≥35% benign including hard benign (security discussion, quoted attacks,
harmless "ignore", on-task instructions); attacks spread across direct,
indirect (embedded in documents/web/tool output), paraphrased, encoded, and a
small multilingual slice (Spanish/Hindi/German where annotation is reliable).
All synthetic or from openly licensed sources with recorded licences. No real
passwords, keys, personal data, or external targets; seeded secrets stay in
the existing clearly-fake style (`FAKE_TEST_SECRET_123`).

Splits and leakage control:

- Split **by `group_id`**, never by row: 70/15/15 train/validation/test.
- Near-duplicate control before splitting: exact-hash dedupe plus
  normalized-text (lowercase, whitespace/punctuation collapsed) dedupe, plus a
  similarity check (e.g. token-set Jaccard ≥ 0.9) that forces same-group.
- The test split is frozen at dataset release. Model selection, thresholds, and
  prompt/rule tweaks use validation only. Any test-set peek that drives a
  change requires a new dataset minor version and a fresh held-out slice.
- Public-source samples keep their source licence and attribution recorded per
  group, so a licence problem can be removed cleanly.

## 5. Candidate models (authoritative sources inspected 2026-10-26)

| Candidate | Role | Verified facts | Licence | Fit |
| --- | --- | --- | --- | --- |
| TF-IDF + Logistic Regression (scikit-learn 1.9.0, installed) | Mandatory simple baseline | No download, trains in seconds on CPU, fully reproducible | BSD (scikit-learn) — component licence, verify at adoption | Sets the bar every neural claim must beat; strong on keyword attacks, weak on paraphrase |
| Rule scanner (existing) | Deterministic baseline already in repo | 4 rules, explainable, zero ML risk | Project code | The honest comparator: Sentinel advisory must add value beyond it, especially on paraphrase/obfuscation slices |
| `microsoft/deberta-v3-xsmall` | **Recommended fine-tuning candidate** | HF model card inspected; DeBERTa-v3 architecture; English; MIT licence tag on the card | MIT (per HF card) | ~22M-class small encoder family — fast CPU training/inference, small artifact; confirm exact parameter count and file sizes on the card's Files page before download |
| `distilbert/distilbert-base-uncased` | Fallback fine-tuning candidate | HF card inspected; English, BookCorpus/Wikipedia pretraining | Apache-2.0 (per HF card) | Widely supported, ONNX-friendly; likely slower/heavier than DeBERTa-xsmall for similar quality |
| `FacebookAI/xlm-roberta-base` | Multilingual stretch candidate | HF card inspected; 100 languages (card text says 2.5TB CommonCrawl; tag lists 94 languages) | MIT (per HF card) | Only if the multilingual slice matters; larger and slower on CPU |
| `protectai/deberta-v3-base-prompt-injection-v2` | External comparison point, **not** our model | HF card inspected: Apache-2.0, English only, not jailbreaks/non-English (card Limitations). Vendor-reported post-training eval on 20,000 unseen prompts: accuracy 95.25%, precision 91.59%, recall 99.74%, F1 95.49% — vendor numbers, not ours | Apache-2.0 (per HF card) | Useful benchmark reference and error-analysis comparator. Using it as "Sentinel" would be wrapping someone else's classifier and is not the deliverable |

Selection rule: fine-tune DeBERTa-v3-xsmall first. Promote a larger or
multilingual model only if the benchmark (§6) shows a material per-slice gain
worth its latency/size cost on this CPU.

Local practicality (measured environment): CPU training for a small encoder on
2–4k short samples is feasible (minutes-to-tens-of-minutes per run at small
batch/sequence lengths; measure, do not assume). Export to ONNX and serve with
onnxruntime (installed) for CPU inference. The GTX 1650 (4 GB) is present but
the installed Torch is CPU-only; GPU training would need a CUDA Torch install
(large, separately approved) and 4 GB still caps model/batch size. Disk is
sufficient (44.7 GB free) for small encoder weights and datasets.

No weights were downloaded in this phase. Parameter counts, exact weight file
sizes, and per-model inference latency are **unverified estimates until
measured** and must be recorded from the model card Files page and local
benchmarks in Phase 11A.

## 6. Benchmark protocol

Reproducibility: fixed seeds (dataset shuffle, model init, training) recorded
per run; dataset version, model base version, code revision (file hashes while
there is no Git), dependency versions, and hardware recorded in a run manifest
JSON next to the metrics. Every reported number must name the dataset version
and split it came from.

Metrics (validation for selection; test reported once per model version):

- Per-class and macro precision, recall, F1; binary suspicious-class PR curve.
- False-positive rate on benign, reported separately for hard-benign slices.
- Full confusion matrix (Stage 1 and Stage 2).
- Calibration: reliability bins / expected calibration error if scores are
  surfaced as "calibrated"; otherwise report raw logits→softmax as uncalibrated.
- Latency: p50/p95 per-sample inference on this CPU (batch 1, 512-char and
  4,000-char inputs), model artifact size on disk, peak RAM if practical.
- Robustness slices: paraphrase, indirect-in-document, each obfuscation type,
  multilingual, quoted/discussion benign. Report per-slice recall/FPR, not just
  global averages.

Comparisons required: rule scanner alone; TF-IDF baseline alone; Sentinel
alone; scanner + Sentinel advisory agreement/disagreement analysis (where ML
catches what rules miss and vice versa). ProtectAI's published numbers are
context only and must not be presented as our benchmark.

Provisional acceptance targets (**proposed targets, not measured results**):

| Target | Proposed value | Why |
| --- | --- | --- |
| Suspicious recall (binary, test) | ≥ 0.90 | False negatives are missed attacks that reach the gate layer relying on policy alone |
| Benign FPR (test) | ≤ 0.05 overall; ≤ 0.10 on hard-benign | False positives that escalate benign work to CONFIRM erode trust and train users to approve reflexively |
| Macro F1 (Stage 2, when shipped) | ≥ 0.75 | Subtype labels must beat "always guess majority subtype" by a clear margin |
| CPU p95 latency | ≤ 250 ms at 4,000 chars | Advisory must not make evaluation feel broken; timeout already fails safe |
| Artifact size | ≤ 250 MB | Local-first demo must stay clone-and-run friendly |

Why both error types matter, in product terms: a false negative means injected
content gets no advisory flag (deterministic policy still decides, so this is
defence-in-depth loss, not automatic compromise); a false positive means extra
confirmations and alert fatigue, which in an approval system is itself a
security risk because habitual approving defeats the CONFIRM gate.

## 7. Proposed API contract and fail-safe integration

Future internal contract (design only, not implemented):

```text
POST /internal/sentinel/v1/analyze        (server-to-server/local only)
Request:  { text: string (<= 4000 chars), sourceType?: enum, requestId: string }
Response: {
  status: "success" | "failed" | "unavailable",
  predictedCategory: "benign" | "suspicious" | null,
  attackCategory: enum | null,
  score: number | null,            // softmax score; "calibrated" only after calibration work
  modelVersion: string,            // e.g. sentinel-deberta-xsmall@dataset-v0.1.0
  datasetVersion: string,
  latencyMs: number,
  failureReason: string | null     // sanitized category only
}
```

Rules mirroring the existing advisory layer:

- Advisory only. The deterministic engine decides ALLOW/CONFIRM/BLOCK and the
  approval flow stays exactly as implemented. A Sentinel "benign" never
  authorizes, skips confirmation, or edits a stored action; a Sentinel
  "suspicious" may at most be shown beside scanner findings.
- Timeout (suggest 2s server-side, hard abort), no unbounded retries, bounded
  queue/concurrency, input size rejection with 400/413-style semantics, and a
  request budget analogous to `MODEL_MAX_REQUESTS`.
- Fail-safe: timeout, model-missing, or malformed output → explicit
  failed/unavailable analysis state. Never evidence of safety. The deterministic
  response is returned regardless.
- Mock/local development: a deterministic mock Sentinel (mirroring scanner
  observations, labelled mock like the current provider) plus a local ONNX
  mode. The frontend never receives model credentials (there are none for a
  local model) and never calls the model directly.
- Logs: request id, model/dataset version, status, sanitized category, latency
  bucket. Never raw text, secrets, or full payloads. Redact before any sample
  is stored for error analysis; store hashes, not content, by default.
- Node integration would shell out to a small local Python service; process
  lifecycle, port, and failure ownership must be designed before any code, and
  the API must start and demo correctly with Sentinel absent.

## 8. Training and evaluation milestones (Phase 11A proposal)

Small, separately approved steps. Each ends with tests/benchmark output:

1. **11A-1 Dataset v0.1 scaffold.** Schema validator (Python, stdlib +
   installed pandas), labelling guide, seed samples expanded from existing
   scanner fixtures/scenarios, group-aware splitter, dedupe checks, dataset
   card. Gate: validator tests pass; split leakage check reports zero group
   overlap.
2. **11A-2 Baselines.** Rule-scanner scoring script and TF-IDF + logistic
   regression baseline on the frozen splits; publish validation metrics.
   No downloads.
3. **11A-3 Candidate download + fine-tune (needs explicit approval to download
   weights).** Record exact model revision and file sizes; fine-tune
   DeBERTa-v3-xsmall on CPU; ONNX export; inference smoke on fixtures.
4. **11A-4 Benchmark + error analysis.** Full §6 protocol on validation, select
   threshold/model, then one test-set evaluation; per-slice report and
   confusion matrices committed as docs artifacts.
5. **11A-5 Advisory integration (separate approval).** Mock Sentinel provider
   behind the existing interface, then optional local ONNX provider, with the
   existing validator, timeout, and failure semantics; full TS regression
   (`npm test`, `npm run typecheck`, `npm run build`) plus Python tests.

## 9. Risks, dependencies, compute, and cost

- **Data risk (largest):** synthetic-only data can teach template matching, not
  injection understanding. Mitigate with paraphrase groups, hard benign items,
  and honest per-slice reporting. A small dataset caps achievable claims.
- **Leakage risk:** variants across splits inflate metrics. Group splits and
  dedupe are mandatory, with an automated overlap report.
- **Licence risk:** base-model and any public dataset licences must be recorded
  per artifact (cards above show MIT/Apache-2.0 tags; verify the full licence
  text and dataset terms at adoption time, not from memory).
- **Compute:** CPU-only Torch today. Small-encoder fine-tuning is practical;
  anything larger is not on this machine. Optional CUDA Torch or cloud GPU is
  an external cost requiring prior approval: provider, purpose, and price are
  unverified until quoted; the local alternative is to stay small/on CPU.
- **Dependency risk:** `datasets`, experiment tracking, or serving frameworks
  are new installs requiring approval. Prefer installed
  transformers/sklearn/onnxruntime first.
- **Product risk:** presenting ML scores as safety proof. Mitigated by the
  advisory contract, failure wording, and keeping deterministic findings
  visually and architecturally separate.
- **Cost:** local path is electricity/time only. No paid API, cloud GPU, or
  Muse credits are needed for 11A-1 to 11A-4. Muse may later be proposed for
  synthetic-data generation or comparative inference; that would need the
  standard credential/budget approval flow and must never become the model.

## 10. Files changed and checks executed

Files changed in Phase 11: only this report,
`docs/phase11-sentinel-research.md`. No source, test, config, `.env`, or UI
files were modified. The eight Stitch screen designs / existing frontend were
not touched (note: `stitch-screens/` is currently an empty directory).

Checks actually executed:

- `npm test` — passed: engine 28, API 44, total 72, 0 failed.
- Python/hardware inventory commands — Python 3.12.10, torch 2.13.0+cpu
  (CUDA unavailable), transformers 4.57.6, sklearn 1.9.0, onnxruntime 1.27.0;
  i7-11800H 8c/16t, 15.7 GB RAM, GTX 1650 4 GB present, 44.7 GB disk free.
- `git rev-parse --is-inside-work-tree` — not a Git repository.
- Presence-only env checks — `MODEL_API_KEY` absent in the audit process,
  `MODEL_LIVE_ENABLED` unset.
- Hugging Face model-card pages inspected for the four candidates listed in §5
  (licences and vendor metrics quoted from those cards; vendor metrics are not
  our results).

Not executed and not claimed: type-check/build (unchanged code, documentation
only), any training, any download, any live or paid API call.

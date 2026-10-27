# Phase 11A-1 + 11A-2 — Dataset Scaffold & Baseline Benchmark

Date: 2026-10-26. Offline only. No pretrained weights downloaded, no fine-tuning,
no external API calls, no credits consumed, mock provider unchanged, and no
production runtime code was modified.

## Files added

| File | Purpose |
| --- | --- |
| `ml/sentinel/schema.py` | Strict stdlib validator for the dataset schema |
| `ml/sentinel/validate.py` | Validator CLI |
| `ml/sentinel/split.py` | Deterministic group-aware 70/15/15 splitter + leakage checks |
| `ml/sentinel/metrics.py` | Shared binary metric helpers |
| `ml/datasets/sentinel/v0.1.0/samples.jsonl` | 64 curated synthetic samples (source of truth) |
| `ml/datasets/sentinel/v0.1.0/DATASET_CARD.md` | Dataset card and limitations |
| `ml/datasets/sentinel/v0.1.0/LABELLING_GUIDE.md` | Labelling guide (label by intent, not keywords) |
| `ml/datasets/sentinel/v0.1.0/splits/` | Generated `train/validation/test.jsonl` + `split_manifest.json` |
| `ml/baselines/scan_dataset.mjs` | Evaluates the **existing built engine scanner** on eligible splits; refuses `test` |
| `ml/baselines/run_baselines.py` | TF-IDF + Logistic Regression baseline (train-only fit, validation threshold) |
| `ml/tests/test_dataset.py` | 5 pytest checks: validity, validator rejection, leakage, determinism, frozen-manifest match |
| `ml/results/scanner-train.json`, `ml/results/scanner-validation.json`, `ml/results/tfidf-logreg-validation.json` | Measured outputs of the runs below |

No existing files were changed (`npm run build -w @agentshield/engine` only
regenerated the already-ignored/built `dist/` used by the scanner baseline).

## Dataset v0.1.0

- 64 samples: benign 32, suspicious 32; 63 groups (one group carries a base
  sample plus its paraphrase variant, sen-0033/sen-0034).
- Attack categories present: direct, indirect, obfuscated, impersonation,
  exfiltration, tool-redirect, other. Hard benign includes quoted attacks,
  security education, incident reports, and defensive advice (13 samples with
  `is_quoted_or_discussed=true`, plus further defensive-advice benign items).
- Languages: English, plus one benign + one suspicious each in Spanish,
  German, Hindi (smoke slice only).
- Splits (deterministic, seed 20261026, group-stratified by label):
  **train 44 (22/22), validation 10 (5/5), test 10**. Test is frozen.

Leakage verification (actually run):

- `python ml/sentinel/validate.py` → `samples=64 labels={'benign': 32, 'suspicious': 32} errors=0`
- Split manifest: group crossing **0**, exact normalized-duplicate cross-split
  **0**, near-duplicate (token Jaccard ≥ 0.9, different group, different split)
  **none found**.
- `python -m pytest ml/tests -q` → **5 passed**.

Limitations: near-duplicate detection is a token-overlap heuristic, not
semantic duplicate detection; paraphrases with low token overlap can still be
conceptually close across splits (grouping by author knowledge mitigates this).
One author wrote all samples, so style leakage is possible.

## Measured baseline results

All numbers below were produced by the commands in the next section on
2026-10-26. The frozen test split was **not** read by either baseline; the
scanner script exits with an error if asked for `test`.

### A. Deterministic rule scanner (existing engine, unmodified)

Train (n=44): accuracy 0.75. Confusion — benign 22→benign, 0→suspicious;
suspicious 11→benign, 11→suspicious. Suspicious precision 1.00, recall 0.50,
F1 0.667. Benign FPR 0.00.

Validation (n=10): accuracy 0.70. Confusion — benign 4→benign, 1→suspicious;
suspicious 2→benign, 3→suspicious. Suspicious precision 0.75, recall 0.60,
F1 0.667. Benign FPR 0.20.

Per-category recall (validation, tiny counts): impersonation 1.0, tool_redirect
1.0, indirect 1.0, direct 0.0, other 0.0. On train, obfuscated recall was 0.0 and
direct only 0.333 — the documented Phase 2 limitation (sentence-start imperative
anchoring) shows up measurably: encoded, spaced, leetspeak, paraphrased, and
non-English attacks are missed, and German direct injection (sen-0059) was a
validation miss. The one validation false positive was sen-0004, the quoted
training example — exactly the hard-benign failure mode the dataset was built
to expose.

### B. TF-IDF + Logistic Regression (train-only fit)

Config: word 1–2 grams, sublinear TF-IDF; balanced logistic regression,
`max_iter=1000`, seed 20261026. Fit time 0.053s. Threshold selected on
validation only: 0.50.

Train (n=44) at threshold: accuracy 0.977, suspicious F1 0.977 (near-memorization
of a tiny synthetic training set — not a quality claim).

Validation (n=10): accuracy 0.70. Confusion — benign 3→benign, 2→suspicious;
suspicious 1→benign, 4→suspicious. Per class — benign P/R/F1 0.75/0.60/0.667;
suspicious 0.667/0.80/0.727. Benign FPR 0.40. Hard-benign slice (n=2): FPR 0.5
(sen-0031, an incident report, flagged). Attack-category recall on validation:
impersonation/indirect/other/tool_redirect 1.0, direct 0.0 (the German sample).

Majority baseline (validation): train labels are tied 22/22; the tie-broken
majority pick scored accuracy 0.50 with benign FPR 1.0, i.e. no skill — included
to show why accuracy alone is meaningless here.

### Interpretation (honest)

Validation has 10 samples, so one sample swings metrics by 10 points. Both
baselines land near 0.70 accuracy / 0.67–0.73 suspicious F1 on validation for
different reasons: the scanner is precise but misses obfuscated, indirect, and
non-English phrasing; TF-IDF catches more attacks but flags hard-benign text at
an unacceptable rate (FPR 0.40 overall, 0.5 on hard benign). Neither meets the
Phase 11 *proposed* targets (recall ≥ 0.90, benign FPR ≤ 0.05); those remain
targets, not results. The benchmark harness works; the dataset is too small
and too single-author to rank models credibly. That is the finding.

## Reproduce

```powershell
python ml/sentinel/validate.py
python ml/sentinel/split.py
python -m pytest ml/tests -q
npm run build -w @agentshield/engine   # scanner baseline uses the built engine
node ml/baselines/scan_dataset.mjs train
node ml/baselines/scan_dataset.mjs validation
python ml/baselines/run_baselines.py
npm test          # AgentShield regression: 72 passed
npm run typecheck # passed
```

Environment: Python 3.12.10, scikit-learn 1.9.0, Windows 11; Node v22.22.3.
No new dependencies were installed (`pytest`, `scikit-learn` already present).

## Regression checks actually run

- `npm test` → 72 passed (engine 28, API 44), 0 failed.
- `npm run typecheck` → passed for all three workspaces.
- `python -m pytest ml/tests -q` → 5 passed.

## Recommendations for Phase 11A-3 (needs separate approval)

1. Do not fine-tune yet on 64 samples. First grow the dataset (target at least
   several hundred reviewed samples) with a second annotator pass, more
   indirect/obfuscated/multilingual groups, and hard-benign incident/education
   material, keeping group hygiene. Re-run both baselines after growth.
2. Add a semantic near-duplicate check (embedding-free option: character
   n-gram similarity) alongside token Jaccard.
3. Only then request approval to download `microsoft/deberta-v3-xsmall`
   weights (record revision + file sizes first), fine-tune on CPU, export
   ONNX, and evaluate with the same frozen splits — selection on validation,
   one final test read.
4. Keep Sentinel offline/advisory. No API integration in 11A-3 without the
   separate integration approval from the Phase 11 plan.

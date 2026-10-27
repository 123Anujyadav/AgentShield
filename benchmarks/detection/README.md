# AgentShield Detection Benchmark (Phase C-1)

Deterministic synthetic benchmark for the deterministic outbound secret
detector and evaluator. It is isolated from ML training and from the frozen
Sentinel dataset splits: the corpus lives in `benchmarks/detection/v1/` and
contains only hand-authored synthetic fixtures with clearly fake markers.
No real secrets, production credentials, blind-review data, or
`ml/datasets/sentinel/` payloads are used.

## Run

From the repository root (the API and this benchmark consume the built
engine, so build it first):

```bash
npm run build -w @agentshield/engine
node benchmarks/detection/run-benchmark.mjs <output-name>
```

The report is written to `benchmarks/detection/results/<output-name>.json`
and printed to stdout. Reports contain no timestamps, so rerunning with the
same engine build and corpus produces a byte-identical file.

The runner validates the corpus before scoring and exits with code 1 on any
problem: a missing or non-boolean `expectedBlock`, an unknown `field`, a
duplicate `id`, an unknown property or placeholder, or payload options on a
summary fixture. A BLOCK caused by any rule other than
`data-leak.outbound-secret` is also an error, so every scored detection comes
from the detector under test. Runner self-tests:

```bash
node --test benchmarks/detection/run-benchmark.test.mjs
```

## Corpus (v1, 53 fixtures)

Expected results (`expectedBlock`) are defined by the documented detection
policy before any detector run and are never derived from detector output.

| Family | Count | Meaning |
| --- | --- | --- |
| labelled-assignment | 8 | Supported `label=value` / `label: value` credential forms |
| quoted-credential | 6 | Single/double/JSON quoted and unclosed quoted values |
| token-formats | 6 | Bearer, realistic `sk-` tokens, and email addresses |
| decoy-and-nested | 4 | Benign first labels hiding a later real credential |
| boundary-lengths | 4 | 255/256 generic-value boundary, padded secret, overlong field |
| hard-benign | 12 | Prose and counts/booleans that must not BLOCK |
| known-unsupported | 3 | Documented gaps expected not to BLOCK under current policy |
| c2-new-syntax | 10 | Phase C-2 additions: `passphrase=` and the `=>` separator (7 positives), plus 3 JavaScript arrow-function negatives |

The three arrow-function negatives (`new-08` to `new-10`) were added during
the Phase C audit, after `=>` support was found to BLOCK code such as
`token => token.trim()`. Their expected result follows the documented policy
(an arrow function is not a credential assignment), but unlike the other
fixtures they were written after the detector behaviour was known.

## Metrics

Per family and overall: TP, FP, TN, FN, precision `TP/(TP+FP)`, and recall
`TP/(TP+FN)`. A metric is `null` (undefined) when its denominator is zero;
no value is invented. `known-unsupported` fixtures count as true negatives
when they do not block, which is stated in every report so the totals are
not mistaken for real-world accuracy.

## Baseline comparison

- `results/baseline-pre-c2.json`: the committed detector before Phase C-2
  (commit `0e79a51`, rebuilt from that commit's engine source). Overall TP 27,
  FP 0, TN 19, FN 7; precision 1.0, recall 0.7941. All 7 false negatives are
  the then-unsupported C-2 syntax positives.
- `results/post-c2.json`: after `passphrase=` and `=>` support, including the
  arrow-function guard. Overall TP 34, FP 0, TN 19, FN 0; precision 1.0,
  recall 1.0.
- For reference (not stored): `=>` support without the arrow-function guard
  scored TP 34, FP 3, TN 16, FN 0 (precision 0.9189); the 3 false positives
  were `new-08` to `new-10`.

`known-unsupported` fixtures describe real gaps (for example `gap-01` and
`gap-03` contain credential-like text) yet count as true negatives, because
the metrics measure agreement with the documented policy rather than
detection of every secret. `gap-02` is a prose description of a split
credential and contains no credential text itself.

These numbers describe this synthetic corpus only. They are not a
real-world accuracy claim and say nothing about unlabelled, encoded, or
split secrets, which remain undetected by design of the pattern set.

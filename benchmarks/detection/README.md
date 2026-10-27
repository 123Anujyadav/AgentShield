# AgentShield Detection Benchmark (Phase C-1)

Deterministic synthetic benchmark for the deterministic outbound secret
detector and evaluator. It is isolated from ML training and from the frozen
Sentinel dataset splits: the corpora live in `benchmarks/detection/<version>/`
and contain only hand-authored synthetic fixtures with clearly fake markers.
No real secrets, production credentials, blind-review data, or
`ml/datasets/sentinel/` payloads are used.

## Run

From the repository root (the API and this benchmark consume the built
engine, so build it first):

```bash
npm run build -w @agentshield/engine
node benchmarks/detection/run-benchmark.mjs <output-name> [corpus-version]
```

`corpus-version` selects `benchmarks/detection/<corpus-version>/fixtures.json`
and defaults to `v1`, so the original Phase C commands still reproduce their
reports. The report is written to
`benchmarks/detection/results/<output-name>.json` and printed to stdout.
Reports contain no timestamps, so rerunning with the same engine build and
corpus produces a byte-identical file.

The runner validates the corpus before scoring and exits with code 1 on any
problem: a missing or non-boolean `expectedBlock`, an unknown `field`, a
duplicate `id`, an unknown property or placeholder, or payload options on a
summary fixture. A BLOCK caused by any rule other than
`data-leak.outbound-secret` is also an error, so every scored detection comes
from the detector under test. Runner self-tests (they also check that each
corpus version extends the previous one without changing earlier fixtures):

```bash
node --test benchmarks/detection/run-benchmark.test.mjs
```

## Corpus versions

Each version is a separate file and only appends fixtures to the previous one.

| Version | Fixtures | Added | Used by |
| --- | --- | --- | --- |
| `v1` | 53 | Phase C corpus | `baseline-pre-c2.json`, `post-c2.json` |
| `v1.1` | 55 | 2 `arrow-disguise` positives (`d1-01`, `d1-02`) | `post-d1.json` |
| `v1.2` | 81 | 14 `arrow-disguise` positives (`d1r-01`..`d1r-14`) and 12 `arrow-code` negatives (`d1r-20`..`d1r-31`) | `post-d1-remediation.json` |
| `v1.3` | 98 | 9 `arrow-disguise` positives for quote and whitespace boundaries and the mixed-case literal rule (`d1s-01`..`d1s-09`) and 8 `arrow-code` negatives (`d1s-20`..`d1s-27`) | `post-d1-boundary-remediation.json` |
| `v1.4` | 117 | 12 `arrow-disguise` positives for spaced member chains (`token . x`, `token ?. x`, `send(x) . then(...)`, `password .x`, a dot on its own line), each in summary and payload (`d1t-01`..`d1t-12`), and 7 `arrow-code` negatives (`d1t-20`..`d1t-26`) | `post-d1-spaced-chain-remediation.json` |

Families in v1.4 (`arrow-disguise` and `arrow-code` grow from v1.3's 25 and 20):

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
| arrow-disguise | 37 | Credentials disguised as an arrow-function body: extra arguments, padded parentheses, later member segments, bracket keys, label members as arguments, curried and chained calls (also after a space or newline), digit-bearing or capitalised member names, a passphrase argument, a quote glued to the expression, a mixed-case password literal, and spaced member chains |
| arrow-code | 27 | Ordinary arrow-function code that must stay ALLOW: long or digit-bearing method names, year- or version-tagged identifiers, helper and library calls, format strings, codec and algorithm names, chains across spaces and lines (including spaced dots), and quoted code in prose |

Expected results (`expectedBlock`) follow the documented detection policy and
are never derived from detector output. Provenance note: the arrow-function
negatives `new-08`..`new-10` (Phase C audit) and all `d1-*`/`d1r-*`/`d1s-*`/`d1t-*`
fixtures (Phase D-1 and its audits) were written after the detector behaviour
they test was known, to pin down audited bypasses and false positives.

## Metrics

Per family and overall: TP, FP, TN, FN, precision `TP/(TP+FP)`, and recall
`TP/(TP+FN)`. A metric is `null` (undefined) when its denominator is zero;
no value is invented. `known-unsupported` fixtures count as true negatives
when they do not block, which is stated in every report so the totals are
not mistaken for real-world accuracy.

## Reports

Historical reports are kept unchanged; each one reproduces byte-for-byte from
its own corpus version and the engine build that produced it.

- `results/baseline-pre-c2.json`: corpus v1, detector before Phase C-2
  (commit `0e79a51`). TP 27, FP 0, TN 19, FN 7; precision 1.0, recall 0.7941.
  All 7 false negatives are the then-unsupported C-2 syntax positives.
- `results/post-c2.json`: corpus v1, Phase C-2 detector (commit `3e80c77`).
  TP 34, FP 0, TN 19, FN 0.
- `results/post-d1.json`: corpus v1.1, the first Phase D-1 arrow-body
  hardening, before its audit remediation. TP 36, FP 0, TN 19, FN 0. That
  detector still allowed every `d1r-*` bypass: run on corpus v1.2 it scores
  TP 36, FP 5, TN 26, FN 14 (precision 0.878, recall 0.72; not stored).
- `results/post-d1-remediation.json`: corpus v1.2, Phase D-1 after the first
  audit remediation. TP 50, FP 0, TN 31, FN 0. That detector still allowed the
  quote and whitespace boundary bypasses: run on corpus v1.3 it scores TP 52,
  FP 1, TN 38, FN 7 (not stored).
- `results/post-d1-boundary-remediation.json`: corpus v1.3, Phase D-1 after
  the boundary and redaction fix. TP 59, FP 0, TN 39, FN 0. The same detector
  on corpus v1.2 reproduces `post-d1-remediation.json` byte-for-byte. It still
  allowed spaced member chains: run on corpus v1.4 it scores TP 60, FP 0,
  TN 46, FN 11 (not stored).
- `results/post-d1-spaced-chain-remediation.json`: corpus v1.4, Phase D-1
  after the spaced-chain fix. TP 71, FP 0, TN 46, FN 0. The same detector on
  corpus v1.3 reproduces `post-d1-boundary-remediation.json` byte-for-byte.
- For reference (not stored): `=>` support without the Phase C arrow-function
  guard scored TP 34, FP 3, TN 16, FN 0 on corpus v1.

`known-unsupported` fixtures describe real gaps (for example `gap-01` and
`gap-03` contain credential-like text) yet count as true negatives, because
the metrics measure agreement with the documented policy rather than
detection of every secret. `gap-02` is a prose description of a split
credential and contains no credential text itself.

These numbers describe these synthetic corpora only. They are not a
real-world precision or recall claim and say nothing about unlabelled,
encoded, or split secrets, which remain undetected by design of the pattern
set.

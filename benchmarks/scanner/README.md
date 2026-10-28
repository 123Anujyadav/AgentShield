# AgentShield Scanner Benchmark (Phase K)

Deterministic synthetic benchmark for the rule-based injection scanner
(`packages/engine/src/scanner/`). It is independent of the credential benchmark
in `benchmarks/detection/`, isolated from ML training, and never reads the
frozen Sentinel dataset splits. Fixtures are hand-authored synthetic text with
no real credentials or personal data.

## Run

From the repository root (the benchmark consumes the built engine):

```bash
npm run build -w @agentshield/engine
node benchmarks/scanner/run-scanner-benchmark.mjs <output-name> [corpus-version]
node --test benchmarks/scanner/run-scanner-benchmark.test.mjs
```

`corpus-version` selects `benchmarks/scanner/<corpus-version>/fixtures.json` and
defaults to `v1`. The report is written to `benchmarks/scanner/results/<output-name>.json`
and has no timestamps, so a rerun with the same engine build and corpus is
byte-identical. The corpus is validated first (unknown properties, duplicate or
malformed ids, unknown rules or categories, missing reasons, and an
`expectedDecision` that disagrees with `expectedRules` all stop the run).

## What is measured

Each fixture is untrusted content evaluated with the `benign-summary` scenario,
whose action the intent allows. Every scanner rule is high or critical
severity, so the decision is `CONFIRM` when any rule fires and `ALLOW`
otherwise. `expectedRules` and `expectedDecision` follow the documented Phase K
policy, never detector output, and every fixture states its `reason`.

- Overall: positive = `expectedDecision` is `CONFIRM`; predicted positive = the
  actual decision is `CONFIRM`.
- Per affected rule (`injection.secret-exfiltration`,
  `injection.unauthorized-tool-action`): positive = the rule is in
  `expectedRules`; predicted positive = the rule fired.
- precision = TP/(TP+FP), recall = TP/(TP+FN), false-positive rate = FP/(FP+TN),
  false-negative rate = FN/(FN+TP). A rate is `null` when its denominator is zero.

## Corpus versions

Each version is a separate file; later versions only append fixtures and never
change existing ids, text, or expected outcomes.

| Version | Fixtures | Contents |
| --- | --- | --- |
| `v1` | 45 | 3 controls, 14 suppression-bypass positives (8 exfiltration, 6 tool-redirect), 13 safety-advice negatives, 11 boundary cases, 4 malformed cases |
| `v2` | 87 | v1 unchanged, plus 11 `hard-benign` safety advice (8 with "ever" between the negation and the verb), 10 `education-descriptive` cases that discuss attacks without requesting them, 10 `attack-framed` requests wrapped in quotes, training, or concealment wording, 9 boundary cases (`x-01`..`x-09`), and 2 `pattern-gap` attacks the current patterns cannot see (`g-01`, `g-02`) |

Educational fixtures are labelled by whether they *request* an action, not by
their framing: a description of an attack expects `ALLOW` even when it quotes
the attack, and a real request expects `CONFIRM` even when it is quoted or
called an example. The scanner has no quote or education exemption, so
descriptions that quote an attack's imperative are reported as false positives
rather than hidden.

## Reports

Reports are kept unchanged once written; each reproduces byte-for-byte from its
corpus version and the engine build that produced it.

- `results/baseline-pre-k.json`: corpus v1, scanner before Phase K. Overall
  TP 4, FP 1, TN 18, FN 22. All 14 suppression-bypass positives are false
  negatives; the false positive is `b-06` (a governing negation with irregular
  spacing that the old sentence-wide guard did not recognise).
- `results/post-k.json`: corpus v1, Phase K scanner. Overall TP 26, FP 0,
  TN 19, FN 0; both affected rules have no false positives or negatives. The
  remediated scanner below reproduces this report byte-for-byte on v1.
- `results/pre-k-remediation.json`: corpus v2, Phase K scanner before the
  negation remediation. Overall TP 42, FP 17, TN 26, FN 2. False positives:
  8 hard-benign "ever" negations, 3 boundary cases, and 6 educational
  descriptions; false negatives: the 2 pattern-gap attacks.
- `results/post-k-remediation.json`: corpus v2, after the remediation (an
  "ever" intensifier, optionally after a comma, may sit between the negation and
  the verb). Overall TP 42, FP 6, TN 37, FN 2. All hard-benign and boundary cases
  and all 10 framed attacks are correct; the 6 educational descriptions that
  quote or restate an attack's imperative (`e-01`, `e-03`, `e-04`, `e-05`,
  `e-07`, `e-09`) remain false positives, and `g-01`/`g-02` remain false
  negatives.

These numbers describe these synthetic corpora only. The corpora were written
after the behaviour they test was known; the results are not a real-world
precision or recall claim. Known gaps: obfuscated, encoded, non-English,
paraphrased, and mid-sentence injections; negations separated from the verb by
any word other than "ever"; descriptions that quote an attack's imperative
(flagged, by design no exemption); an override wrapped in quote marks after
other text; "transfer" as an exfiltration verb; and payment amounts written as
`$500`.

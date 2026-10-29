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
`expectedDecision` that disagrees with `expectedRules` all stop the run). The
self-tests also use the built engine, to check that replacing every space in
each plain v1-v3 fixture with any approved invisible character leaves its
findings unchanged (Design B3), so build the engine before running them.

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
| `v3` | 115 | v2 unchanged, plus 15 `obfuscated-attack` cases across all four rules that hide a request with invisible format characters (every approved character group appears on its own at least once; `o-01`..`o-15`) and 13 `obfuscated-benign` texts that legitimately contain them: a leading BOM, soft hyphens, directional marks with Hebrew and Arabic, an emoji joiner sequence, bidi isolates, an invisible operator, and negated safety advice (`w-01`..`w-13`) |
| `v4` | 165 | v3 unchanged, plus 28 `separator-attack` requests whose spaces are replaced by approved invisible format characters (all four rules; each of the 22 code points is the only separator in at least one; leading and trailing padding, a new line, separators mixed with ordinary spaces, a negation that governs another verb, a bidi isolate; `s-01`..`s-28`), 18 `separator-benign` texts (negated safety advice with separators or with an invisible character inside never, not, or ever, emoji joiners, Persian ZWNJ, Thai word breaks, Hebrew RLM, a bidi-isolated name, a word joiner in a product name, an invisible operator, descriptive text, full syllable hyphenation, and three documented false positives, `sb-16`..`sb-18`; `sb-01`..`sb-18`), and 4 `separator-gap` attacks that mix an invisible character inside a word with invisible separators (`sg-01`..`sg-04`) |

Corpus files store the invisible characters as `\uXXXX` escapes, so they are
reviewable and contain no raw bidi controls; the self-tests check that every
version is in this canonical form.

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

- `results/pre-l.json`: corpus v3, Phase K scanner before invisible-character
  normalization. Overall TP 42, FP 6, TN 50, FN 17: all 15 obfuscated attacks
  are false negatives, all 13 obfuscated-benign texts are correct, and the v2
  failures are unchanged.
- `results/post-l.json`: corpus v3, Phase L scanner. Overall TP 57, FP 6,
  TN 50, FN 2: all 15 obfuscated attacks are CONFIRM and all 13 obfuscated-benign
  texts are ALLOW; the remaining failures are the six v2 educational false
  positives and the two v2 pattern gaps. The same scanner reproduces
  `post-k.json` (v1) and `post-k-remediation.json` (v2) byte-for-byte.
- `results/pre-space-substitution.json`: corpus v4, the committed scanner
  before Design B3 (Phase L/M). Overall TP 57, FP 6, TN 68, FN 34: all 28
  separator attacks and all 4 separator-gap attacks are false negatives, all
  18 separator-benign texts are ALLOW, and the v3 results are unchanged.
- `results/post-space-substitution.json`: corpus v4, Design B3. Overall TP 85,
  FP 9, TN 65, FN 6 (precision 0.9043, recall 0.9341): all 28 separator attacks
  are CONFIRM. The new failures are the three documented false positives
  `sb-16` and `sb-17` (a single soft hyphen at a compound boundary exposes
  "delete" or "send") and `sb-18` (an invisible character inside "do not" plus
  invisible separators hides the negation), and the four `separator-gap`
  false negatives; the six v2 educational false positives and the two v2
  pattern gaps are unchanged. `separator-gap` fixtures expect CONFIRM, so a
  miss is counted as a false negative, never as a true negative. The same
  scanner reproduces `post-k.json`, `post-k-remediation.json`, and
  `post-l.json` byte-for-byte.

Reports score decisions and rules only, never evidence, and fixtures have no
evidence field. The later fixes to separated-text evidence (a secret split by
invisible characters is also looked for in the joined text around the evidence
window, reading each nearby run both as a separator and as a split, and is
redacted; a value cut short at an invisible run continues to the end of its
word; redaction is narrowed to the smallest span the detectors recognize, and
the matched rule's own words show in any case, so a number in a separated
request, even a mixed-case one, no longer redacts the request) therefore change
no report: `post-space-substitution.json` still reproduces byte-for-byte, and
no v4 fixture was added. They are tested in the engine
(`packages/engine/src/scanner/space-substitution.test.ts`) with fake tokens
split into 3- to 36-character chunks by every approved character, glued to
neighbouring words, crossing the evidence window, cut by the raw bound, and
after a Bearer label 0 to 1,400 characters before the window; with benign
numbers in normal-case, mixed-case, and all-capitals requests, an email
address, and a `token:` label as over-redaction controls; and with four
findings far apart in dense input as a hang check. The root README states the
exact conservative cases, which limitations B3 introduces or newly exposes and
which are pre-existing in the Phase L joined text, and the measured cost (about
0.3 ms for ordinary 8,000-character prose; 14 to 56 ms median, 67 ms slowest
run, for dense adversarial input with four separated findings, on the
development machine).

These numbers describe these synthetic corpora only. The corpora were written
after the behaviour they test was known; the results are not a real-world
precision or recall claim. Known gaps: an invisible character inside a word
combined with invisible separators (the v4 `separator-gap` category, which
Design B3 does not cover); in separated-text evidence (introduced with B3),
redaction of a value after a label split by an invisible character, or of a
prefix-only secret glued to the word before it, more than 1,024 joined
characters before the window, and plain-word pieces of a random secret; in
evidence generally (pre-existing in the Phase L joined text, and newly reachable
through B3), a letters-only prefix-only value glued to the word before it by an
invisible character, letters-only body lines under a private-key header whose
words are separated by invisible characters, and a secret split by ordinary
spaces; invisible characters outside the approved set and look-alike letters (for example a Cyrillic "і"); encoded,
non-English, paraphrased, and mid-sentence injections; negations separated from the verb by
any word other than "ever"; descriptions that quote an attack's imperative
(flagged, by design no exemption); an override wrapped in quote marks after
other text; "transfer" as an exfiltration verb; and payment amounts written as
`$500`.

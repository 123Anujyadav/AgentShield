# Sentinel Dataset Changelog

## v0.2.0 (2026-10-26)

- Preserved all 64 v0.1.0 samples, IDs, labels, and provenance verbatim. No label
  was silently rewritten. Label-correction proposals: none recorded yet; any
  future correction must be listed here with rationale before it lands.
- Added 440 synthetic samples (sen-0065… onward in file order after dedupe;
  actual IDs are sequential in `samples.jsonl`) via
  `ml/sentinel/generate_expansion.py` (deterministic, seed 20261026):
  ordinary benign tasks, quoted/education/incident/advice hard benign,
  direct/indirect/impersonation/exfiltration/tool-redirect/other injections,
  real base64/leetspeak/spacing/unicode transforms, and hand-written
  Spanish/German/Hindi samples.
- New optional fields: `generation_method`, `independent_review`, `rationale`.
- Review state: every new sample is `review_status=unreviewed`,
  `independent_review=false`. `REVIEW_QUEUE.csv` awaits a real second
  annotator; no independent review has occurred.
- Splits regenerated with the same group-aware 70/15/15 procedure. This is a
  new dataset version, so its test split is the new frozen held-out set;
  v0.1 test results are not comparable as the same test set.
- Generation method honesty: combinatorial template generation trades authoring
  time for surface-pattern repetition. Near-duplicate checks pass at the
  documented thresholds, but template families are a known diversity limit.

## v0.1.0 (2026-10-26)

- Initial 64 hand-authored synthetic samples (32 benign / 32 suspicious).

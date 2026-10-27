# Sentinel Dataset v0.3.0 — Dataset Card

Version: `sentinel-v0.3.0` (supersedes v0.1.0; all 64 v0.1 samples and IDs preserved verbatim) · Format: JSONL (`samples.jsonl`) · Seed: 20261026

A small, fully synthetic, hand-reviewed seed dataset for offline prompt-injection
benchmarking inside AgentShield. It exists to establish a reproducible baseline
harness, not to support broad claims about detection quality.

- 504 samples: 237 benign, 267 suspicious. The first 64 are the preserved v0.1.0 samples; 440 are new in v0.3.0 (see `CHANGELOG.md`). New samples are template/combinatorial synthetic generations, marked `unreviewed` with `independent_review=false`; template diversity is limited and many share surface patterns — treat quality claims accordingly.
- All samples are synthetic and written for this project
  (`provenance: synthetic-agentshield`). No real credentials, personal data, or
  external targets. The only secret-shaped value is the clearly fake
  `FAKE_TEST_SECRET_123`.
- Attack categories follow `docs/phase11-sentinel-research.md`:
  `direct_injection`, `indirect_injection`, `obfuscated_injection`,
  `impersonation`, `exfiltration_request`, `tool_redirect`, `other_suspicious`.
- Hard benign is deliberately represented: quoted attacks, security education,
  incident reports, defensive advice, harmless "ignore" uses, and one
  adjudicated scoped user deletion (sen-0015).
- Languages: English plus one benign and one suspicious sample each in Spanish,
  German, and Hindi. This is a smoke slice, not multilingual coverage.
- Splits are group-aware 70/15/15 (see `splits/split_manifest.json`). Related
  variants share a `group_id` and therefore a split. The test split is frozen
  for this version; baselines must not use it for selection.

Limitations: 64 synthetic samples written by one author cannot estimate
real-world precision/recall. Expect optimistic, unstable metrics. Treat every
number from this dataset as a harness check, not a security guarantee.

Regeneration:

```powershell
python ml/sentinel/validate.py
python ml/sentinel/split.py
```

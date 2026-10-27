# Sentinel Dataset Changelog

## v0.3.0 (2026-10-26)

- Preserved all 504 v0.2.0 samples verbatim; no labels changed.
- Added 50 hand-authored curated samples prioritising other_suspicious and impersonation, indirect attacks in useful documents/mail/tool output, hard-benign analysis/incident/advice, and flagged multilingual items.
- All new samples are unreviewed, single-author. Multilingual items are author-written and explicitly flagged for native-speaker review.
- Added REVIEW_PACKAGE with blind stratified review files. No independent review has occurred.
- Splits regenerated (group-aware 70/15/15, seed 20261026); this version's test split is the new frozen set.

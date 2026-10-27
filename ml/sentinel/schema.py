"""Strict validator for Sentinel dataset v0.1. Stdlib only."""
from __future__ import annotations

import json
from pathlib import Path

LABELS = {"benign", "suspicious"}
ATTACK_CATEGORIES = {
    "direct_injection",
    "indirect_injection",
    "obfuscated_injection",
    "impersonation",
    "exfiltration_request",
    "tool_redirect",
    "other_suspicious",
}
SOURCE_TYPES = {"document", "webpage", "tool_output", "email", "chat", "synthetic_direct"}
OBFUSCATION_TYPES = {"none", "paraphrase", "base64", "leetspeak", "spacing", "unicode", "translation", "multi_turn"}
RISKS = {"low", "medium", "high", "critical"}
SPLITS = {"train", "validation", "test"}
REQUIRED = {
    "sample_id": str,
    "text": str,
    "label": str,
    "attack_category": (str, type(None)),
    "source_type": str,
    "language": str,
    "obfuscation_type": str,
    "expected_risk": str,
    "group_id": str,
    "annotation_confidence": (int, float),
    "is_quoted_or_discussed": bool,
    "review_status": str,
}


def validate_sample(sample: dict, line_no: int = 0) -> list[str]:
    errors: list[str] = []
    where = f"line {line_no} ({sample.get('sample_id', '?')})"
    for field, types in REQUIRED.items():
        if field not in sample:
            errors.append(f"{where}: missing {field}")
        elif not isinstance(sample[field], types):
            errors.append(f"{where}: {field} has wrong type")
    if errors:
        return errors
    if not sample["text"].strip():
        errors.append(f"{where}: empty text")
    if len(sample["text"]) > 4000:
        errors.append(f"{where}: text exceeds 4000 chars")
    if sample["label"] not in LABELS:
        errors.append(f"{where}: invalid label {sample['label']!r}")
    if sample["label"] == "suspicious" and sample["attack_category"] not in ATTACK_CATEGORIES:
        errors.append(f"{where}: suspicious sample needs a valid attack_category")
    if sample["label"] == "benign" and sample["attack_category"] is not None:
        errors.append(f"{where}: benign sample must have attack_category=null")
    if sample["source_type"] not in SOURCE_TYPES:
        errors.append(f"{where}: invalid source_type")
    if sample["obfuscation_type"] not in OBFUSCATION_TYPES:
        errors.append(f"{where}: invalid obfuscation_type")
    if sample["expected_risk"] not in RISKS:
        errors.append(f"{where}: invalid expected_risk")
    if not 0.0 <= float(sample["annotation_confidence"]) <= 1.0:
        errors.append(f"{where}: annotation_confidence out of range")
    if sample.get("split") is not None and sample["split"] not in SPLITS:
        errors.append(f"{where}: invalid split")
    # Optional v0.2 provenance fields: validated when present, never required for v0.1.
    if "generation_method" in sample and sample["generation_method"] not in {
        "synthetic-authored", "synthetic-generated-template", "synthetic-transformed",
    }:
        errors.append(f"{where}: invalid generation_method")
    if "rationale" in sample and (not isinstance(sample["rationale"], str) or len(sample["rationale"]) > 300):
        errors.append(f"{where}: rationale missing type or too long")
    if "independent_review" in sample and not isinstance(sample["independent_review"], bool):
        errors.append(f"{where}: independent_review must be boolean")
    # Seeded secrets must be clearly fake; reject credential-shaped values.
    lowered = sample["text"].lower()
    if "sk-" in lowered and "fake" not in lowered:
        errors.append(f"{where}: possible non-fake secret-shaped value")
    return errors


def load_dataset(path: Path) -> tuple[list[dict], list[str]]:
    samples: list[dict] = []
    errors: list[str] = []
    seen_ids: set[str] = set()
    for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            sample = json.loads(line)
        except json.JSONDecodeError as exc:
            errors.append(f"line {line_no}: invalid JSON ({exc.msg})")
            continue
        if sample.get("sample_id") in seen_ids:
            errors.append(f"line {line_no}: duplicate sample_id {sample.get('sample_id')}")
        seen_ids.add(sample.get("sample_id"))
        errors.extend(validate_sample(sample, line_no))
        samples.append(sample)
    return samples, errors

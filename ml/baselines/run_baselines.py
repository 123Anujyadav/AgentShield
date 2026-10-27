"""TF-IDF + Logistic Regression baseline. Offline, installed deps only.

Trains on the train split only, selects the decision threshold on the
validation split, and never reads the frozen test split.
Usage: python ml/baselines/run_baselines.py
"""
from __future__ import annotations

import json
import platform
import sys
import time
from pathlib import Path

import sklearn
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sentinel.metrics import binary_metrics  # noqa: E402

SEED = 20261026
ROOT = Path(__file__).resolve().parents[1]
VERSION = sys.argv[1] if len(sys.argv) > 1 else "v0.1.0"
DATA = ROOT / "datasets" / "sentinel" / VERSION / "splits"
RESULTS = ROOT / "results"


def load(name: str) -> list[dict]:
    return [json.loads(l) for l in (DATA / f"{name}.jsonl").read_text(encoding="utf-8").splitlines() if l.strip()]


def slice_report(rows: list[dict], pred: list[str]) -> dict:
    hard = [(r, p) for r, p in zip(rows, pred) if r["label"] == "benign" and r["is_quoted_or_discussed"]]
    out = {}
    if hard:
        out["hard_benign"] = {"n": len(hard),
                              "fpr": round(sum(1 for _, p in hard if p == "suspicious") / len(hard), 4),
                              "false_positive_ids": [r["sample_id"] for r, p in hard if p == "suspicious"]}
    cats: dict[str, list[int]] = {}
    for r, p in zip(rows, pred):
        if r["label"] == "suspicious" and r["attack_category"]:
            cats.setdefault(r["attack_category"], []).append(1 if p == "suspicious" else 0)
    out["attack_category_recall"] = {k: round(sum(v) / len(v), 3) for k, v in sorted(cats.items())}
    return out


def main() -> int:
    train, val = load("train"), load("validation")
    started = time.perf_counter()
    model = Pipeline([
        ("tfidf", TfidfVectorizer(lowercase=True, ngram_range=(1, 2), min_df=1, sublinear_tf=True)),
        ("clf", LogisticRegression(max_iter=1000, random_state=SEED, class_weight="balanced")),
    ])
    model.fit([r["text"] for r in train], [r["label"] for r in train])
    fit_seconds = round(time.perf_counter() - started, 3)

    def evaluate(rows: list[dict], threshold: float) -> tuple[dict, list[str]]:
        probs = model.predict_proba([r["text"] for r in rows])
        classes = list(model.classes_)
        idx = classes.index("suspicious")
        pred = ["suspicious" if p[idx] >= threshold else "benign" for p in probs]
        return binary_metrics([r["label"] for r in rows], pred), pred

    # Threshold selection on validation only (maximize suspicious F1, tie-break lower FPR).
    candidates = [round(0.30 + 0.05 * i, 2) for i in range(9)]
    scored = []
    for t in candidates:
        m, _ = evaluate(val, t)
        scored.append((m["per_class"]["suspicious"]["f1"], -m["benign_fpr"], t))
    best_threshold = max(scored)[2]

    train_metrics, _ = evaluate(train, best_threshold)
    val_metrics, val_pred = evaluate(val, best_threshold)

    majority_label = max({r["label"] for r in train}, key=lambda l: sum(1 for r in train if r["label"] == l))
    majority_metrics = binary_metrics([r["label"] for r in val], [majority_label] * len(val))

    report = {
        "experiment": "tfidf-logreg-baseline",
        "dataset": f"sentinel-{VERSION}",
        "seed": SEED,
        "config": {"vectorizer": "tfidf word 1-2 grams, sublinear", "classifier": "logistic-regression balanced, max_iter=1000"},
        "environment": {"python": platform.python_version(), "sklearn": sklearn.__version__, "platform": platform.platform()},
        "fit_seconds_train_split": fit_seconds,
        "threshold_selected_on_validation": best_threshold,
        "train_metrics_at_threshold": train_metrics,
        "validation_metrics": val_metrics,
        "validation_slices": slice_report(val, val_pred),
        "majority_baseline_validation": majority_metrics,
        "test_split_used": False,
    }
    RESULTS.mkdir(exist_ok=True)
    (RESULTS / f"tfidf-logreg-{VERSION}-validation.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

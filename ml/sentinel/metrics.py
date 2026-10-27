"""Small metric helpers shared by baselines. Positive class: suspicious."""
from __future__ import annotations


def binary_metrics(y_true: list[str], y_pred: list[str]) -> dict:
    labels = ["benign", "suspicious"]
    confusion = {t: {p: 0 for p in labels} for t in labels}
    for t, p in zip(y_true, y_pred):
        confusion[t][p] += 1
    per_class = {}
    for label in labels:
        tp = confusion[label][label]
        fp = sum(confusion[other][label] for other in labels if other != label)
        fn = sum(confusion[label][other] for other in labels if other != label)
        precision = tp / (tp + fp) if tp + fp else 0.0
        recall = tp / (tp + fn) if tp + fn else 0.0
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
        per_class[label] = {"precision": round(precision, 4), "recall": round(recall, 4),
                            "f1": round(f1, 4), "support": tp + fn}
    benign_total = sum(confusion["benign"].values())
    benign_fpr = confusion["benign"]["suspicious"] / benign_total if benign_total else 0.0
    accuracy = sum(confusion[l][l] for l in labels) / max(1, len(y_true))
    return {"accuracy": round(accuracy, 4), "confusion": confusion, "per_class": per_class,
            "benign_fpr": round(benign_fpr, 4), "n": len(y_true)}

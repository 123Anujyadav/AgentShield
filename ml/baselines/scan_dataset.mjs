/**
 * Evaluate the EXISTING deterministic scanner (built engine dist) on dataset
 * splits. Usage: node ml/baselines/scan_dataset.mjs [train|validation]
 * Test split is refused by design in Phase 11A-2.
 */
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { scanUntrustedContent } from "../../packages/engine/dist/index.js";

const split = process.argv[2] ?? "validation";
if (split === "test") {
  console.error("Refusing to evaluate the frozen test split during baseline development.");
  process.exit(2);
}
const root = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const version = process.argv[3] ?? "v0.1.0";
const path = resolve(root, `ml/datasets/sentinel/${version}/splits/${split}.jsonl`);
const rows = readFileSync(path, "utf8").split(/\r?\n/).filter(Boolean).map((l) => JSON.parse(l));

let tp = 0, fp = 0, tn = 0, fn = 0;
const misses = [], falsePositives = [], perCategory = {};
for (const row of rows) {
  const result = scanUntrustedContent(row.text);
  const predicted = result.status === "suspicious" ? "suspicious" : "benign";
  if (row.label === "suspicious") {
    if (row.attack_category) {
      perCategory[row.attack_category] ??= { total: 0, detected: 0 };
      perCategory[row.attack_category].total += 1;
      if (predicted === "suspicious") perCategory[row.attack_category].detected += 1;
    }
    if (predicted === "suspicious") tp += 1; else { fn += 1; misses.push(row.sample_id); }
  } else if (predicted === "suspicious") { fp += 1; falsePositives.push(row.sample_id); } else tn += 1;
}
const precision = tp / Math.max(1, tp + fp), recall = tp / Math.max(1, tp + fn);
const out = {
  baseline: "deterministic-rule-scanner (packages/engine)",
  split, n: rows.length,
  accuracy: +(((tp + tn) / rows.length).toFixed(4)),
  confusion: { benign: { benign: tn, suspicious: fp }, suspicious: { benign: fn, suspicious: tp } },
  suspicious: { precision: +precision.toFixed(4), recall: +recall.toFixed(4), f1: +((2 * precision * recall) / Math.max(1e-9, precision + recall)).toFixed(4) },
  benign_fpr: +(fp / Math.max(1, fp + tn)).toFixed(4),
  per_attack_category_recall: Object.fromEntries(Object.entries(perCategory).map(([k, v]) => [k, +(v.detected / v.total).toFixed(3)])),
  misses, false_positives: falsePositives,
};
mkdirSync(resolve(root, "ml/results"), { recursive: true });
writeFileSync(resolve(root, `ml/results/scanner-${version}-${split}.json`), JSON.stringify(out, null, 2));
console.log(JSON.stringify(out, null, 2));

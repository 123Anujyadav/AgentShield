/**
 * Deterministic synthetic benchmark for the rule-based injection scanner (Phase K).
 *
 * Independent of the credential benchmark in benchmarks/detection/. Each fixture
 * is untrusted content evaluated against the benign-summary scenario (an action
 * the intent allows), so the decision is CONFIRM when any scanner rule fires
 * and ALLOW otherwise. Expected outcomes come from the documented policy,
 * never from detector output.
 *
 * Usage (from the repository root, engine built first):
 *   npm run build -w @agentshield/engine
 *   node benchmarks/scanner/run-scanner-benchmark.mjs [output-name] [corpus-version-dir]
 *
 * corpus-version-dir selects benchmarks/scanner/<dir>/fixtures.json (default: v1).
 * Output: benchmarks/scanner/results/<output-name>.json (default name: latest).
 * The report has no timestamps, so reruns are byte-identical for the same
 * engine build and corpus. The corpus is validated before anything runs.
 * Self-tests: node --test benchmarks/scanner/run-scanner-benchmark.test.mjs
 */
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

/** The two rules whose suppression guards Phase K changed; metrics are reported per rule. */
export const AFFECTED_RULES = ["injection.secret-exfiltration", "injection.unauthorized-tool-action"];
export const KNOWN_RULES = new Set([
  "injection.instruction-override",
  "injection.privilege-impersonation",
  ...AFFECTED_RULES,
]);
export const CATEGORIES = new Set([
  // v1
  "control",
  "suppression-bypass",
  "safety-advice",
  "boundary",
  "malformed",
  // v2: hard-benign safety advice, descriptive security education, attacks framed as
  // quotes or training, and attacks the current patterns cannot see (pattern-gap).
  "hard-benign",
  "education-descriptive",
  "attack-framed",
  "pattern-gap",
  // v3: attacks hidden with invisible format characters, and benign text that
  // legitimately contains them (directional marks, soft hyphens, a leading BOM).
  "obfuscated-attack",
  "obfuscated-benign",
]);
const DECISIONS = new Set(["CONFIRM", "ALLOW"]);
const FIXTURE_KEYS = new Set(["id", "category", "text", "expectedRules", "expectedDecision", "reason"]);

/** Returns every problem found in the corpus; an empty list means it is safe to score. */
export function validateCorpus(corpus) {
  const errors = [];
  if (typeof corpus !== "object" || corpus === null) return ["corpus must be a JSON object"];
  if (typeof corpus.corpus !== "string" || !corpus.corpus) errors.push("corpus.corpus must be a non-empty string");
  if (typeof corpus.version !== "string" || !corpus.version) errors.push("corpus.version must be a non-empty string");
  if (!Array.isArray(corpus.fixtures) || corpus.fixtures.length === 0) {
    errors.push("corpus.fixtures must be a non-empty array");
    return errors;
  }
  const seen = new Set();
  corpus.fixtures.forEach((fixture, index) => {
    const at = `fixtures[${index}]${fixture && typeof fixture.id === "string" ? ` (${fixture.id})` : ""}`;
    if (typeof fixture !== "object" || fixture === null) {
      errors.push(`${at}: must be an object`);
      return;
    }
    for (const key of Object.keys(fixture)) if (!FIXTURE_KEYS.has(key)) errors.push(`${at}: unknown property "${key}"`);
    if (typeof fixture.id !== "string" || !/^[a-z]+-\d{2,}$/.test(fixture.id)) errors.push(`${at}: id must look like "k-01"`);
    else if (seen.has(fixture.id)) errors.push(`${at}: duplicate id`);
    else seen.add(fixture.id);
    if (!CATEGORIES.has(fixture.category)) errors.push(`${at}: unknown category "${fixture.category}"`);
    if (typeof fixture.text !== "string") errors.push(`${at}: text must be a string`);
    if (typeof fixture.reason !== "string" || !fixture.reason.trim()) errors.push(`${at}: reason must be a non-empty string`);
    if (!DECISIONS.has(fixture.expectedDecision)) errors.push(`${at}: expectedDecision must be "CONFIRM" or "ALLOW"`);
    if (!Array.isArray(fixture.expectedRules)) {
      errors.push(`${at}: expectedRules must be an array`);
    } else {
      for (const rule of fixture.expectedRules) if (!KNOWN_RULES.has(rule)) errors.push(`${at}: unknown rule "${rule}"`);
      if (new Set(fixture.expectedRules).size !== fixture.expectedRules.length) errors.push(`${at}: duplicate expected rule`);
      // Every scanner rule is high or critical severity, so for an allowed action
      // any finding escalates to CONFIRM and no finding means ALLOW.
      const confirm = fixture.expectedRules.length > 0;
      if (DECISIONS.has(fixture.expectedDecision) && confirm !== (fixture.expectedDecision === "CONFIRM")) {
        errors.push(`${at}: expectedDecision must be CONFIRM exactly when expectedRules is non-empty`);
      }
    }
  });
  return errors;
}

/**
 * Rates with their denominators, null when a denominator is zero:
 * precision = TP/(TP+FP), recall = TP/(TP+FN), falsePositiveRate = FP/(FP+TN),
 * falseNegativeRate = FN/(FN+TP).
 */
export function metrics(tp, fp, tn, fn) {
  const rate = (num, den) => (den === 0 ? null : +(num / den).toFixed(4));
  return {
    tp,
    fp,
    tn,
    fn,
    precision: rate(tp, tp + fp),
    recall: rate(tp, tp + fn),
    falsePositiveRate: rate(fp, fp + tn),
    falseNegativeRate: rate(fn, fn + tp),
  };
}

/**
 * Scores the corpus. `scan(fixture)` returns { decision, rules } for the
 * fixture's text. Per affected rule, a fixture is positive when the rule is in
 * expectedRules; overall, a fixture is positive when expectedDecision is CONFIRM.
 */
export function scoreCorpus(corpus, scan) {
  const count = () => ({ tp: 0, fp: 0, tn: 0, fn: 0 });
  const tally = (c, expected, actual) => {
    if (expected && actual) c.tp += 1;
    else if (!expected && actual) c.fp += 1;
    else if (!expected && !actual) c.tn += 1;
    else c.fn += 1;
  };
  const overall = count();
  const perRule = new Map(AFFECTED_RULES.map((rule) => [rule, count()]));
  const perCategory = new Map();
  const failures = [];
  for (const fixture of corpus.fixtures) {
    const result = scan(fixture);
    if (!DECISIONS.has(result.decision)) throw new Error(`${fixture.id}: unexpected decision ${result.decision}`);
    const expectedConfirm = fixture.expectedDecision === "CONFIRM";
    const actualConfirm = result.decision === "CONFIRM";
    tally(overall, expectedConfirm, actualConfirm);
    const category = perCategory.get(fixture.category) ?? count();
    tally(category, expectedConfirm, actualConfirm);
    perCategory.set(fixture.category, category);
    if (expectedConfirm !== actualConfirm) {
      failures.push({ id: fixture.id, category: fixture.category, scope: "decision", kind: expectedConfirm ? "false-negative" : "false-positive" });
    }
    for (const rule of AFFECTED_RULES) {
      const expected = fixture.expectedRules.includes(rule);
      const actual = result.rules.includes(rule);
      tally(perRule.get(rule), expected, actual);
      if (expected !== actual) failures.push({ id: fixture.id, category: fixture.category, scope: rule, kind: expected ? "false-negative" : "false-positive" });
    }
  }
  const toMetrics = (c) => metrics(c.tp, c.fp, c.tn, c.fn);
  return {
    benchmark: corpus.corpus,
    corpusVersion: corpus.version,
    fixtures: corpus.fixtures.length,
    definition:
      "Each fixture is untrusted content evaluated with the benign-summary scenario. Overall: positive = expectedDecision CONFIRM, predicted positive = actual decision CONFIRM. Per rule: positive = rule in expectedRules, predicted positive = rule fired. precision = TP/(TP+FP), recall = TP/(TP+FN), falsePositiveRate = FP/(FP+TN), falseNegativeRate = FN/(FN+TP); a rate is null when its denominator is zero.",
    overall: toMetrics(overall),
    perRule: Object.fromEntries(AFFECTED_RULES.map((rule) => [rule, toMetrics(perRule.get(rule))])),
    perCategory: Object.fromEntries([...perCategory.entries()].sort(([a], [b]) => a.localeCompare(b)).map(([k, v]) => [k, toMetrics(v)])),
    failures,
    limitations: limitationsFor(corpus),
  };
}

/**
 * Fixed report caveats. A corpus without obfuscated attacks (v1, v2) keeps the
 * original wording, so its historical reports reproduce byte-for-byte; a corpus
 * that includes them (v3) says how many and names the gaps that remain.
 */
function limitationsFor(corpus) {
  const obfuscated = corpus.fixtures.filter((f) => f.category === "obfuscated-attack").length;
  return [
    "Synthetic hand-authored fixtures only; metrics describe agreement with the documented Phase K policy on similar synthetic text, not real-world detection accuracy.",
    obfuscated === 0
      ? "Only the rule-based scanner is measured. Obfuscated, encoded, non-English, paraphrased, and mid-sentence injections are documented gaps and are not represented here."
      : `Only the rule-based scanner is measured. This corpus includes ${obfuscated} obfuscated attacks that hide a request with the approved invisible format characters (Phase L). Other obfuscation (look-alike letters, invisible characters outside the approved set, and approved characters used in place of spaces) and encoded, non-English, paraphrased, and mid-sentence injections are documented gaps and are not comprehensively represented here.`,
    "The frozen ML test split and all ml/datasets/sentinel payloads are untouched by this benchmark.",
  ];
}

async function main() {
  const root = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
  const corpusDir = process.argv[3] ?? "v1";
  const corpus = JSON.parse(readFileSync(resolve(root, "benchmarks/scanner", corpusDir, "fixtures.json"), "utf8"));
  const errors = validateCorpus(corpus);
  if (errors.length > 0) {
    console.error(`Invalid scanner corpus (${errors.length} problem${errors.length === 1 ? "" : "s"}):`);
    for (const error of errors) console.error(`- ${error}`);
    process.exit(1);
  }

  const { evaluateAction, getScenario } = await import("../../packages/engine/dist/index.js");
  const scenario = getScenario("benign-summary");
  if (!scenario) throw new Error("benign-summary scenario missing from built engine");
  const report = scoreCorpus(corpus, (fixture) => {
    const result = evaluateAction({
      intent: scenario.intent,
      action: scenario.action,
      untrustedContent: { source: "scanner-benchmark", text: fixture.text },
    });
    return { decision: result.decision, rules: result.scannerFindings.map((f) => f.ruleId) };
  });

  const outName = process.argv[2] ?? "latest";
  const outDir = resolve(root, "benchmarks/scanner/results");
  mkdirSync(outDir, { recursive: true });
  writeFileSync(resolve(outDir, `${outName}.json`), `${JSON.stringify(report, null, 2)}\n`);
  console.log(JSON.stringify(report, null, 2));
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  await main();
}

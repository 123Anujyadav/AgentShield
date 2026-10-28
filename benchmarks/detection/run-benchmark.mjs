/**
 * Deterministic synthetic detection benchmark (Phase C-1).
 *
 * Runs the built deterministic engine evaluator over a hand-authored fixture
 * corpus stored OUTSIDE ml/datasets/sentinel/. Expected results are defined
 * in the fixtures by the documented detection policy; they are never derived
 * from detector output. This corpus is isolated from ML training and frozen
 * dataset splits.
 *
 * Usage (from the repository root, engine built first):
 *   npm run build -w @agentshield/engine
 *   node benchmarks/detection/run-benchmark.mjs [output-name] [corpus-version-dir]
 *
 * corpus-version-dir selects benchmarks/detection/<dir>/fixtures.json
 * (default: v1). Output: benchmarks/detection/results/<output-name>.json
 * (default name: latest)
 * The report contains no timestamps, so reruns are byte-identical for the
 * same engine build and corpus.
 *
 * The corpus is validated before anything runs: a malformed fixture, an
 * unknown placeholder, a duplicate id, or a BLOCK caused by something other
 * than the data-leak rule stops the run with exit code 1 instead of being
 * scored silently. Self-tests: node --test benchmarks/detection/run-benchmark.test.mjs
 */
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const DATA_LEAK_RULE = "data-leak.outbound-secret";
const FIELDS = new Set(["summary", "payload", "destination", "tool", "type"]);
/**
 * Phase H provider-credential placeholders. Values are assembled here at run
 * time from clearly fake parts, so neither the corpus files nor this source
 * contain a literal that looks like a real credential (or that the repository
 * secret scanner would flag). Earlier corpora use only the __PAD_*__ entries.
 */
const join = (...parts) => parts.join("");
const fake = (seed, length) => seed.padEnd(length, "0");
const PEM_BODY = "FAKEbenchmarkKeyMaterial0123456789abcdefFAKE";
const pemArmor = (edge, label) => join("-----", edge, " ", label, "-----");
const PRIVATE_KEY_LABEL = join("RSA PRIV", "ATE KEY");
const PROVIDER_PLACEHOLDERS = {
  __PH_AWS_AKIA__: join("AK", "IA", fake("FAKEBENCH", 16)),
  __PH_AWS_ASIA__: join("AS", "IA", fake("FAKEBENCH2", 16)),
  __PH_GITHUB_CLASSIC__: join("gh", "p_", fake("fakeBenchmarkGithub", 36)),
  __PH_GITHUB_FINE__: join("github", "_pat_", fake("fakeBenchmark", 22), "_", fake("fakeBenchmarkFine", 59)),
  __PH_GITLAB__: join("gl", "pat-", fake("fakeBenchmarkGitlab", 20)),
  __PH_STRIPE_SK__: join("sk", "_live_", fake("fakeBenchmarkStripe", 24)),
  __PH_STRIPE_RK__: join("rk", "_live_", fake("fakeBenchmarkRestrict", 24)),
  __PH_SLACK_BOT__: join("xo", "xb-", "000000000001-000000000002-fakeBenchmarkSlack"),
  __PH_GOOGLE__: join("AI", "za", fake("FakeBenchmarkGoogle", 35)),
  __PH_PEM_RSA__: join(pemArmor("BEGIN", PRIVATE_KEY_LABEL), "\n", PEM_BODY, "\n", pemArmor("END", PRIVATE_KEY_LABEL)),
  __PH_AWS_SHORT__: join("AK", "IA", fake("FAKEBENCH", 15)),
  __PH_AWS_GLUED__: join("x", "AK", "IA", fake("FAKEBENCH", 16)),
  __PH_ASIA_WORD__: join("AS", "IA", "PACIFICOPERATION"),
  __PH_GITHUB_UPPER__: join("GH", "P_", fake("fakeBenchmarkGithub", 36)),
  __PH_SLACK_XOXO__: join("xo", "xo-gossip-girl-fans-2024"),
  __PH_GOOGLE_LONG__: join("AI", "za", fake("FakeBenchmarkGoogle", 36)),
  __PH_PEM_HEADER_ONLY__: pemArmor("BEGIN", PRIVATE_KEY_LABEL),
  __PH_PEM_ELIDED__: join(pemArmor("BEGIN", PRIVATE_KEY_LABEL), "\nMIIEvQIBADANBg...\n", pemArmor("END", PRIVATE_KEY_LABEL)),
  __PH_PEM_PUBLIC__: join(pemArmor("BEGIN", "PUBLIC KEY"), "\n", PEM_BODY, "\n", pemArmor("END", "PUBLIC KEY")),
};
/**
 * v1.9 placeholders: a provider value with one approved invisible format
 * character inserted inside its prefix (or, for one GitHub case, its body).
 * Characters are built from their code points, so neither this file nor the
 * corpus holds a raw invisible character. Earlier corpora do not use them.
 */
const insertAt = (value, index, codePoint) => join(value.slice(0, index), String.fromCharCode(codePoint), value.slice(index));
const INVISIBLE_SPLIT_PLACEHOLDERS = {
  __PH_GITHUB_SPLIT_FEFF__: insertAt(PROVIDER_PLACEHOLDERS.__PH_GITHUB_CLASSIC__, 2, 0xfeff),
  __PH_GITHUB_BODY_SPLIT_200B__: insertAt(PROVIDER_PLACEHOLDERS.__PH_GITHUB_CLASSIC__, 16, 0x200b),
  __PH_GITLAB_SPLIT_200D__: insertAt(PROVIDER_PLACEHOLDERS.__PH_GITLAB__, 2, 0x200d),
  __PH_AWS_SPLIT_200F__: insertAt(PROVIDER_PLACEHOLDERS.__PH_AWS_AKIA__, 2, 0x200f),
  __PH_STRIPE_SPLIT_2062__: insertAt(PROVIDER_PLACEHOLDERS.__PH_STRIPE_SK__, 3, 0x2062),
  __PH_SLACK_SPLIT_202E__: insertAt(PROVIDER_PLACEHOLDERS.__PH_SLACK_BOT__, 2, 0x202e),
  __PH_GOOGLE_SPLIT_2069__: insertAt(PROVIDER_PLACEHOLDERS.__PH_GOOGLE__, 2, 0x2069),
  __PH_PEM_SPLIT_200E__: insertAt(PROVIDER_PLACEHOLDERS.__PH_PEM_RSA__, 19, 0x200e),
};
const PLACEHOLDERS = {
  __PAD_2500__: "a".repeat(2500),
  __PAD_9000__: "a".repeat(9000),
  ...PROVIDER_PLACEHOLDERS,
  ...INVISIBLE_SPLIT_PLACEHOLDERS,
};
const PLACEHOLDER_TOKEN = /__[A-Z0-9_]+__/g;

/** Replaces every known placeholder; an unknown placeholder is an error, never left in place. */
export function expand(text) {
  return text.replace(PLACEHOLDER_TOKEN, (token) => {
    if (!Object.hasOwn(PLACEHOLDERS, token)) throw new Error(`unknown placeholder ${token}`);
    return PLACEHOLDERS[token];
  });
}

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
    const allowed = new Set(["id", "family", "field", "text", "expectedBlock", "payloadKey", "payloadValue"]);
    for (const key of Object.keys(fixture)) if (!allowed.has(key)) errors.push(`${at}: unknown property "${key}"`);
    if (typeof fixture.id !== "string" || !fixture.id) errors.push(`${at}: id must be a non-empty string`);
    else if (seen.has(fixture.id)) errors.push(`${at}: duplicate id`);
    else seen.add(fixture.id);
    if (typeof fixture.family !== "string" || !fixture.family) errors.push(`${at}: family must be a non-empty string`);
    if (!FIELDS.has(fixture.field)) errors.push(`${at}: field must be "summary", "payload", "destination", "tool", or "type"`);
    if (typeof fixture.expectedBlock !== "boolean") errors.push(`${at}: expectedBlock must be true or false`);
    if (typeof fixture.text !== "string" || !fixture.text) errors.push(`${at}: text must be a non-empty string`);
    if (fixture.field !== "payload" && (fixture.payloadKey !== undefined || fixture.payloadValue !== undefined)) {
      errors.push(`${at}: payloadKey/payloadValue are only valid when field is "payload"`);
    }
    if (fixture.payloadKey !== undefined && (typeof fixture.payloadKey !== "string" || !fixture.payloadKey)) {
      errors.push(`${at}: payloadKey must be a non-empty string`);
    }
    if (fixture.payloadValue !== undefined && !["string", "number", "boolean"].includes(typeof fixture.payloadValue)) {
      errors.push(`${at}: payloadValue must be a string, number, or boolean`);
    }
    for (const value of [fixture.text, fixture.payloadValue, fixture.payloadKey]) {
      if (typeof value !== "string") continue;
      try {
        expand(value);
      } catch (error) {
        errors.push(`${at}: ${error.message}`);
      }
    }
  });
  return errors;
}

/** Builds the action for one fixture from the benign scenario. */
export function actionFor(baseAction, fixture) {
  if (fixture.field === "tool") {
    return { ...baseAction, tool: expand(fixture.text) };
  }
  if (fixture.field === "type") {
    return { ...baseAction, type: expand(fixture.text) };
  }
  if (fixture.field === "destination") {
    return { ...baseAction, destination: expand(fixture.text) };
  }
  if (fixture.field === "payload") {
    const key = fixture.payloadKey === undefined ? "note" : expand(fixture.payloadKey);
    const raw = fixture.payloadValue ?? fixture.text;
    const value = typeof raw === "string" ? expand(raw) : raw;
    return { ...baseAction, payload: { [key]: value } };
  }
  return { ...baseAction, summary: expand(fixture.text) };
}

function metrics(tp, fp, tn, fn) {
  const precision = tp + fp === 0 ? null : +(tp / (tp + fp)).toFixed(4);
  const recall = tp + fn === 0 ? null : +(tp / (tp + fn)).toFixed(4);
  return { tp, fp, tn, fn, precision, recall };
}

/**
 * Scores the corpus. `evaluate(fixture)` returns the engine result. A BLOCK
 * only counts as a detection when the data-leak rule produced it; any other
 * BLOCK means the fixture does not test the detector and is an error.
 */
export function scoreCorpus(corpus, evaluate) {
  const perFamily = new Map();
  const failures = [];
  let tp = 0, fp = 0, tn = 0, fn = 0;
  for (const fixture of corpus.fixtures) {
    const result = evaluate(fixture);
    const blocked = result.decision === "BLOCK";
    if (blocked && !result.findings.some((f) => f.ruleId === DATA_LEAK_RULE)) {
      throw new Error(`${fixture.id}: BLOCK came from a rule other than ${DATA_LEAK_RULE}`);
    }
    const fam = perFamily.get(fixture.family) ?? { tp: 0, fp: 0, tn: 0, fn: 0 };
    if (fixture.expectedBlock && blocked) { tp += 1; fam.tp += 1; }
    else if (fixture.expectedBlock && !blocked) { fn += 1; fam.fn += 1; failures.push({ id: fixture.id, family: fixture.family, kind: "false-negative" }); }
    else if (!fixture.expectedBlock && blocked) { fp += 1; fam.fp += 1; failures.push({ id: fixture.id, family: fixture.family, kind: "false-positive" }); }
    else { tn += 1; fam.tn += 1; }
    perFamily.set(fixture.family, fam);
  }
  if (tp + fp + tn + fn !== corpus.fixtures.length) {
    throw new Error(`scored ${tp + fp + tn + fn} of ${corpus.fixtures.length} fixtures`);
  }

  return {
    benchmark: corpus.corpus,
    corpusVersion: corpus.version,
    fixtures: corpus.fixtures.length,
    definition:
      "expectedBlock=true means the documented policy requires a hard BLOCK; precision = TP/(TP+FP), recall = TP/(TP+FN), null when the denominator is zero.",
    overall: metrics(tp, fp, tn, fn),
    perFamily: Object.fromEntries(
      [...perFamily.entries()].sort(([a], [b]) => a.localeCompare(b)).map(([k, v]) => [k, metrics(v.tp, v.fp, v.tn, v.fn)]),
    ),
    failures,
    limitations: [
      "Synthetic hand-authored fixtures only; metrics estimate performance on similar synthetic text, not real-world traffic.",
      "known-unsupported fixtures are expected not to block under the current documented policy and count as true negatives when they do not.",
      "The frozen ML test split and all ml/datasets/sentinel payloads are untouched by this benchmark.",
    ],
  };
}

async function main() {
  const root = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
  // Corpus versions live side by side (v1/, v1.1/, v1.2/); v1 stays the default
  // so historical commands reproduce their original reports.
  const corpusDir = process.argv[3] ?? "v1";
  const corpus = JSON.parse(readFileSync(resolve(root, "benchmarks/detection", corpusDir, "fixtures.json"), "utf8"));
  const errors = validateCorpus(corpus);
  if (errors.length > 0) {
    console.error(`Invalid benchmark corpus (${errors.length} problem${errors.length === 1 ? "" : "s"}):`);
    for (const error of errors) console.error(`- ${error}`);
    process.exit(1);
  }

  const { evaluateAction, getScenario } = await import("../../packages/engine/dist/index.js");
  const scenario = getScenario("benign-summary");
  if (!scenario) throw new Error("benign-summary scenario missing from built engine");
  const report = scoreCorpus(corpus, (fixture) => {
    // A destination fixture is judged on its secret content, not on whether
    // the fixture text happens to be an allowed destination.
    const intent =
      fixture.field === "destination"
        ? { ...scenario.intent, allowedDestinations: [expand(fixture.text)] }
        : fixture.field === "type"
          ? { ...scenario.intent, allowedActions: [expand(fixture.text)] }
          : scenario.intent;
    return evaluateAction({ intent, action: actionFor(scenario.action, fixture) });
  });

  const outName = process.argv[2] ?? "latest";
  const outDir = resolve(root, "benchmarks/detection/results");
  mkdirSync(outDir, { recursive: true });
  writeFileSync(resolve(outDir, `${outName}.json`), `${JSON.stringify(report, null, 2)}\n`);
  console.log(JSON.stringify(report, null, 2));
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  await main();
}

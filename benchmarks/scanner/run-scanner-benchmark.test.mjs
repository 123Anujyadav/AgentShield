// Self-tests for the scanner benchmark runner. Run: node --test benchmarks/scanner/run-scanner-benchmark.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { AFFECTED_RULES, metrics, scoreCorpus, validateCorpus } from "./run-scanner-benchmark.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const loadCorpus = (dir) => JSON.parse(readFileSync(resolve(here, dir, "fixtures.json"), "utf8"));
const [EXFIL, TOOL] = AFFECTED_RULES;
const good = { id: "x-01", category: "control", text: "hello", expectedRules: [], expectedDecision: "ALLOW", reason: "benign" };
const withFixtures = (...fixtures) => ({ corpus: "c", version: "v", fixtures });

test("corpus v1 validates cleanly and meets the Phase K composition minimums", () => {
  const corpus = loadCorpus("v1");
  assert.deepEqual(validateCorpus(corpus), []);
  assert.equal(corpus.version, "v1");
  const bypass = corpus.fixtures.filter((f) => f.category === "suppression-bypass");
  assert.ok(bypass.length >= 10, "at least 10 suppression-bypass positives");
  assert.ok(bypass.every((f) => f.expectedDecision === "CONFIRM"));
  for (const rule of AFFECTED_RULES) assert.ok(bypass.some((f) => f.expectedRules.includes(rule)), `bypass cases cover ${rule}`);
  const advice = corpus.fixtures.filter((f) => f.category === "safety-advice");
  assert.ok(advice.length >= 10, "at least 10 safety-advice negatives");
  assert.ok(advice.every((f) => f.expectedDecision === "ALLOW"));
  assert.ok(corpus.fixtures.some((f) => f.category === "boundary"));
  assert.ok(corpus.fixtures.some((f) => f.category === "malformed"));
});

/** The approved invisible format characters (Phase L), as [first, last] code point groups. */
const INVISIBLE_GROUPS = [[0x00ad], [0x180e], [0x200b, 0x200f], [0x202a, 0x202e], [0x2060, 0x2064], [0x2066, 0x2069], [0xfeff]];
const inGroup = ([first, last = first], char) => char.codePointAt(0) >= first && char.codePointAt(0) <= last;
const isInvisible = (char) => INVISIBLE_GROUPS.some((group) => inGroup(group, char));

/** Canonical file form: JSON.stringify(…, 2) with invisible characters written as \uXXXX escapes. */
const canonical = (corpus) =>
  `${[...JSON.stringify(corpus, null, 2)].map((c) => (isInvisible(c) ? `\\u${c.codePointAt(0).toString(16).toUpperCase().padStart(4, "0")}` : c)).join("")}\n`;

test("every corpus version is stored in canonical JSON form with no raw invisible characters", () => {
  for (const dir of ["v1", "v2", "v3"]) {
    const raw = readFileSync(resolve(here, dir, "fixtures.json"), "utf8");
    assert.equal(raw, canonical(JSON.parse(raw)), dir);
    assert.ok(![...raw].some(isInvisible), `${dir} must not contain raw invisible characters`);
  }
});

test("corpus v3 only appends to v2 and meets the Phase L composition minimums", () => {
  const [v2, v3] = ["v2", "v3"].map(loadCorpus);
  assert.deepEqual(validateCorpus(v3), []);
  assert.equal(v3.version, "v3");
  assert.deepEqual(v3.fixtures.slice(0, v2.fixtures.length), v2.fixtures);
  const added = v3.fixtures.slice(v2.fixtures.length);
  const attacks = added.filter((f) => f.category === "obfuscated-attack");
  assert.ok(attacks.length >= 12 && attacks.every((f) => f.expectedDecision === "CONFIRM"));
  for (const rule of ["injection.instruction-override", "injection.privilege-impersonation", ...AFFECTED_RULES]) {
    assert.ok(attacks.some((f) => f.expectedRules.includes(rule)), `obfuscated attacks cover ${rule}`);
  }
  // Every approved group is the only invisible character class in at least one attack,
  // so removing that group from the normalizer is observable.
  for (const group of INVISIBLE_GROUPS) {
    const sole = attacks.filter((f) => {
      const used = [...f.text].filter(isInvisible);
      return used.length > 0 && used.every((c) => inGroup(group, c));
    });
    assert.ok(sole.length > 0, `group U+${group[0].toString(16).toUpperCase()} is exercised on its own`);
  }
  const benign = added.filter((f) => f.category === "obfuscated-benign");
  assert.ok(benign.length >= 10 && benign.every((f) => f.expectedDecision === "ALLOW"));
  assert.ok(benign.every((f) => [...f.text].some(isInvisible)), "every benign v3 text contains an invisible character");
  assert.ok(benign.some((f) => f.text.startsWith("\uFEFF")), "a leading BOM is covered");
  assert.ok(benign.some((f) => /[\u200E\u200F]/.test(f.text)), "directional marks are covered");
  assert.ok(benign.some((f) => f.text.includes("\u00AD")), "soft hyphens are covered");
  assert.ok(benign.some((f) => /^(never|do not)\b/i.test(f.text)), "negated safety advice is covered");
});

test("report limitations keep the v1/v2 wording and state the v3 obfuscated attacks", () => {
  const limitations = (dir) => scoreCorpus(loadCorpus(dir), () => ({ decision: "ALLOW", rules: [] })).limitations;
  const stored = (name) => JSON.parse(readFileSync(resolve(here, "results", `${name}.json`), "utf8")).limitations;
  assert.deepEqual(limitations("v1"), stored("post-k"));
  assert.deepEqual(limitations("v2"), stored("post-k-remediation"));
  const v3 = limitations("v3").join("\n");
  assert.match(v3, /includes 15 obfuscated attacks/);
  assert.doesNotMatch(v3, /Obfuscated, encoded/);
  assert.match(v3, /encoded, non-English, paraphrased, and mid-sentence injections are documented gaps and are not comprehensively represented/);
});

test("corpus v2 only appends to v1 and meets the remediation composition minimums", () => {
  const [v1, v2] = ["v1", "v2"].map(loadCorpus);
  assert.deepEqual(validateCorpus(v2), []);
  assert.equal(v2.version, "v2");
  assert.deepEqual(v2.fixtures.slice(0, v1.fixtures.length), v1.fixtures);
  const added = v2.fixtures.slice(v1.fixtures.length);
  const of = (category) => added.filter((f) => f.category === category);
  const hardBenign = of("hard-benign");
  assert.ok(hardBenign.length >= 10 && hardBenign.every((f) => f.expectedDecision === "ALLOW"));
  assert.ok(hardBenign.filter((f) => /\bever\b/i.test(f.text)).length >= 2, "adverb-separated negations are covered");
  const education = of("education-descriptive");
  assert.ok(education.length >= 10 && education.every((f) => f.expectedDecision === "ALLOW"));
  const framed = of("attack-framed");
  assert.ok(framed.length >= 10 && framed.every((f) => f.expectedDecision === "CONFIRM"));
  assert.ok(framed.some((f) => /["']/.test(f.text)), "quoted attacks are covered");
  assert.ok(of("boundary").length > 0);
});

test("invalid fixtures are rejected instead of scored silently", () => {
  const cases = [
    [{ ...good, reason: "" }, /reason/],
    [{ ...good, category: "other" }, /unknown category/],
    [{ ...good, expectedRules: ["injection.made-up"], expectedDecision: "CONFIRM" }, /unknown rule/],
    [{ ...good, expectedDecision: "BLOCK" }, /expectedDecision must be/],
    [{ ...good, expectedRules: [EXFIL] }, /CONFIRM exactly when/],
    [{ ...good, expectedDecision: "CONFIRM" }, /CONFIRM exactly when/],
    [{ ...good, extra: 1 }, /unknown property/],
    [{ ...good, id: "bad id" }, /id must look like/],
  ];
  for (const [fixture, pattern] of cases) assert.match(validateCorpus(withFixtures(fixture)).join("\n"), pattern);
  assert.match(validateCorpus(withFixtures(good, good)).join("\n"), /duplicate id/);
  assert.deepEqual(validateCorpus(withFixtures(good)), []);
});

test("metrics use explicit denominators and null for zero denominators", () => {
  assert.deepEqual(metrics(3, 1, 4, 2), { tp: 3, fp: 1, tn: 4, fn: 2, precision: 0.75, recall: 0.6, falsePositiveRate: 0.2, falseNegativeRate: 0.4 });
  assert.deepEqual(metrics(0, 0, 0, 0), { tp: 0, fp: 0, tn: 0, fn: 0, precision: null, recall: null, falsePositiveRate: null, falseNegativeRate: null });
  assert.equal(metrics(0, 0, 5, 0).falsePositiveRate, 0);
  assert.equal(metrics(0, 0, 5, 0).recall, null);
});

test("scoring counts decision and per-rule outcomes from the scan result", () => {
  const corpus = withFixtures(
    { ...good, id: "x-01", expectedRules: [EXFIL], expectedDecision: "CONFIRM" },
    { ...good, id: "x-02", expectedRules: [TOOL], expectedDecision: "CONFIRM" },
    { ...good, id: "x-03" },
    { ...good, id: "x-04" },
  );
  const outcomes = {
    "x-01": { decision: "CONFIRM", rules: [EXFIL] }, // TP
    "x-02": { decision: "ALLOW", rules: [] }, // FN
    "x-03": { decision: "CONFIRM", rules: [TOOL] }, // FP
    "x-04": { decision: "ALLOW", rules: [] }, // TN
  };
  const report = scoreCorpus(corpus, (f) => outcomes[f.id]);
  assert.deepEqual([report.overall.tp, report.overall.fp, report.overall.tn, report.overall.fn], [1, 1, 1, 1]);
  assert.deepEqual([report.perRule[EXFIL].tp, report.perRule[EXFIL].fn, report.perRule[EXFIL].tn], [1, 0, 3]);
  assert.deepEqual([report.perRule[TOOL].tp, report.perRule[TOOL].fp, report.perRule[TOOL].fn], [0, 1, 1]);
  assert.deepEqual(report.failures.filter((f) => f.scope === "decision").map((f) => `${f.id}:${f.kind}`), ["x-02:false-negative", "x-03:false-positive"]);
  // Deterministic: scoring twice yields identical serialized reports.
  assert.equal(JSON.stringify(scoreCorpus(corpus, (f) => outcomes[f.id])), JSON.stringify(report));
});

test("a decision other than CONFIRM or ALLOW is an error, not a score", () => {
  assert.throws(() => scoreCorpus(withFixtures(good), () => ({ decision: "BLOCK", rules: [] })), /unexpected decision/);
});

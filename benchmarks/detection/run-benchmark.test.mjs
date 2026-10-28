// Self-tests for the benchmark runner. Run: node --test benchmarks/detection/run-benchmark.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { actionFor, expand, scoreCorpus, validateCorpus } from "./run-benchmark.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const loadCorpus = (dir) => JSON.parse(readFileSync(resolve(here, dir, "fixtures.json"), "utf8"));
const good = { id: "x-01", family: "fam", field: "summary", text: "hello", expectedBlock: false };
const withFixtures = (...fixtures) => ({ corpus: "c", version: "v", fixtures });

test("every corpus version validates cleanly and declares its own version", () => {
  for (const [dir, version, count] of [["v1", "v1", 53], ["v1.1", "v1.1", 55], ["v1.2", "v1.2", 81], ["v1.3", "v1.3", 98], ["v1.4", "v1.4", 117], ["v1.5", "v1.5", 128], ["v1.6", "v1.6", 135], ["v1.7", "v1.7", 159]]) {
    const corpus = loadCorpus(dir);
    assert.deepEqual(validateCorpus(corpus), [], dir);
    assert.equal(corpus.version, version);
    assert.equal(corpus.fixtures.length, count);
  }
});

test("each corpus version extends the previous one without changing earlier fixtures", () => {
  const [v1, v11, v12, v13, v14, v15, v16, v17] = ["v1", "v1.1", "v1.2", "v1.3", "v1.4", "v1.5", "v1.6", "v1.7"].map(loadCorpus);
  assert.deepEqual(v11.fixtures.slice(0, v1.fixtures.length), v1.fixtures);
  assert.deepEqual(v12.fixtures.slice(0, v11.fixtures.length), v11.fixtures);
  assert.deepEqual(v13.fixtures.slice(0, v12.fixtures.length), v12.fixtures);
  assert.deepEqual(v14.fixtures.slice(0, v13.fixtures.length), v13.fixtures);
  assert.deepEqual(v15.fixtures.slice(0, v14.fixtures.length), v14.fixtures);
  // v1.6 differs from v1.5 in exactly one carried fixture: gap-01 is
  // reclassified from known-unsupported to an escaped-json positive (Phase G).
  const carried = v16.fixtures.slice(0, v15.fixtures.length);
  const changed = carried.filter((f, i) => JSON.stringify(f) !== JSON.stringify(v15.fixtures[i]));
  assert.deepEqual(changed.map((f) => f.id), ["gap-01"]);
  assert.deepEqual(carried.find((f) => f.id === "gap-01"), {
    ...v15.fixtures.find((f) => f.id === "gap-01"),
    family: "escaped-json",
    expectedBlock: true,
  });
  // v1.7 (Phase H) only appends to v1.6.
  assert.deepEqual(v17.fixtures.slice(0, v16.fixtures.length), v16.fixtures);
});

test("Phase H fixtures carry provider credentials only as runtime placeholders", () => {
  const raw = readFileSync(resolve(here, "v1.7", "fixtures.json"), "utf8");
  // Credential shapes the runtime detector recognizes; none may appear literally in the corpus file.
  const shapes = [
    /(?:AKIA|ASIA)[A-Z0-9]{16}/,
    /(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30}|github_pat_[A-Za-z0-9_]{30}/,
    /glpat-[A-Za-z0-9_-]{20}/,
    /(?:sk|rk)_live_[A-Za-z0-9]{24}/,
    /xox[abprs]-[A-Za-z0-9-]{10}/,
    /AIza[A-Za-z0-9_-]{35}/,
    /BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY/,
  ];
  for (const shape of shapes) assert.doesNotMatch(raw, shape);
  const v17 = loadCorpus("v1.7");
  const added = v17.fixtures.slice(loadCorpus("v1.6").fixtures.length);
  for (const fixture of added) {
    const fields = [fixture.text, fixture.payloadKey, fixture.payloadValue].filter((v) => typeof v === "string").join(" ");
    if (fixture.family === "provider-token") assert.match(fields, /__PH_[A-Z0-9_]+__/, fixture.id);
  }
  // Placeholders expand in payload keys too, and to the documented shapes.
  const action = actionFor({ summary: "s" }, { ...good, field: "payload", payloadKey: "__PH_GITLAB__", payloadValue: "x" });
  const [key] = Object.keys(action.payload);
  assert.match(key, shapes[2]);
  assert.match(expand("__PH_PEM_RSA__"), shapes[6]);
  assert.doesNotMatch(expand("__PH_PEM_PUBLIC__"), shapes[6]);
});

test("earlier corpora use only the original padding placeholders", () => {
  for (const dir of ["v1", "v1.1", "v1.2", "v1.3", "v1.4", "v1.5", "v1.6"]) {
    const tokens = readFileSync(resolve(here, dir, "fixtures.json"), "utf8").match(/__[A-Z0-9_]+__/g) ?? [];
    assert.deepEqual([...new Set(tokens)].sort(), ["__PAD_2500__", "__PAD_9000__"], dir);
  }
});

test("invalid fixtures are rejected instead of scored silently", () => {
  const cases = [
    [{ ...good, expectedBlock: undefined }, /expectedBlock/],
    [{ ...good, expectedBlock: "true" }, /expectedBlock/],
    [{ ...good, field: "summray" }, /field/],
    [{ ...good, family: "" }, /family/],
    [{ ...good, text: "__PAD_250__" }, /unknown placeholder __PAD_250__/],
    [{ ...good, field: "payload", payloadValue: "__PAD_1__" }, /unknown placeholder __PAD_1__/],
    [{ ...good, payloadKey: "note" }, /only valid when field is "payload"/],
    [{ ...good, expectedblock: true }, /unknown property "expectedblock"/],
    [{ ...good, field: "payload", payloadValue: { nested: 1 } }, /payloadValue/],
  ];
  for (const [fixture, pattern] of cases) {
    const errors = validateCorpus(withFixtures(fixture));
    assert.ok(errors.some((e) => pattern.test(e)), `expected ${pattern} in ${JSON.stringify(errors)}`);
  }
  assert.ok(validateCorpus(withFixtures(good, { ...good })).some((e) => /duplicate id/.test(e)));
  assert.ok(validateCorpus(withFixtures()).some((e) => /non-empty array/.test(e)));
});

test("placeholders expand everywhere they appear, including payload values", () => {
  assert.equal(expand("__PAD_2500__|__PAD_2500__").length, 5001);
  const action = actionFor({ summary: "s" }, { ...good, field: "payload", payloadValue: "__PAD_2500__" });
  assert.equal(action.payload.note.length, 2500);
  assert.throws(() => expand("__PAD_7__"), /unknown placeholder/);
});

test("metrics use TP/FP/TN/FN with null for zero denominators", () => {
  const fixtures = [
    { ...good, id: "p1", family: "pos", expectedBlock: true },
    { ...good, id: "p2", family: "pos", expectedBlock: true },
    { ...good, id: "n1", family: "neg", expectedBlock: false },
    { ...good, id: "n2", family: "neg", expectedBlock: false },
  ];
  const blockedIds = new Set(["p1", "n2"]);
  const leak = { decision: "BLOCK", findings: [{ ruleId: "data-leak.outbound-secret" }] };
  const allow = { decision: "ALLOW", findings: [] };
  const report = scoreCorpus(withFixtures(...fixtures), (f) => (blockedIds.has(f.id) ? leak : allow));
  assert.deepEqual(report.overall, { tp: 1, fp: 1, tn: 1, fn: 1, precision: 0.5, recall: 0.5 });
  assert.deepEqual(report.perFamily.pos, { tp: 1, fp: 0, tn: 0, fn: 1, precision: 1, recall: 0.5 });
  assert.deepEqual(report.perFamily.neg, { tp: 0, fp: 1, tn: 1, fn: 0, precision: 0, recall: null });
  assert.deepEqual(report.failures.map((f) => [f.id, f.kind]), [["p2", "false-negative"], ["n2", "false-positive"]]);
});

test("a BLOCK from a rule other than the data-leak guard is an error, not a detection", () => {
  const otherBlock = { decision: "BLOCK", findings: [{ ruleId: "intent.action-not-allowed" }] };
  assert.throws(() => scoreCorpus(withFixtures({ ...good, expectedBlock: true }), () => otherBlock), /other than data-leak/);
});

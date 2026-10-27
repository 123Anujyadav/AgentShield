// Self-tests for the benchmark runner. Run: node --test benchmarks/detection/run-benchmark.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { actionFor, expand, scoreCorpus, validateCorpus } from "./run-benchmark.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const corpus = JSON.parse(readFileSync(resolve(here, "v1/fixtures.json"), "utf8"));
const good = { id: "x-01", family: "fam", field: "summary", text: "hello", expectedBlock: false };
const withFixtures = (...fixtures) => ({ corpus: "c", version: "v", fixtures });

test("the committed corpus validates cleanly", () => {
  assert.deepEqual(validateCorpus(corpus), []);
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

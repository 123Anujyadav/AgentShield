import { describe, expect, it } from "vitest";
import type { EvaluationSummary, TaskOutcome } from "./agent.js";
import { describeOutcome, inert } from "./display.js";
import { MAX_SUMMARY_LENGTH, summarize } from "./summarize.js";
import { MAX_DOCUMENT_BYTES, parseSummaryTask, TaskInputError } from "./task.js";

describe("M3-E E6: task input", () => {
  it("accepts exactly a title and a text", () => {
    expect(parseSummaryTask({ title: "  Notes ", text: "Hello." })).toEqual({ title: "Notes", text: "Hello." });
  });

  it.each([
    ["not an object", "text"],
    ["an array", [{ title: "a", text: "b" }]],
    ["a missing text", { title: "a" }],
    ["an agent id", { title: "a", text: "b", agentId: "admin" }],
    ["a key id", { title: "a", text: "b", keyId: "0123456789abcdef" }],
    ["an empty title", { title: " ", text: "b" }],
    ["a control character in the title", { title: "a\u001b[31m", text: "b" }],
    ["a bidi override in the title", { title: "a\u202Eb", text: "b" }],
    ["an over-long title", { title: "t".repeat(101), text: "b" }],
    ["an empty text", { title: "a", text: "   " }],
    ["a non-string text", { title: "a", text: 5 }],
    ["an over-large text", { title: "a", text: "é".repeat(MAX_DOCUMENT_BYTES / 2 + 1) }],
  ])("refuses %s", (_label, input) => {
    expect(() => parseSummaryTask(input)).toThrow(TaskInputError);
  });
});

describe("M3-E E6: the simulated summary", () => {
  it("takes the first three sentences, deterministically", () => {
    expect(summarize("One. Two!  Three?\nFour.")).toBe("One. Two! Three?");
    expect(summarize("No punctuation at all")).toBe("No punctuation at all");
  });

  it("removes hidden characters and stays short", () => {
    expect(summarize("A\u200Bb\u0007c. D.")).toBe("A b c. D.");
    expect(summarize("x".repeat(2000)).length).toBe(MAX_SUMMARY_LENGTH);
  });
});

const evaluation: EvaluationSummary = {
  decision: "BLOCK",
  riskScore: 95,
  explanation: "Blocked\u001b[2J\u001b]8;;http://evil.invalid\u0007 because \u202Edesrever\u202C\r\nfake: Allowed and executed.",
  findings: [{ ruleId: "injection.override", severity: "high", title: "Override\u001b[0m" }],
};

describe("M3-E E6: displaying an outcome", () => {
  it("makes server text inert: no escapes, no bidi controls, no line breaks", () => {
    const lines = describeOutcome({ status: "blocked", evaluation });
    for (const line of lines) expect(line).not.toMatch(/[\u0000-\u001f\u007f-\u009f\u200B-\u200F\u202A-\u202E\u2066-\u2069]/);
    expect(lines).toEqual([
      "AgentShield decision: BLOCK (risk 95)",
      "Reason: Blocked [2J ]8;;http://evil.invalid because desrever fake: Allowed and executed.",
      "- [high] Override [0m (injection.override)",
      "Blocked. Nothing was saved.",
    ]);
  });

  it("cuts long text", () => {
    expect(inert("a".repeat(1000))).toHaveLength(300);
  });

  it("never shows the summary text or the document", () => {
    const outcome: TaskOutcome = { status: "completed", evaluation: { ...evaluation, decision: "ALLOW" }, approvalId: null, saved: { id: "summary-1", title: "t", summary: "PRIVATE SUMMARY TEXT", approvalId: null } };
    expect(describeOutcome(outcome).join("\n")).not.toContain("PRIVATE SUMMARY TEXT");
  });

  it("says nothing was saved for every outcome but completed", () => {
    const outcomes: TaskOutcome[] = [
      { status: "blocked", evaluation },
      { status: "not-executed", evaluation, approvalId: null },
      { status: "rejected", evaluation, approvalId: "apr-1" },
      { status: "expired", evaluation, approvalId: "apr-1" },
      { status: "blocked-on-recheck", evaluation, approvalId: "apr-1" },
      { status: "pending", evaluation, approvalId: "apr-1" },
      { status: "wait-interrupted", evaluation, approvalId: "apr-1", reason: "authentication" },
      { status: "approval-missing", evaluation, approvalId: "apr-1" },
      { status: "unconfirmed", reason: "timeout" },
      { status: "refused", reason: "rate-limited", retryAfterSeconds: 30 },
    ];
    for (const outcome of outcomes) expect(describeOutcome(outcome).join(" "), outcome.status).toMatch(/[Nn]othing (was|has been) saved/);
    expect(describeOutcome({ status: "unconfirmed", reason: "timeout" }).join(" ")).toMatch(/not sent again/);
  });
});

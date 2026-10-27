import { describe, expect, it } from "vitest";
import { validateModelOutput } from "./model-analysis.js";

const valid = {
  summary: "Suspicious instruction-like content.",
  indicators: [{ category: "manipulation", severity: "medium", detail: "Urgent framing." }],
  suspectedUnauthorizedAction: false,
  suspectedDataExfiltration: false,
  explanation: "Advisory only.",
};

describe("validateModelOutput", () => {
  it("accepts a bounded advisory response", () => {
    const result = validateModelOutput(valid);
    expect(result.ok).toBe(true);
  });

  it("rejects decision, approval, and execution fields", () => {
    for (const extra of [{ decision: "ALLOW" }, { approved: true }, { toolCall: "send_payment" }, { riskOverride: 0 }]) {
      expect(validateModelOutput({ ...valid, ...extra }).ok).toBe(false);
    }
  });

  it("rejects invalid severity, category, oversized strings, and missing fields", () => {
    expect(validateModelOutput({ ...valid, indicators: [{ category: "x", severity: "high", detail: "d" }] }).ok).toBe(false);
    expect(validateModelOutput({ ...valid, indicators: [{ category: "manipulation", severity: "extreme", detail: "d" }] }).ok).toBe(false);
    expect(validateModelOutput({ ...valid, summary: "x".repeat(281) }).ok).toBe(false);
    expect(validateModelOutput({ summary: "only" }).ok).toBe(false);
    expect(validateModelOutput("nope").ok).toBe(false);
    expect(validateModelOutput(null).ok).toBe(false);
  });
});

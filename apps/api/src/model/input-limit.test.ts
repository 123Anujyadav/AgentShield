import { describe, expect, it } from "vitest";
import { evaluateAction, getScenario, MAX_SCAN_LENGTH, MODEL_ANALYSIS_LIMITS } from "@agentshield/engine";
import { ModelAnalysisService } from "./analyze.js";
import { loadModelConfig } from "./config.js";
import { MockModelProvider } from "./provider.js";

/**
 * M3-B (G9): the advisory analysis accepts the same untrusted-content length as
 * evaluation. Pure: the mock provider only, no app, no server, no network.
 */

const service = (env: NodeJS.ProcessEnv = {}) => new ModelAnalysisService(new MockModelProvider(), loadModelConfig(env));

describe("M3-B (G9): model input limit matches the evaluation contract", () => {
  it("defaults to the evaluation limit (8,000 characters)", () => {
    expect(MAX_SCAN_LENGTH).toBe(8000);
    expect(MODEL_ANALYSIS_LIMITS.maxInputLength).toBe(MAX_SCAN_LENGTH);
    expect(loadModelConfig({}).maxInputLength).toBe(MAX_SCAN_LENGTH);
  });

  it("analyzes content right up to 8,000 characters and refuses 8,001 explicitly", async () => {
    const atLimit = await service().analyze("a".repeat(MAX_SCAN_LENGTH));
    expect(atLimit.failureReason).not.toBe("oversized-input");
    expect(atLimit.status).toBe("success");
    const over = await service().analyze("a".repeat(MAX_SCAN_LENGTH + 1));
    expect([over.status, over.failureReason]).toEqual(["failed", "oversized-input"]);
  });

  it("a lower configured limit is reported as an analysis failure, never a silent truncation", async () => {
    const limited = service({ MODEL_MAX_INPUT_CHARS: "4000" });
    expect((await limited.analyze("a".repeat(4000))).status).toBe("success");
    const refused = await limited.analyze("a".repeat(4001));
    expect([refused.status, refused.failureReason, refused.authority]).toEqual(["failed", "oversized-input", "advisory-only"]);
  });

  it("the analysis stays advisory: it carries no decision and cannot change the evaluation", async () => {
    const scenario = getScenario("injection-in-document");
    if (!scenario) throw new Error("missing scenario");
    const text = `${scenario.untrustedContent!.text} ${"x".repeat(MAX_SCAN_LENGTH - scenario.untrustedContent!.text.length - 1)}`;
    expect(text.length).toBe(MAX_SCAN_LENGTH);
    const input = { intent: scenario.intent, action: scenario.action, untrustedContent: { source: scenario.untrustedContent!.source, text } };
    const before = evaluateAction(input);
    const analysis = await service().analyze(text);
    const after = evaluateAction(input);
    expect(after).toEqual(before);
    expect(before.decision).toBe("CONFIRM");
    expect(analysis.authority).toBe("advisory-only");
    for (const key of ["decision", "riskScore", "allow", "block", "approve", "execute"]) expect(Object.keys(analysis)).not.toContain(key);
  });
});

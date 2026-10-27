import { describe, expect, it } from "vitest";
import { evaluateAction } from "./evaluate.js";
import { getScenario } from "./scenarios.js";

describe("evaluateAction (walking skeleton)", () => {
  it("allows a permitted benign action", () => {
    const scenario = getScenario("benign-summary");
    if (!scenario) throw new Error("missing benign scenario");
    const result = evaluateAction({ intent: scenario.intent, action: scenario.action });
    expect(result.decision).toBe("ALLOW");
    expect(result.riskScore).toBeLessThan(50);
    expect(result.findings[0]?.ruleId).toBe("intent.action-allowed");
  });

  it("flags injected content but lets action policy decide: permitted action becomes CONFIRM, not BLOCK", () => {
    const scenario = getScenario("injection-in-document");
    if (!scenario) throw new Error("missing injection scenario");
    const result = evaluateAction({
      intent: scenario.intent,
      action: scenario.action,
      untrustedContent: scenario.untrustedContent,
    });
    expect(result.scannerStatus).toBe("suspicious");
    expect(result.scannerFindings.length).toBeGreaterThanOrEqual(2);
    expect(result.scannerFindings.every((f) => f.category === "injection")).toBe(true);
    expect(result.decision).toBe("CONFIRM");
    expect(result.findings.some((f) => f.ruleId === "policy.suspicious-content-requires-confirmation")).toBe(true);
  });

  it("keeps hard-deny BLOCK authoritative when content is also malicious", () => {
    const scenario = getScenario("forbidden-payment");
    if (!scenario) throw new Error("missing forbidden scenario");
    const result = evaluateAction({
      intent: scenario.intent,
      action: scenario.action,
      untrustedContent: scenario.untrustedContent,
      userApproved: true,
    });
    expect(result.decision).toBe("BLOCK");
    expect(result.riskScore).toBe(95);
    expect(result.scannerFindings.length).toBeGreaterThan(0);
    const evidence = result.findings.map((f) => f.evidence).join(" ");
    expect(evidence).not.toContain("FAKE_TEST_SECRET_123");
  });

  it("allows a benign security article with a clean scan", () => {
    const scenario = getScenario("benign-security-article");
    if (!scenario) throw new Error("missing article scenario");
    const result = evaluateAction({
      intent: scenario.intent,
      action: scenario.action,
      untrustedContent: scenario.untrustedContent,
    });
    expect(result.scannerStatus).toBe("clean");
    expect(result.decision).toBe("ALLOW");
  });

  it("intent firewall: missing permissions block conservatively", () => {
    const scenario = getScenario("benign-summary");
    if (!scenario) throw new Error("missing scenario");
    const result = evaluateAction({
      intent: { task: "Vague request", allowedActions: [], deniedActions: [] },
      action: scenario.action,
    });
    expect(result.decision).toBe("BLOCK");
    expect(result.findings.some((f) => f.ruleId === "intent.permissions-missing")).toBe(true);
  });

  it("intent firewall: permitted type to a disallowed destination blocks", () => {
    const scenario = getScenario("benign-summary");
    if (!scenario) throw new Error("missing scenario");
    const result = evaluateAction({
      intent: scenario.intent,
      action: { ...scenario.action, destination: "external-server" },
    });
    expect(result.decision).toBe("BLOCK");
    expect(result.findings.some((f) => f.ruleId === "intent.destination-not-allowed")).toBe(true);
  });

  it("intent firewall: conflicting allow+deny resolves to deny, scanner stays distinct", () => {
    const scenario = getScenario("benign-summary");
    if (!scenario) throw new Error("missing scenario");
    const result = evaluateAction({
      intent: { ...scenario.intent, allowedActions: ["create_summary", "send_payment"], deniedActions: ["send_payment"] },
      action: { type: "send_payment", tool: "simulated.payment.send", destination: "external-account", summary: "Pay" },
      untrustedContent: getScenario("forbidden-payment")?.untrustedContent,
    });
    expect(result.decision).toBe("BLOCK");
    expect(result.findings.some((f) => f.category === "hard-deny")).toBe(true);
    expect(result.scannerFindings.length).toBeGreaterThan(0);
    expect(result.scannerFindings.every((f) => f.category === "injection")).toBe(true);
  });

  it("blocks an explicitly forbidden action, even with user approval", () => {
    const scenario = getScenario("forbidden-payment");
    if (!scenario) throw new Error("missing forbidden scenario");
    const result = evaluateAction({ intent: scenario.intent, action: scenario.action, userApproved: true });
    expect(result.decision).toBe("BLOCK");
    expect(result.riskScore).toBeGreaterThanOrEqual(90);
    expect(result.findings[0]?.category).toBe("hard-deny");
  });
});

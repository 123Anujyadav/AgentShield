import { describe, expect, it } from "vitest";
import { evaluateAction, getScenario } from "@agentshield/engine";
import { createApprovalStore, createPendingApproval, processApproval } from "./approvals.js";
import { createSimulator } from "./simulator.js";

function makePending() {
  const scenario = getScenario("injection-in-document");
  if (!scenario) throw new Error("missing scenario");
  const store = createApprovalStore();
  const evaluation = evaluateAction({
    intent: scenario.intent,
    action: scenario.action,
    untrustedContent: scenario.untrustedContent,
  });
  const approval = createPendingApproval(store, {
    scenarioId: scenario.id,
    intent: scenario.intent,
    action: scenario.action,
    untrustedContent: scenario.untrustedContent,
    evaluation,
  });
  return { store, scenario, approval };
}

describe("processApproval policy recheck", () => {
  it("prevents execution when current policy returns BLOCK for the stored action", () => {
    const { store, approval } = makePending();
    const simulator = createSimulator();
    const outcome = processApproval(
      store,
      approval.id,
      (record) =>
        evaluateAction({
          intent: { ...record.intent, allowedActions: [], deniedActions: ["create_summary"] },
          action: record.action,
          untrustedContent: record.untrustedContent,
        }),
      simulator,
    );
    expect(outcome.kind).toBe("blocked-on-recheck");
    expect(simulator.invocationCount).toBe(0);
    if (outcome.kind === "blocked-on-recheck") {
      expect(outcome.approval.status).toBe("BLOCKED_ON_RECHECK");
      expect(outcome.recheck.decision).toBe("BLOCK");
    }
  });

  it("expired approvals cannot execute", () => {
    const { store, scenario, approval } = makePending();
    const simulator = createSimulator();
    const outcome = processApproval(
      store,
      approval.id,
      (record) =>
        evaluateAction({ intent: record.intent, action: record.action, untrustedContent: record.untrustedContent }),
      simulator,
      new Date(Date.now() + 16 * 60 * 1000),
    );
    expect(outcome.kind).toBe("expired");
    expect(simulator.invocationCount).toBe(0);
    expect(scenario.id).toBe("injection-in-document");
  });

  it("simulator independently refuses BLOCK and CONFIRM decisions", () => {
    const simulator = createSimulator();
    const scenario = getScenario("benign-summary");
    if (!scenario) throw new Error("missing scenario");
    expect(simulator.execute(scenario.action, "BLOCK").executed).toBe(false);
    expect(simulator.execute(scenario.action, "CONFIRM").executed).toBe(false);
    expect(simulator.invocationCount).toBe(0);
    expect(simulator.execute(scenario.action, "ALLOW").executed).toBe(true);
    expect(simulator.invocationCount).toBe(1);
  });
});

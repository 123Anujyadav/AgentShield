import { describe, expect, it } from "vitest";
import { evaluateAction, getScenario } from "@agentshield/engine";
import {
  APPROVAL_TTL_MS,
  createApprovalStore,
  createPendingApproval,
  expirePendingApprovals,
  markExpiryEventRecorded,
  processApproval,
  processRejection,
  type ApprovalRecord,
  type ApprovalStore,
} from "./approvals.js";
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

function makePendingIn(store: ApprovalStore) {
  const scenario = getScenario("injection-in-document");
  if (!scenario) throw new Error("missing scenario");
  const evaluation = evaluateAction({
    intent: scenario.intent,
    action: scenario.action,
    untrustedContent: scenario.untrustedContent,
  });
  return createPendingApproval(store, {
    scenarioId: scenario.id,
    intent: scenario.intent,
    action: scenario.action,
    untrustedContent: scenario.untrustedContent,
    evaluation,
  });
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

  it("expirePendingApprovals transitions only stale PENDING records to EXPIRED", () => {
    const { store, approval } = makePending();
    const future = new Date(Date.now() + 16 * 60 * 1000);
    expect(expirePendingApprovals(store, future)).toBe(1);
    expect(store.records.get(approval.id)?.status).toBe("EXPIRED");
    // Idempotent: a second sweep changes nothing.
    expect(expirePendingApprovals(store, future)).toBe(0);
  });

  it("expirePendingApprovals leaves fresh and already-final records untouched", () => {
    const { store, approval } = makePending();
    expect(expirePendingApprovals(store, new Date())).toBe(0);
    expect(store.records.get(approval.id)?.status).toBe("PENDING");
    const rejected = processRejection(store, approval.id, new Date());
    expect(rejected.kind).toBe("rejected");
    expect(expirePendingApprovals(store, new Date(Date.now() + 60 * 60 * 1000))).toBe(0);
    expect(store.records.get(approval.id)?.status).toBe("REJECTED");
  });

  it("rejecting an expired approval reports expiry instead of rejection", () => {
    const { store, approval } = makePending();
    const outcome = processRejection(store, approval.id, new Date(Date.now() + 16 * 60 * 1000));
    expect(outcome.kind).toBe("expired");
    expect(store.records.get(approval.id)?.status).toBe("EXPIRED");
  });

  it("a new approval expires exactly 15 minutes after creation", () => {
    const scenario = getScenario("injection-in-document");
    if (!scenario) throw new Error("missing scenario");
    const store = createApprovalStore();
    const evaluation = evaluateAction({
      intent: scenario.intent,
      action: scenario.action,
      untrustedContent: scenario.untrustedContent,
    });
    const now = new Date("2026-10-27T00:00:00.000Z");
    const approval = createPendingApproval(
      store,
      {
        scenarioId: scenario.id,
        intent: scenario.intent,
        action: scenario.action,
        untrustedContent: scenario.untrustedContent,
        evaluation,
      },
      now,
    );
    expect(APPROVAL_TTL_MS).toBe(15 * 60 * 1000);
    expect(new Date(approval.expiresAt).getTime() - new Date(approval.createdAt).getTime()).toBe(APPROVAL_TTL_MS);
    expect(approval.createdAt).toBe(now.toISOString());
  });

  it("expiry boundary: valid exactly at expiresAt, expired one millisecond after", () => {
    const { store, approval } = makePending();
    const record = store.records.get(approval.id);
    if (!record) throw new Error("pending record missing");
    const expiresAt = new Date(record.expiresAt);
    expect(expirePendingApprovals(store, expiresAt)).toBe(0);
    expect(record.status).toBe("PENDING");
    expect(expirePendingApprovals(store, new Date(expiresAt.getTime() + 1))).toBe(1);
    expect(record.status).toBe("EXPIRED");
  });

  it("sweeping mixed fresh PENDING, stale PENDING and already-final records only expires the stale one", () => {
    const store = createApprovalStore();
    const fresh = makePendingIn(store);
    const stale = makePendingIn(store);
    const rejected = makePendingIn(store);
    expect(processRejection(store, rejected.id, new Date()).kind).toBe("rejected");
    const staleRecord = store.records.get(stale.id);
    if (!staleRecord) throw new Error("stale record missing");
    staleRecord.expiresAt = new Date(Date.now() - 1000).toISOString();

    const notified: string[] = [];
    expect(expirePendingApprovals(store, new Date(), (a) => notified.push(a.id))).toBe(1);
    expect(notified).toEqual([stale.id]);
    expect(store.records.get(fresh.id)?.status).toBe("PENDING");
    expect(store.records.get(stale.id)?.status).toBe("EXPIRED");
    expect(store.records.get(rejected.id)?.status).toBe("REJECTED");
    // No second notification on a repeat sweep.
    expect(expirePendingApprovals(store, new Date(), (a) => notified.push(a.id))).toBe(0);
    expect(notified).toEqual([stale.id]);
  });

  it("repeated rejection after expiry stays expired with the event still pending until acknowledged", () => {
    const { store, approval } = makePending();
    const future = new Date(Date.now() + 16 * 60 * 1000);
    const first = processRejection(store, approval.id, future);
    expect(first.kind).toBe("expired");
    if (first.kind === "expired") expect(first.expiryEventPending).toBe(true);
    const second = processRejection(store, approval.id, future);
    expect(second.kind).toBe("expired");
    if (second.kind === "expired") {
      expect(second.expiryEventPending).toBe(true);
      expect(second.approval.status).toBe("EXPIRED");
    }
    expect(markExpiryEventRecorded(store, approval.id)).toBe(true);
    expect(markExpiryEventRecorded(store, approval.id)).toBe(false);
    const approve = processApproval(
      store,
      approval.id,
      (record) =>
        evaluateAction({ intent: record.intent, action: record.action, untrustedContent: record.untrustedContent }),
      createSimulator(),
      future,
    );
    expect(approve.kind).toBe("expired");
    if (approve.kind === "expired") expect(approve.expiryEventPending).toBe(false);
  });

  it("a failing expiry-event write neither blocks other stale records nor loses the failed event", () => {
    const store = createApprovalStore();
    const first = makePendingIn(store);
    const second = makePendingIn(store);
    for (const a of [first, second]) {
      const r = store.records.get(a.id);
      if (!r) throw new Error("record missing");
      r.expiresAt = new Date(Date.now() - 1000).toISOString();
    }
    const written: string[] = [];
    const attempt = (failFirst: boolean) =>
      expirePendingApprovals(store, new Date(), (a) => {
        if (failFirst && a.id === first.id) throw new Error("injected event-write failure");
        written.push(a.id);
      });

    // First sweep: first record's write fails, second is still processed.
    expect(attempt(true)).toBe(2);
    expect(written).toEqual([second.id]);
    expect(store.records.get(first.id)?.status).toBe("EXPIRED");
    expect(store.records.get(first.id)?.expiryEventPending).toBe(true);
    expect(store.records.get(second.id)?.expiryEventPending).toBe(false);

    // Retry delivers exactly the missing event, once.
    expect(attempt(false)).toBe(0);
    expect(written).toEqual([second.id, first.id]);
    expect(store.records.get(first.id)?.expiryEventPending).toBe(false);
    expect(attempt(false)).toBe(0);
    expect(written).toEqual([second.id, first.id]);
  });

  it("EXECUTED and BLOCKED_ON_RECHECK records past expiry stay final with no expiry event", () => {
    const store = createApprovalStore();
    const executed = makePendingIn(store);
    const blocked = makePendingIn(store);
    const simulator = createSimulator();
    const reevaluate = (record: ApprovalRecord) =>
      evaluateAction({ intent: record.intent, action: record.action, untrustedContent: record.untrustedContent });
    expect(processApproval(store, executed.id, reevaluate, simulator).kind).toBe("executed");
    const blockedOutcome = processApproval(
      store,
      blocked.id,
      (record) =>
        evaluateAction({
          intent: { ...record.intent, deniedActions: [...record.intent.deniedActions, record.action.type] },
          action: record.action,
          untrustedContent: record.untrustedContent,
        }),
      simulator,
    );
    expect(blockedOutcome.kind).toBe("blocked-on-recheck");
    for (const a of [executed, blocked]) {
      const r = store.records.get(a.id);
      if (!r) throw new Error("record missing");
      r.expiresAt = new Date(Date.now() - 1000).toISOString();
    }
    const notified: string[] = [];
    expect(expirePendingApprovals(store, new Date(), (a) => notified.push(a.id))).toBe(0);
    expect(notified).toEqual([]);
    expect(store.records.get(executed.id)?.status).toBe("EXECUTED");
    expect(store.records.get(blocked.id)?.status).toBe("BLOCKED_ON_RECHECK");
  });

  it("approve and reject exactly at expiresAt still act on a live approval", () => {
    const approvedCase = makePending();
    const approvedRecord = approvedCase.store.records.get(approvedCase.approval.id);
    if (!approvedRecord) throw new Error("record missing");
    const simulator = createSimulator();
    const atExpiry = new Date(approvedRecord.expiresAt);
    const approveOutcome = processApproval(
      approvedCase.store,
      approvedCase.approval.id,
      (record) =>
        evaluateAction({ intent: record.intent, action: record.action, untrustedContent: record.untrustedContent }),
      simulator,
      atExpiry,
    );
    expect(approveOutcome.kind).toBe("executed");
    expect(simulator.invocationCount).toBe(1);

    const rejectedCase = makePending();
    const rejectedRecord = rejectedCase.store.records.get(rejectedCase.approval.id);
    if (!rejectedRecord) throw new Error("record missing");
    const rejectOutcome = processRejection(
      rejectedCase.store,
      rejectedCase.approval.id,
      new Date(rejectedRecord.expiresAt),
    );
    expect(rejectOutcome.kind).toBe("rejected");

    const lateCase = makePending();
    const lateRecord = lateCase.store.records.get(lateCase.approval.id);
    if (!lateRecord) throw new Error("record missing");
    const lateOutcome = processRejection(
      lateCase.store,
      lateCase.approval.id,
      new Date(new Date(lateRecord.expiresAt).getTime() + 1),
    );
    expect(lateOutcome.kind).toBe("expired");
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

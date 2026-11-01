import { appendFileSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { evaluateAction, getScenario } from "@agentshield/engine";
import { approvalStorePathFromEnv, openDurableApprovalStore, type DurableApprovalStore } from "./approval-journal.js";
import { createPendingApproval, processApproval, processRejection } from "./approvals.js";
import { createSimulator } from "./simulator.js";

/** M3-E E12: the durable approval store on its own. Temporary files only. */

let dir: string;
let path: string;
const stores: DurableApprovalStore[] = [];
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "agentshield-approvals-"));
  path = join(dir, "approvals.journal");
  vi.spyOn(console, "warn").mockImplementation(() => {});
});
afterEach(() => {
  vi.restoreAllMocks();
  for (const s of stores.splice(0)) s.close();
  rmSync(dir, { recursive: true, force: true });
});

const open = (extra: Partial<Parameters<typeof openDurableApprovalStore>[0]> = {}) => {
  const store = openDurableApprovalStore({ path, ...extra });
  stores.push(store);
  return store;
};
const restart = (store: DurableApprovalStore, extra: Partial<Parameters<typeof openDurableApprovalStore>[0]> = {}) => {
  store.close();
  stores.splice(stores.indexOf(store), 1);
  return open(extra);
};

const scenario = getScenario("injection-in-document")!;
const evaluation = evaluateAction({ intent: scenario.intent, action: scenario.action, untrustedContent: scenario.untrustedContent });
const pending = (store: DurableApprovalStore) =>
  createPendingApproval(store, { scenarioId: null, intent: scenario.intent, action: scenario.action, untrustedContent: scenario.untrustedContent, evaluation, agentId: "writer", requestedBy: { kind: "agent", credentialId: "0123456789abcdef" }, credentialKeyId: "0123456789abcdef" });
const allow = () => ({ ...evaluation, decision: "ALLOW" as const });

describe("M3-E E12: durable approval store", () => {
  it("approvals and their states survive a restart, with the same ids and timestamps", () => {
    let store = open();
    const a = pending(store);
    const b = pending(store);
    const c = pending(store);
    processRejection(store, b.id);
    expect(processApproval(store, c.id, allow, createSimulator())).toMatchObject({ kind: "executed", durable: true });
    store = restart(store);
    expect([...store.records.values()].map((r) => [r.id, r.status, r.createdAt])).toEqual([
      [a.id, "PENDING", a.createdAt],
      [b.id, "REJECTED", b.createdAt],
      [c.id, "EXECUTED", c.createdAt],
    ]);
    expect(store.records.get(a.id)).toMatchObject({ untrustedContent: scenario.untrustedContent, credentialKeyId: "0123456789abcdef" });
    expect(store.recovery).toMatchObject({ records: 3, pending: 1, interrupted: 0, corrupt: 0 });
  });

  it("ids are never reused, even after records are compacted away", () => {
    let store = open({ limit: 1, finishedRetentionMs: 0, compactAtBytes: 1 });
    const first = pending(store);
    processRejection(store, first.id);
    const second = pending(store); // evicts the first; the next append compacts the journal
    processRejection(store, second.id);
    expect(readFileSync(path, "utf8")).not.toContain(`"id":"${first.id}","status"`);
    store = restart(store, { limit: 1, finishedRetentionMs: 0 });
    expect(pending(store).id).toBe("apr-3");
  });

  it("a final decision can never be changed by a later journal line (a rejected approval never becomes approved)", () => {
    let store = open();
    const a = pending(store);
    processRejection(store, a.id);
    store.close();
    stores.length = 0;
    appendFileSync(path, `${JSON.stringify({ v: 1, t: "to", id: a.id, s: "EXECUTED", e: { executed: true, handler: "create_summary", result: "x", reason: null } })}\n`);
    store = open();
    expect(store.records.get(a.id)).toMatchObject({ status: "REJECTED" });
    expect(store.recovery.corrupt).toBe(1);
  });

  it("an approval being carried out when the API stopped becomes OUTCOME_UNKNOWN: never run again, never reported as executed", () => {
    let store = open();
    const a = pending(store);
    store.close();
    stores.length = 0;
    appendFileSync(path, `${JSON.stringify({ v: 1, t: "approving", id: a.id })}\n`);
    store = open();
    expect(store.records.get(a.id)).toMatchObject({ status: "OUTCOME_UNKNOWN", execution: { executed: false } });
    expect(store.recovery.interrupted).toBe(1);
    const simulator = createSimulator();
    expect(processApproval(store, a.id, allow, simulator).kind).toBe("already-final");
    expect(simulator.invocationCount).toBe(0);
    // Recorded durably: a second restart reads the same state without re-deriving it.
    expect(restart(store).records.get(a.id)?.status).toBe("OUTCOME_UNKNOWN");
  });

  it("a damaged record: the pending approvals it names (or, if none, all pending ones) become OUTCOME_UNKNOWN; final ones are untouched", () => {
    let store = open();
    const a = pending(store);
    const b = pending(store);
    const c = pending(store);
    processRejection(store, c.id);
    store.close();
    stores.length = 0;
    appendFileSync(path, `{"v":1,"t":"to","id":"${a.id}","s":"REJ\n`);
    store = open();
    expect([store.records.get(a.id)?.status, store.records.get(b.id)?.status, store.records.get(c.id)?.status]).toEqual(["OUTCOME_UNKNOWN", "PENDING", "REJECTED"]);
    expect(readFileSync(path, "utf8")).not.toContain('"s":"REJ\n'); // rewritten without the damaged line
    store.close();
    stores.length = 0;
    appendFileSync(path, "garbage without an id\n");
    store = open();
    expect(store.records.get(b.id)?.status).toBe("OUTCOME_UNKNOWN");
    expect(store.recovery.quarantined).toBe(1);
  });

  it("a record cut short by a crash was never acted on: the previous state stands", () => {
    let store = open();
    const a = pending(store);
    store.close();
    stores.length = 0;
    appendFileSync(path, `{"v":1,"t":"approving","id":"${a.id}"`); // no LF: the write did not complete
    store = open();
    expect(store.records.get(a.id)?.status).toBe("PENDING");
    expect(store.recovery).toMatchObject({ truncatedTail: true, interrupted: 0, corrupt: 0 });
  });

  it("recent finished approvals are kept (an idempotency record may refer to them); the store is full instead", () => {
    const store = open({ limit: 2 });
    const a = pending(store);
    processRejection(store, a.id);
    pending(store);
    expect(() => pending(store)).toThrow(/approval-queue-full/);
    expect(store.records.has(a.id)).toBe(true);
  });

  it("default location under the profile", () => {
    expect(approvalStorePathFromEnv({ LOCALAPPDATA: "C:\\Users\\x\\AppData\\Local" })).toBe(join("C:\\Users\\x\\AppData\\Local", "AgentShield", "approvals.journal"));
  });
});

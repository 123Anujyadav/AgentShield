import { appendFileSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { evaluateAction, getScenario, type ActivityEvent } from "@agentshield/engine";
import { openDurableApprovalStore, type DurableApprovalStore } from "../approval-journal.js";
import { createPendingApproval, processApproval, processRejection } from "../approvals.js";
import { openFileAuditLog, serializeAuditRecord, type AuditLog } from "../audit/file-audit-log.js";
import { openDurableNonceCache } from "../agents/durable-nonce-cache.js";
import { createIdempotencyStore } from "../idempotency.js";
import { createSimulator } from "../simulator.js";
import { DEFAULT_JOURNAL_IO, openJournal, type Journal } from "./journal.js";

/**
 * M3-E E13: integrity-chain detection (corruption detection, not authenticity), fail-safe recovery of
 * every store, and filesystem hardening. Temporary directories only.
 */

let dir: string;
const closers: Array<() => void> = [];
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "agentshield-integrity-"));
  vi.spyOn(console, "warn").mockImplementation(() => {});
  vi.spyOn(console, "error").mockImplementation(() => {});
});
afterEach(() => {
  vi.restoreAllMocks();
  for (const close of closers.splice(0)) close();
  rmSync(dir, { recursive: true, force: true });
});

const journalAt = (path: string, extra: Partial<Parameters<typeof openJournal>[1]> = {}): Journal => {
  const journal = openJournal(path, { label: "test journal", maxBytes: 1024 * 1024, maxRecordBytes: 4096, ...extra });
  closers.push(() => journal.close());
  return journal;
};
const lines = (path: string) => readFileSync(path, "utf8").split("\n").filter(Boolean);
const rewriteLines = (path: string, next: string[]) => writeFileSync(path, next.map((l) => `${l}\n`).join(""));

function written(path: string, records: string[]) {
  const journal = journalAt(path);
  for (const record of records) journal.append(record);
  journal.close();
}

describe("M3-E E13: what the journal integrity chain detects", () => {
  const records = ["r1 alpha", "r2 beta", "r3 gamma", "r4 delta"];

  it("an untouched journal verifies; each line carries its chain value", () => {
    const path = join(dir, "j.journal");
    written(path, records);
    expect(lines(path).every((l) => /\t[0-9a-f]{64}$/.test(l))).toBe(true);
    const journal = journalAt(path);
    expect([journal.records, journal.verified, journal.integrity]).toEqual([records, [true, true, true, true], { legacy: false, unverified: 0, firstUnverifiedLine: null }]);
  });

  it.each([
    ["modification of one record", (l: string[]) => [l[0]!, l[1]!.replace("beta", "BETA"), l[2]!, l[3]!], [true, false, true, true]],
    ["deletion of a record (the next one no longer verifies)", (l: string[]) => [l[0]!, l[2]!, l[3]!], [true, false, true]],
    ["insertion of a record (it and the next one fail)", (l: string[]) => [l[0]!, `forged\t${"0".repeat(64)}`, l[1]!, l[2]!, l[3]!], [true, false, false, true, true]],
    ["reordering", (l: string[]) => [l[0]!, l[2]!, l[1]!, l[3]!], [true, false, false, false]],
    // Without its chain value the next record cannot be linked either, so both are unverified.
    ["a record without integrity metadata", (l: string[]) => [l[0]!, "r2 beta", l[2]!, l[3]!], [true, false, false, true]],
    ["invalid integrity metadata", (l: string[]) => [l[0]!, l[1]!.replace(/\t[0-9a-f]{64}$/, `\t${"z".repeat(64)}`), l[2]!, l[3]!], [true, false, false, true]],
  ])("detects %s", (_label, tamper, expected) => {
    const path = join(dir, "j.journal");
    written(path, records);
    rewriteLines(path, tamper(lines(path)));
    const journal = journalAt(path);
    expect(journal.verified).toEqual(expected);
    expect(journal.integrity.unverified).toBe(expected.filter((v) => !v).length);
  });

  it("a journal copied from another store does not verify (per-store genesis)", () => {
    const path = join(dir, "j.journal");
    written(path, records);
    const journal = journalAt(path, { label: "another store" });
    expect(journal.verified[0]).toBe(false);
  });

  it("documented limit: whole records removed from the end, or a chain recomputed by the editor, are NOT detected", () => {
    const path = join(dir, "j.journal");
    written(path, records);
    rewriteLines(path, lines(path).slice(0, 2));
    expect(journalAt(path).integrity.unverified).toBe(0);
  });

  it("a journal written before M3-E E13 (no chain at all) is reported as legacy, not as tampered", () => {
    const path = join(dir, "j.journal");
    rewriteLines(path, records);
    const journal = journalAt(path);
    expect([journal.integrity.legacy, journal.verified.every(Boolean)]).toEqual([true, true]);
  });

  it("a compaction interrupted by a crash leaves the previous journal intact and verifiable", () => {
    const path = join(dir, "j.journal");
    written(path, records);
    const journal = journalAt(path, {
      io: {
        ...DEFAULT_JOURNAL_IO,
        replaceFile: (target, content) => {
          writeFileSync(`${target}.partial-temp`, content.slice(0, 10)); // the temporary file, then the crash
          throw new Error("simulated crash before the rename");
        },
      },
    });
    expect(() => journal.rewrite(["only"])).toThrow(/rewrite-failed/);
    journal.close();
    const reopened = journalAt(path);
    expect([reopened.records, reopened.integrity.unverified]).toEqual([records, 0]);
  });
});

describe("M3-E E13: filesystem hardening", () => {
  it("refuses a journal or audit log under a parent directory that is a junction or symbolic link", () => {
    const real = join(dir, "real");
    mkdirSync(real);
    symlinkSync(real, join(dir, "linked"), "junction");
    expect(() => journalAt(join(dir, "linked", "state", "j.journal"))).toThrow(/parent directory of the file is a symbolic link or junction/);
    expect(() => openFileAuditLog(join(dir, "linked", "audit.jsonl"))).toThrow(/parent directory of the file is a symbolic link or junction/);
    expect(readdirSync(real)).toEqual([]); // nothing was created through the link
  });

  it("lock tampering: a removed or replaced lock stops writing (fail closed); the other process's lock is left alone", () => {
    const path = join(dir, "j.journal");
    const journal = journalAt(path);
    journal.append("first");
    rmSync(`${path}.lock`);
    expect(() => journal.append("second")).toThrow(/lock-lost/);
    expect(journal.failed).toBe(true);

    const other = join(dir, "k.journal");
    const second = journalAt(other);
    writeFileSync(`${other}.lock`, "999999"); // someone else's lock now
    expect(() => second.append("x")).toThrow(/lock-lost/);
    second.close();
    expect(readFileSync(`${other}.lock`, "utf8")).toBe("999999");
  });

  it("the audit log stops appending when its lock is removed", () => {
    const log = openFileAuditLog(join(dir, "audit.jsonl"));
    closers.push(() => log.close());
    rmSync(join(dir, "audit.jsonl.lock"));
    expect(() => log.append(auditEvent(1))).toThrow(/lock-lost/);
    expect(log.readiness()).toEqual({ ok: false, reason: "audit-unavailable" });
  });
});

function auditEvent(seq: number): ActivityEvent {
  return {
    id: `evt-${seq}`,
    timestamp: new Date(Date.UTC(2026, 10, 1, 9, 0, seq)).toISOString(),
    scenarioId: null,
    intentTask: `Task ${seq}`,
    actionType: "create_summary",
    tool: "simulated.workspace.createSummary",
    destination: "simulated-workspace",
    decision: "ALLOW",
    riskScore: 10,
    findings: [],
    explanation: "Allowed.",
  };
}

describe("M3-E E13: audit log integrity", () => {
  const open = (): AuditLog => {
    const log = openFileAuditLog(join(dir, "audit.jsonl"));
    closers.push(() => log.close());
    return log;
  };

  it("a modified or deleted event is detected, reported, and left out of the event view (never silently accepted)", () => {
    let log = open();
    for (let i = 1; i <= 4; i += 1) log.append(auditEvent(i));
    log.close();
    const path = join(dir, "audit.jsonl");
    const original = lines(path);
    // Delete event 2: event 3's prev no longer matches.
    rewriteLines(path, [original[0]!, original[2]!, original[3]!]);
    log = open();
    expect(log.recovery).toMatchObject({ unverified: 1, unverifiedLines: [2] });
    expect(log.loaded.map((e) => e.id)).toEqual(["evt-1", "evt-4"]);
    log.close();
    // A pre-E13 (v1) record placed after chained ones is not accepted either.
    appendFileSync(path, serializeAuditRecord(auditEvent(9)));
    log = open();
    expect(log.recovery.unverified).toBe(2);
    expect(log.loaded.map((e) => e.id)).not.toContain("evt-9");
  });

  it("a pre-E13 log (v1 records) is accepted as legacy; new records are chained after it", () => {
    const path = join(dir, "audit.jsonl");
    writeFileSync(path, [1, 2].map((i) => serializeAuditRecord(auditEvent(i))).join(""));
    let log = open();
    expect(log.recovery).toMatchObject({ legacyRecords: 2, unverified: 0 });
    log.append(auditEvent(3));
    log.close();
    log = open();
    expect([log.loaded.map((e) => e.id), log.recovery.unverified]).toEqual([["evt-1", "evt-2", "evt-3"], 0]);
  });
});

describe("M3-E E13: stores recover fail-safe from integrity failures", () => {
  const scenario = getScenario("injection-in-document")!;
  const evaluation = evaluateAction({ intent: scenario.intent, action: scenario.action, untrustedContent: scenario.untrustedContent });
  const approvalsPath = () => join(dir, "approvals.journal");
  const openApprovals = (): DurableApprovalStore => {
    const store = openDurableApprovalStore({ path: approvalsPath() });
    closers.push(() => store.close());
    return store;
  };
  const pending = (store: DurableApprovalStore) =>
    createPendingApproval(store, { scenarioId: null, intent: scenario.intent, action: scenario.action, untrustedContent: scenario.untrustedContent, evaluation, agentId: "writer", requestedBy: { kind: "agent", credentialId: "0123456789abcdef" }, credentialKeyId: "0123456789abcdef" });

  it("a modified pending approval can never become executable: OUTCOME_UNKNOWN, and the damaged journal is preserved", () => {
    let store = openApprovals();
    const a = pending(store);
    const b = pending(store);
    processRejection(store, b.id);
    store.close();
    // Someone edits the stored action of the pending approval (without a valid chain).
    writeFileSync(approvalsPath(), readFileSync(approvalsPath(), "utf8").replace('"destination":"simulated-workspace"', '"destination":"attacker-share"'));
    store = openApprovals();
    expect(store.records.get(a.id)).toMatchObject({ status: "OUTCOME_UNKNOWN" });
    expect(store.records.get(b.id)?.status).toBe("REJECTED");
    expect(store.recovery.damagedCopy).toMatch(/approvals\.journal\.damaged-/);
    expect(existsSync(store.recovery.damagedCopy!)).toBe(true);
    const simulator = createSimulator();
    expect(processApproval(store, a.id, () => ({ ...evaluation, decision: "ALLOW" }), simulator).kind).toBe("already-final");
    expect(simulator.invocationCount).toBe(0);
  });

  it("a pre-E13 approval journal is migrated: records kept, then rewritten with the chain", () => {
    const store = openApprovals();
    const a = pending(store);
    store.close();
    rewriteLines(approvalsPath(), lines(approvalsPath()).map((l) => l.replace(/\t[0-9a-f]{64}$/, "")));
    const migrated = openApprovals();
    expect([migrated.recovery.legacyMigrated, migrated.records.get(a.id)?.status]).toEqual([true, "PENDING"]);
    expect(lines(approvalsPath()).every((l) => /\t[0-9a-f]{64}$/.test(l))).toBe(true);
  });

  it("E12 regression: a cut-short decision record does not quarantine its approval on a later restart", () => {
    let store = openApprovals();
    const a = pending(store);
    store.close();
    appendFileSync(approvalsPath(), `{"v":1,"t":"to","id":"${a.id}","s":"REJE`);
    store = openApprovals(); // first restart: tail excluded, journal rewritten clean
    expect(store.records.get(a.id)?.status).toBe("PENDING");
    store.close();
    store = openApprovals(); // second restart: still pending, nothing quarantined
    expect([store.records.get(a.id)?.status, store.recovery.quarantined, store.recovery.corrupt]).toEqual(["PENDING", 0, 0]);
  });

  it("replay protection cannot silently reset: a deleted nonce record triggers the recovery fence", () => {
    const path = join(dir, "replay.journal");
    const T = 1_793_523_600_000;
    let cache = openDurableNonceCache({ path, now: () => T - 120_000, skewMs: 30_000 });
    cache.checkAndInsert("0123456789abcdef", "nonce-0000000000000001", T + 30_000, T - 120_000);
    cache.checkAndInsert("0123456789abcdef", "nonce-0000000000000002", T + 30_000, T - 120_000);
    cache.close();
    const kept = lines(path);
    rewriteLines(path, kept.filter((l) => !l.includes("nonce-0000000000000001")));
    cache = openDurableNonceCache({ path, now: () => T, skewMs: 30_000 });
    closers.push(() => cache.close());
    expect(cache.recovery.unverified).toBeGreaterThan(0);
    expect(cache.recoveringUntil).toBe(T + 30_000);
  });

  it("a forged idempotency result is never replayed: the key becomes outcome-unknown", () => {
    const path = join(dir, "idempotency.journal");
    let store = createIdempotencyStore({ path, now: () => Date.now() });
    store.begin("writer", "key-000000000000001", "1".repeat(64), Date.now());
    store.complete("writer", "key-000000000000001", { status: 200, body: { evaluation: { decision: "BLOCK" }, executed: false } });
    store.close();
    writeFileSync(path, readFileSync(path, "utf8").replace('"decision":"BLOCK"', '"decision":"ALLOW"'));
    store = createIdempotencyStore({ path, now: () => Date.now() });
    closers.push(() => store.close());
    expect(store.recovery).toMatchObject({ unverified: 1 });
    expect(store.begin("writer", "key-000000000000001", "1".repeat(64), Date.now()).kind).toBe("unknown");
  });
});

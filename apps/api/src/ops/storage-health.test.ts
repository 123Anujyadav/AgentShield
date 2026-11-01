import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { DEMO_AGENT_POLICY, type ActivityEvent } from "@agentshield/engine";
import { createApp } from "../app.js";
import { openDurableApprovalStore } from "../approval-journal.js";
import { openFileAuditLog } from "../audit/file-audit-log.js";
import { createCredentialStore } from "../agents/credentials.js";
import { openDurableNonceCache } from "../agents/durable-nonce-cache.js";
import { createIdempotencyStore } from "../idempotency.js";
import { createPolicyStore } from "../policies/store.js";
import { chainValue, journalGenesis } from "../storage/journal.js";
import type { StoreHealth } from "../storage/health.js";
import { request, signedRequest, TEST_API_TOKEN, testSigningKey } from "../test-support.js";
import { createStorageMonitor, storageHealthReport, type StartupFindings, type StoreSource } from "./storage-health.js";
import { storeSources } from "./store-sources.js";

/**
 * M3-E E14: storage capacity and health (the report, the operator route, the monitor) and start-up
 * diagnostics: unsupported versions, stale and conflicting locks, lost stores, a previous crash, permissions.
 */

const T = Date.UTC(2026, 10, 1, 9, 0, 0);
let dir: string;
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "agentshield-health-"));
  vi.spyOn(console, "warn").mockImplementation(() => {});
  vi.spyOn(console, "error").mockImplementation(() => {});
});
afterEach(() => {
  vi.restoreAllMocks();
  rmSync(dir, { recursive: true, force: true });
});

const healthy: StoreHealth = { bytes: 100, maxBytes: 1000, entries: 1, entryLimit: 100, writable: true, lockHeld: true, full: false };
const clean: StartupFindings = { integrityFailures: 0, damagedCopyPreserved: false, truncatedRecordRecovered: false, legacyMigrated: false, staleLockReplaced: false, permissionsRestricted: true };
const source = (h: Partial<StoreHealth> = {}, s: Partial<StartupFindings> = {}, recoveringUntil?: number): StoreSource => ({
  store: "approval-store",
  health: () => ({ ...healthy, ...h }),
  startup: { ...clean, ...s },
  ...(recoveringUntil !== undefined ? { recoveringUntil } : {}),
});
const levelOf = (s: StoreSource) => {
  const r = storageHealthReport([s], T).stores.find((x) => x.store === "approval-store")!;
  return [r.level, r.warnings];
};

function event(seq: number, approvalId?: string): ActivityEvent {
  return {
    id: `evt-${seq}`,
    timestamp: new Date(T + seq).toISOString(),
    scenarioId: null,
    intentTask: "t",
    actionType: "create_summary",
    tool: "t",
    destination: "d",
    decision: "ALLOW",
    riskScore: 1,
    findings: [],
    explanation: "e",
    ...(approvalId ? { approvalId } : {}),
  };
}

/** A process id that ran and has exited: a lock holding it is stale. */
function deadPid(): number {
  return spawnSync(process.execPath, ["-e", ""]).pid!;
}

describe("M3-E E14: the storage health report", () => {
  it("rates capacity: ok below 80%, warning from 80%, critical from 95% or when full", () => {
    expect(levelOf(source())).toEqual(["ok", []]);
    expect(levelOf(source({ bytes: 800 }))).toEqual(["warning", ["bytes-above-warning"]]);
    expect(levelOf(source({ bytes: 950 }))).toEqual(["critical", ["bytes-above-critical"]]);
    expect(levelOf(source({ entries: 80 }))).toEqual(["warning", ["entries-above-warning"]]);
    expect(levelOf(source({ entries: 99 }))).toEqual(["critical", ["entries-above-critical"]]);
    expect(levelOf(source({ full: true, bytes: 10 }))).toEqual(["critical", ["storage-full"]]);
  });

  it("reports a failed store (a write failed, or the lock was lost) as failed", () => {
    expect(levelOf(source({ writable: false }))).toEqual(["failed", ["write-failed"]]);
    expect(levelOf(source({ lockHeld: false, writable: false }))).toEqual(["failed", ["lock-lost", "write-failed"]]);
  });

  it("raises integrity failures, recovery windows and loose permissions found at start-up; crash artifacts are informational", () => {
    expect(levelOf(source({}, { integrityFailures: 2 }))).toEqual(["warning", ["integrity-failure-at-startup"]]);
    expect(levelOf(source({}, { permissionsRestricted: false }))).toEqual(["warning", ["permissions-not-restricted"]]);
    expect(levelOf(source({}, {}, T + 1000))).toEqual(["warning", ["recovering"]]);
    expect(levelOf(source({}, {}, T - 1000))).toEqual(["ok", []]); // a window that has passed
    expect(levelOf(source({}, { staleLockReplaced: true, truncatedRecordRecovered: true, legacyMigrated: true, approvalsMadeOutcomeUnknown: 1 }))).toEqual([
      "ok",
      ["approvals-made-outcome-unknown-at-startup", "stale-lock-replaced-at-startup", "truncated-record-recovered-at-startup", "migrated-at-startup"],
    ]);
  });

  it("lists every store; memory-only ones are marked not durable; the overall level is the worst", () => {
    const report = storageHealthReport([source({ bytes: 960 })], T);
    expect(report.stores.map((s) => [s.store, s.durable])).toEqual([
      ["audit-log", false],
      ["approval-store", true],
      ["idempotency-store", false],
      ["replay-store", false],
    ]);
    expect(report.level).toBe("critical");
    expect(report.stores[1]).toMatchObject({ remainingBytes: 40, bytesUsedPercent: 96 });
  });

  it("the monitor logs a store when its level or warnings change, never repeatedly, and never deletes anything", () => {
    let bytes = 100;
    const logged: string[] = [];
    const monitor = createStorageMonitor(() => storageHealthReport([source({ get bytes() { return bytes; } } as Partial<StoreHealth>)], T), (line) => logged.push(line));
    monitor.check();
    expect(logged).toEqual([]); // ok at start-up: nothing to say
    bytes = 850;
    monitor.check();
    monitor.check();
    expect(logged).toEqual(["storage store=approval-store level=warning bytesUsedPercent=85 remainingBytes=150 entries=1/100 warnings=bytes-above-warning"]);
    bytes = 100;
    monitor.check();
    expect(logged.at(-1)).toContain("level=ok");
  });
});

describe("M3-E E14: GET /api/storage/health", () => {
  function durableApp() {
    const auditLog = openFileAuditLog(join(dir, "audit-events.jsonl"), { maxBytes: 1024 * 1024 });
    // A replay journal from an earlier start, so its start-up fence has passed and signed requests are served.
    openDurableNonceCache({ path: join(dir, "replay-nonces.journal"), now: () => Date.now() - 120_000, skewMs: 30_000 }).close();
    const nonceCache = openDurableNonceCache({ path: join(dir, "replay-nonces.journal"), now: Date.now, skewMs: 30_000 });
    const idempotencyStore = createIdempotencyStore({ path: join(dir, "idempotency.journal") });
    const approvalStore = openDurableApprovalStore({ path: join(dir, "approvals.journal") });
    const writer = testSigningKey("writer", "e14-health-writer");
    const app = createApp({
      apiToken: TEST_API_TOKEN,
      auditLog,
      nonceCache,
      idempotencyStore,
      approvalStore,
      policyStore: createPolicyStore([DEMO_AGENT_POLICY, { agentId: "writer", version: 1, allowedActions: ["create_summary"], deniedActions: [], allowedDestinations: ["simulated-workspace"] }], "file"),
      credentialStore: createCredentialStore([writer.record]),
    });
    const close = () => {
      approvalStore.close();
      idempotencyStore.close();
      nonceCache.close();
      auditLog.close();
    };
    return { app, writer, close, approvalStore, auditLog };
  }

  it("is operator-only, numbers and codes only (no path, no file name), never cached", async () => {
    const t = durableApp();
    try {
      const res = await request(t.app).get("/api/storage/health");
      expect(res.status).toBe(200);
      expect(res.headers["cache-control"]).toBe("no-store");
      expect(res.body.level).toBe("ok");
      expect(res.body.stores.map((s: { store: string; durable: boolean }) => [s.store, s.durable])).toEqual([
        ["audit-log", true],
        ["approval-store", true],
        ["idempotency-store", true],
        ["replay-store", true],
      ]);
      expect(res.body.stores.find((s: { store: string }) => s.store === "approval-store")).toMatchObject({ entries: 0, entryLimit: 500, writable: true, lockHeld: true });
      const text = JSON.stringify(res.body);
      expect(text).not.toContain(dir.replace(/\\/g, "\\\\"));
      expect(text).not.toMatch(/\.journal|\.jsonl|AgentShield|Users/);
      const agent = await signedRequest(t.app, t.writer, "get", "/api/storage/health", { ts: Date.now() }).send();
      expect([agent.status, agent.body.reason]).toEqual([403, "operator-required"]);
    } finally {
      t.close();
    }
  });

  it("shows a full audit log as critical, and a lost lock as failed", async () => {
    const t = durableApp();
    try {
      // Fill the audit log to its readiness limit (one maximum-size record of room).
      const big = "x".repeat(200 * 1024);
      for (let seq = 1; t.auditLog.readiness().ok; seq += 1) t.auditLog.append({ ...event(seq), explanation: big });
      rmSync(join(dir, "approvals.journal.lock"));
      const res = await request(t.app).get("/api/storage/health");
      const audit = res.body.stores.find((s: { store: string }) => s.store === "audit-log");
      expect(audit).toMatchObject({ level: "critical", full: true });
      expect(audit.warnings).toContain("storage-full");
      expect(res.body.stores.find((s: { store: string }) => s.store === "approval-store")).toMatchObject({ level: "failed", lockHeld: false });
      expect(res.body.level).toBe("failed");
      // Reported only: nothing was deleted or rotated.
      expect(existsSync(join(dir, "audit-events.jsonl"))).toBe(true);
    } finally {
      t.close();
    }
  });
});

describe("M3-E E14: start-up refuses a newer format instead of rewriting it away", () => {
  const chained = (label: string, records: string[]) => {
    let chain = journalGenesis(label);
    return records.map((r) => `${r}\t${(chain = chainValue(chain, r))}\n`).join("");
  };

  it.each([
    ["approval store", "approvals.journal", (p: string) => openDurableApprovalStore({ path: p }).close(), JSON.stringify({ v: 2, t: "create" })],
    ["idempotency store", "idempotency.journal", (p: string) => createIdempotencyStore({ path: p }).close(), JSON.stringify({ v: 3, t: "b" })],
    ["replay store", "replay-nonces.journal", (p: string) => openDurableNonceCache({ path: p, now: () => T, skewMs: 30_000 }).close(), "n2 0123456789abcdef AAAAAAAAAAAAAAAAAAAAAA 1793523600000"],
  ])("%s", (label, file, open, record) => {
    const path = join(dir, file);
    const content = chained(label, [record]);
    writeFileSync(path, content);
    expect(() => open(path)).toThrow(/format version \d, written by a newer AgentShield/);
    expect(readFileSync(path, "utf8")).toBe(content); // untouched: nothing rewritten, nothing lost
    expect(existsSync(`${path}.lock`)).toBe(false);
  });

  it("audit log", () => {
    const path = join(dir, "audit-events.jsonl");
    const content = `{"v":3,"seq":1,"future":true}\n`;
    writeFileSync(path, content);
    expect(() => openFileAuditLog(path)).toThrow(/format version 3, written by a newer AgentShield/);
    expect(readFileSync(path, "utf8")).toBe(content);
  });
});

describe("M3-E E14: start-up after a previous process crashed", () => {
  it("replaces stale locks, recovers cut-short records, and reports both without raising an integrity failure", () => {
    const paths = { audit: join(dir, "audit-events.jsonl"), approvals: join(dir, "approvals.journal"), idem: join(dir, "idempotency.journal"), replay: join(dir, "replay-nonces.journal") };
    const audit = openFileAuditLog(paths.audit);
    audit.append(event(1));
    audit.close();
    const approvals = openDurableApprovalStore({ path: paths.approvals });
    approvals.close();
    // The crash: a record cut short in every file, and every lock left behind by a process that is gone.
    const dead = deadPid();
    for (const p of Object.values(paths)) {
      writeFileSync(p, `${existsSync(p) ? readFileSync(p, "utf8") : ""}{"v":1,"t":"cut-sh`);
      writeFileSync(`${p}.lock`, String(dead));
    }
    const a = openFileAuditLog(paths.audit);
    const ap = openDurableApprovalStore({ path: paths.approvals });
    const id = createIdempotencyStore({ path: paths.idem, historyExpected: true });
    const r = openDurableNonceCache({ path: paths.replay, now: Date.now, skewMs: 30_000 });
    try {
      expect(a.recovery).toMatchObject({ staleLockReplaced: true, truncatedTail: true });
      expect(ap.recovery).toMatchObject({ staleLockReplaced: true, truncatedTail: true, corrupt: 0 });
      expect(id.recovery).toMatchObject({ staleLockReplaced: true, truncatedTail: true, corrupt: 0, missingWithHistory: false });
      expect(r.recovery).toMatchObject({ staleLockReplaced: true, truncatedTail: true, corrupt: 0 });
      const report = storageHealthReport(storeSources({ auditLog: a, approvalStore: ap, idempotencyStore: id, nonceCache: r }), Date.now());
      for (const s of report.stores) {
        expect(s.startup?.integrityFailures, s.store).toBe(0);
        expect(s.warnings, s.store).toContain("stale-lock-replaced-at-startup");
        expect(s.warnings, s.store).toContain("truncated-record-recovered-at-startup");
      }
    } finally {
      r.close();
      id.close();
      ap.close();
      a.close();
    }
  });

  it("a lock held by a running process stops start-up and is left in place", () => {
    const path = join(dir, "approvals.journal");
    writeFileSync(`${path}.lock`, String(process.ppid));
    expect(() => openDurableApprovalStore({ path })).toThrow(new RegExp(`in use by another AgentShield API process \\(pid ${process.ppid}\\)`));
    expect(readFileSync(`${path}.lock`, "utf8")).toBe(String(process.ppid));
  });
});

describe("M3-E E14: start-up when a store was lost", () => {
  it("a lost approval journal never reissues an id the audit log shows was issued", () => {
    const audit = openFileAuditLog(join(dir, "audit-events.jsonl"));
    audit.append(event(1, "apr-7"));
    const highest = audit.recovery.highestApprovalId; // 0: read when opened
    audit.close();
    expect(highest).toBe(0);
    const reopened = openFileAuditLog(join(dir, "audit-events.jsonl"));
    expect(reopened.recovery.highestApprovalId).toBe(7);
    reopened.close();
    const path = join(dir, "approvals.journal");
    const store = openDurableApprovalStore({ path });
    expect(store.recovery.created).toBe(true);
    expect(store.reserveIdsThrough(7)).toBe(true);
    expect(store.nextId).toBe(8);
    expect(store.reserveIdsThrough(3)).toBe(false); // never moves backwards
    store.close();
    const again = openDurableApprovalStore({ path });
    expect(again.nextId).toBe(8); // recorded durably
    again.close();
  });

  it("a lost idempotency journal (other stores hold history) applies the recovery window; a first start does not", () => {
    const lost = createIdempotencyStore({ path: join(dir, "lost.journal"), now: () => T, historyExpected: true });
    expect(lost.recovery).toMatchObject({ missingWithHistory: true, recoveringUntil: T + 15 * 60 * 1000 });
    expect(lost.begin("writer", "idem-key-0000000001", "a".repeat(64), T).kind).toBe("unavailable");
    lost.close();
    // The window is recorded, so a restart inside it keeps it (the journal now exists).
    const restarted = createIdempotencyStore({ path: join(dir, "lost.journal"), now: () => T + 1000, historyExpected: true });
    expect(restarted.recovery).toMatchObject({ missingWithHistory: false, recoveringUntil: T + 15 * 60 * 1000 });
    restarted.close();
    const first = createIdempotencyStore({ path: join(dir, "first.journal"), now: () => T, historyExpected: false });
    expect(first.recovery).toMatchObject({ missingWithHistory: false, recoveringUntil: 0 });
    first.close();
  });

  it("an existing journal whose permissions are not restricted is reported", () => {
    if (process.platform !== "win32") return;
    const path = join(dir, "approvals.journal");
    writeFileSync(path, ""); // inherits the temporary directory's permissions
    const store = openDurableApprovalStore({ path, checkPermissions: true });
    try {
      expect(store.recovery.permissionsRestricted).toBe(false);
      const report = storageHealthReport(storeSources({ approvalStore: store }), T);
      expect(report.stores.find((s) => s.store === "approval-store")?.warnings).toContain("permissions-not-restricted");
    } finally {
      store.close();
    }
  });
});

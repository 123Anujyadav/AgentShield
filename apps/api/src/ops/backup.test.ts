import { createHash } from "node:crypto";
import { cpSync, existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { evaluateAction, getScenario, type ActivityEvent } from "@agentshield/engine";
import { openDurableApprovalStore } from "../approval-journal.js";
import { createPendingApproval, processApproval, processRejection, type ApprovalStore } from "../approvals.js";
import { openFileAuditLog } from "../audit/file-audit-log.js";
import { openDurableNonceCache } from "../agents/durable-nonce-cache.js";
import { isRestrictedToCurrentUser, windowsAclEntries } from "../agents/file-security.js";
import { readCredentialFile, serializeCredentialDocument } from "../agents/credentials.js";
import { createIdempotencyStore } from "../idempotency.js";
import { createSimulator } from "../simulator.js";
import { chainValue, journalGenesis } from "../storage/journal.js";
import { testSigningKey } from "../test-support.js";
import { backupStores, MANIFEST_NAME, OpsError, restoreStores, storageStatus, verifyBackup, type StorePaths } from "./backup.js";
import { runOpsCli } from "./cli.js";

/**
 * M3-E E14: offline backup, backup verification, restore (missing or damaged stores only) and storage status.
 * Temporary directories and deterministic test credentials only; nothing touches the real AgentShield state.
 */

// Each backup restricts several files with icacls on Windows (a process per file): allow for a busy machine.
vi.setConfig({ testTimeout: 20_000 });

const T = Date.UTC(2026, 10, 1, 9, 0, 0);
const now = () => T;
const scenario = getScenario("injection-in-document")!;
const evaluation = evaluateAction({ intent: scenario.intent, action: scenario.action, untrustedContent: scenario.untrustedContent });
/** A recognisable value stored inside approvals and events: it must never appear in any tool output. */
const CANARY = "e14-canary-record-content";

let root: string;
let state: string;
let paths: StorePaths;

beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), "agentshield-ops-"));
  state = join(root, "state");
  paths = {
    auditLog: join(state, "audit-events.jsonl"),
    approvals: join(state, "approvals.journal"),
    idempotency: join(state, "idempotency.journal"),
    replay: join(state, "replay-nonces.journal"),
    credentials: join(state, "agent-credentials.json"),
  };
  vi.spyOn(console, "warn").mockImplementation(() => {});
  vi.spyOn(console, "error").mockImplementation(() => {});
});
afterEach(() => {
  vi.restoreAllMocks();
  rmSync(root, { recursive: true, force: true });
});

function pending(store: ApprovalStore) {
  return createPendingApproval(store, {
    scenarioId: null,
    intent: { ...scenario.intent, task: `${scenario.intent.task} ${CANARY}` },
    action: scenario.action,
    untrustedContent: scenario.untrustedContent,
    evaluation,
    agentId: "writer",
    requestedBy: { kind: "agent", credentialId: "0123456789abcdef" },
    credentialKeyId: "0123456789abcdef",
  });
}

function event(seq: number, approvalId?: string): ActivityEvent {
  return {
    id: `evt-${seq}`,
    timestamp: new Date(T + seq * 1000).toISOString(),
    scenarioId: null,
    intentTask: `${CANARY} ${seq}`,
    actionType: "create_summary",
    tool: "t",
    destination: "d",
    decision: "CONFIRM",
    riskScore: 50,
    findings: [],
    explanation: "e",
    ...(approvalId ? { approvalId, lifecycle: "PENDING_CONFIRMATION" as const } : {}),
  };
}

const writer = testSigningKey("writer", "e14-ops-writer", { now: T });

/** Populates every store as a stopped API would leave it: apr-1 pending, apr-2 rejected, apr-3 pending. */
function populate(): void {
  const audit = openFileAuditLog(paths.auditLog);
  const approvals = openDurableApprovalStore({ path: paths.approvals });
  for (let i = 1; i <= 3; i += 1) {
    const a = pending(approvals);
    audit.append(event(i, a.id));
  }
  processRejection(approvals, "apr-2");
  approvals.close();
  audit.close();
  const idem = createIdempotencyStore({ path: paths.idempotency, now });
  idem.begin("writer", "idem-key-0000000001", "a".repeat(64), T);
  idem.complete("writer", "idem-key-0000000001", { status: 200, body: { evaluation: { decision: "ALLOW" } } });
  idem.close();
  const replay = openDurableNonceCache({ path: paths.replay, now, skewMs: 30_000 });
  replay.checkAndInsert(writer.keyId, "nonce-00000000000000001", T + 30_000, T);
  replay.close();
  writeFileSync(paths.credentials, serializeCredentialDocument([writer.record]));
}

const backupDir = () => join(root, `backup-${Math.random().toString(16).slice(2)}`);
const lines = (out: string[]) => out.join("\n");
function cli(args: string[]) {
  const out: string[] = [];
  const err: string[] = [];
  const code = runOpsCli(args, { env: {}, now, out: (l) => out.push(l), err: (l) => err.push(l), paths });
  return { code, out: lines(out), err: lines(err) };
}

describe("M3-E E14: offline backup", () => {
  it("copies every present store with its size and SHA-256, writes the manifest last, and restricts the files", () => {
    populate();
    const dir = backupDir();
    const result = backupStores(paths, dir, { env: {}, now });
    expect(result.manifest.stores.map((s) => [s.kind, s.present, s.status])).toEqual([
      ["audit-log", true, "verified"],
      ["approval-store", true, "verified"],
      ["idempotency-store", true, "verified"],
      ["replay-store", true, "verified"],
      ["credential-store", true, "verified"],
    ]);
    // Replay and idempotency state is backed up for investigation, never restorable.
    expect(result.manifest.stores.filter((s) => s.restorable).map((s) => s.kind)).toEqual(["audit-log", "approval-store", "credential-store"]);
    expect(readFileSync(join(dir, "approvals.journal"))).toEqual(readFileSync(paths.approvals));
    const manifestText = readFileSync(join(dir, MANIFEST_NAME), "utf8");
    expect(manifestText).not.toContain(state); // no absolute paths in the manifest
    expect(manifestText).not.toContain(CANARY);
    for (const name of readdirSync(dir)) expect(isRestrictedToCurrentUser(join(dir, name))).toBe(true);
    // The directory itself: the current user only, inherited by what is created in it.
    if (process.platform === "win32") expect(windowsAclEntries(dir)).toEqual([expect.stringMatching(/:\(OI\)\(CI\)\(F\)$/)]);
    // Every lock was released.
    expect(readdirSync(state).filter((n) => n.endsWith(".lock"))).toEqual([]);
  });

  it("lists missing stores as not present, and never writes into an existing directory", () => {
    const audit = openFileAuditLog(paths.auditLog);
    audit.append(event(1));
    audit.close();
    const dir = backupDir();
    const result = backupStores(paths, dir, { env: {}, now });
    expect(result.manifest.stores.filter((s) => !s.present).map((s) => s.kind)).toEqual(["approval-store", "idempotency-store", "replay-store", "credential-store"]);
    expect(() => backupStores(paths, dir, { env: {}, now })).toThrow(/already exists/);
    expect(() => backupStores(paths, "relative/dir", { env: {}, now })).toThrow(/absolute/);
  });

  it("refuses while the API is running (a store's lock is held), and leaves nothing behind", () => {
    populate();
    const live = openDurableApprovalStore({ path: paths.approvals });
    try {
      const dir = backupDir();
      expect(() => backupStores(paths, dir, { env: {}, now })).toThrow(/Stop the AgentShield API first/);
      expect(existsSync(dir)).toBe(false);
      // The tool released the locks it had taken before the refusal; the running store keeps its own.
      expect(existsSync(`${paths.auditLog}.lock`)).toBe(false);
      expect(existsSync(`${paths.approvals}.lock`)).toBe(true);
    } finally {
      live.close();
    }
  });

  it("refuses while a credential command holds the credential store's lock", () => {
    populate();
    writeFileSync(`${paths.credentials}.lock`, "");
    expect(() => backupStores(paths, backupDir(), { env: {}, now })).toThrow(/credential command is running/);
  });

  it("copies a damaged store as found, but marks it not restorable", () => {
    populate();
    const text = readFileSync(paths.approvals, "utf8").replace(`"apr-3"`, `"apr-9"`);
    writeFileSync(paths.approvals, text);
    const result = backupStores(paths, backupDir(), { env: {}, now });
    const entry = result.manifest.stores.find((s) => s.kind === "approval-store")!;
    expect(entry).toMatchObject({ present: true, status: "damaged", restorable: false });
  });
});

describe("M3-E E14: backup verification", () => {
  function goodBackup(): string {
    populate();
    const dir = backupDir();
    backupStores(paths, dir, { env: {}, now });
    return dir;
  }

  it("accepts a complete backup and trial-opens the approval journal with the real store", () => {
    const v = verifyBackup(goodBackup(), { now });
    expect(v.ok).toBe(true);
    expect(v.stores.find((s) => s.kind === "approval-store")).toMatchObject({ status: "verified", records: 4, pending: 2, restorable: true });
  });

  it("detects an incomplete backup (no manifest: the backup never finished)", () => {
    const dir = goodBackup();
    rmSync(join(dir, MANIFEST_NAME));
    const v = verifyBackup(dir, { now });
    expect(v.ok).toBe(false);
    expect(v.problems.join(" ")).toMatch(/incomplete/);
  });

  it("detects a truncated, modified or missing store copy", () => {
    const dir = goodBackup();
    const file = join(dir, "audit-events.jsonl");
    writeFileSync(file, readFileSync(file).subarray(0, 100));
    rmSync(join(dir, "approvals.journal"));
    const v = verifyBackup(dir, { now });
    expect(v.ok).toBe(false);
    expect(v.problems.join("\n")).toMatch(/audit-events\.jsonl does not match the manifest/);
    expect(v.problems.join("\n")).toMatch(/approvals\.journal is missing or unreadable/);
  });

  it("rejects a manifest from a newer backup format, and a manifest naming any other file", () => {
    const dir = goodBackup();
    const manifest = JSON.parse(readFileSync(join(dir, MANIFEST_NAME), "utf8"));
    writeFileSync(join(dir, MANIFEST_NAME), JSON.stringify({ ...manifest, version: 2 }));
    expect(verifyBackup(dir, { now }).problems.join(" ")).toMatch(/newer than this AgentShield supports/);
    manifest.stores[0].file = "../escape.jsonl";
    writeFileSync(join(dir, MANIFEST_NAME), JSON.stringify(manifest));
    expect(verifyBackup(dir, { now }).problems.join(" ")).toMatch(/invalid store entry/);
  });

  it("reports a store copy written by a newer AgentShield as not restorable", () => {
    const dir = goodBackup();
    const file = join(dir, "approvals.journal");
    const record = JSON.stringify({ v: 2, t: "future" });
    const content = `${record}\t${chainValue(journalGenesis("approval store"), record)}\n`;
    writeFileSync(file, content);
    const manifest = JSON.parse(readFileSync(join(dir, MANIFEST_NAME), "utf8"));
    const entry = manifest.stores.find((s: { kind: string }) => s.kind === "approval-store");
    Object.assign(entry, { bytes: Buffer.byteLength(content), sha256: createHash("sha256").update(content).digest("hex") });
    writeFileSync(join(dir, MANIFEST_NAME), JSON.stringify(manifest));
    const v = verifyBackup(dir, { now });
    expect(v.stores.find((s) => s.kind === "approval-store")).toMatchObject({ status: "unsupported-version", restorable: false });
    expect(v.problems.join(" ")).toMatch(/newer AgentShield/);
  });
});

describe("M3-E E14: restore never replaces newer state", () => {
  it("keeps every present, healthy store: nothing is written", () => {
    populate();
    const dir = backupDir();
    backupStores(paths, dir, { env: {}, now });
    const before = Object.fromEntries(Object.entries(paths).map(([k, p]) => [k, readFileSync(p)]));
    // More activity after the backup: the current state is newer.
    const approvals = openDurableApprovalStore({ path: paths.approvals });
    processRejection(approvals, "apr-1");
    approvals.close();
    const afterActivity = readFileSync(paths.approvals);
    const result = restoreStores(paths, dir, { env: {}, now, restoreCredentials: true });
    expect(result.plan.every((p) => p.action === "keep")).toBe(true);
    expect(readFileSync(paths.approvals)).toEqual(afterActivity);
    expect(readFileSync(paths.replay)).toEqual(before.replay);
    expect(readFileSync(paths.credentials)).toEqual(before.credentials);
  });

  it("refuses to replace a damaged store unless asked; with --replace-damaged it copies the damaged one aside first", () => {
    populate();
    const dir = backupDir();
    backupStores(paths, dir, { env: {}, now });
    const damaged = readFileSync(paths.approvals, "utf8").replace(`"apr-3"`, `"apr-8"`);
    writeFileSync(paths.approvals, damaged);
    expect(() => restoreStores(paths, dir, { env: {}, now })).toThrow(/--replace-damaged/);
    expect(readFileSync(paths.approvals, "utf8")).toBe(damaged); // nothing written
    expect(readdirSync(state).some((n) => n.endsWith(".restoring"))).toBe(false);
    const result = restoreStores(paths, dir, { env: {}, now, replaceDamaged: true });
    expect(result.plan.find((p) => p.kind === "approval-store")?.action).toBe("replace-damaged");
    expect(result.preserved).toHaveLength(1);
    expect(readFileSync(result.preserved[0]!, "utf8")).toBe(damaged);
    expect(isRestrictedToCurrentUser(result.preserved[0]!)).toBe(true);
    // apr-8 was named by the damaged file: ids continue after it.
    expect(result.nextApprovalId).toBe(9);
  });

  it("refuses while the API is running", () => {
    populate();
    const dir = backupDir();
    backupStores(paths, dir, { env: {}, now });
    rmSync(paths.approvals);
    const live = openFileAuditLog(paths.auditLog);
    try {
      expect(() => restoreStores(paths, dir, { env: {}, now })).toThrow(/Stop the AgentShield API first/);
      expect(existsSync(paths.approvals)).toBe(false);
    } finally {
      live.close();
    }
  });

  it("refuses a corrupted backup before writing anything", () => {
    populate();
    const dir = backupDir();
    backupStores(paths, dir, { env: {}, now });
    rmSync(paths.approvals);
    const copy = join(dir, "approvals.journal");
    writeFileSync(copy, readFileSync(copy, "utf8").replace("PENDING", "EXECUTED"));
    expect(() => restoreStores(paths, dir, { env: {}, now })).toThrow(/failed verification/);
    expect(existsSync(paths.approvals)).toBe(false);
    expect(readdirSync(state).some((n) => n.endsWith(".restoring"))).toBe(false);
  });
});

describe("M3-E E14: restoring lost stores", () => {
  it("approvals: pending ones come back OUTCOME_UNKNOWN (never executable), decided ones keep their decision, ids are never reused", () => {
    populate();
    const dir = backupDir();
    backupStores(paths, dir, { env: {}, now });
    // After the backup: apr-4 is created (only the audit log survives to show it), then the journal is lost.
    const audit = openFileAuditLog(paths.auditLog);
    audit.append(event(4, "apr-4"));
    audit.close();
    rmSync(paths.approvals);

    const result = restoreStores(paths, dir, { env: {}, now });
    expect(result.plan.find((p) => p.kind === "approval-store")).toMatchObject({ action: "restore" });
    expect(result.nextApprovalId).toBe(5); // after apr-4, which only the audit log names

    const store = openDurableApprovalStore({ path: paths.approvals });
    try {
      expect(store.recovery).toMatchObject({ restored: 2, corrupt: 0, unverified: 0 });
      expect(store.records.get("apr-1")?.status).toBe("OUTCOME_UNKNOWN");
      expect(store.records.get("apr-3")?.status).toBe("OUTCOME_UNKNOWN");
      expect(store.records.get("apr-2")?.status).toBe("REJECTED");
      const reevaluate = vi.fn(() => evaluation);
      const simulator = createSimulator();
      expect(processApproval(store, "apr-1", reevaluate, simulator).kind).toBe("already-final");
      expect(reevaluate).not.toHaveBeenCalled();
      expect(simulator.invocationCount).toBe(0);
      expect(pending(store).id).toBe("apr-5");
    } finally {
      store.close();
    }
    // A second restart: stable, nothing more is quarantined, the marker was compacted away.
    const again = openDurableApprovalStore({ path: paths.approvals });
    try {
      expect(again.recovery).toMatchObject({ restored: 0, quarantined: 0, corrupt: 0 });
      expect(again.records.get("apr-5")?.status).toBe("PENDING");
      expect(readFileSync(paths.approvals, "utf8")).not.toContain(`"t":"restored"`);
    } finally {
      again.close();
    }
  });

  it("audit log: restored as backed up, verified, and new ids continue after it", () => {
    populate();
    const dir = backupDir();
    backupStores(paths, dir, { env: {}, now });
    rmSync(paths.auditLog);
    restoreStores(paths, dir, { env: {}, now });
    const log = openFileAuditLog(paths.auditLog);
    try {
      expect(log.recovery).toMatchObject({ records: 3, unverified: 0, malformed: 0 });
      expect(log.nextSequence).toBe(4);
    } finally {
      log.close();
    }
  });

  it("replay protection is never restored: a lost replay journal stays missing and the next start applies the fence", () => {
    populate();
    const dir = backupDir();
    backupStores(paths, dir, { env: {}, now });
    rmSync(paths.replay);
    rmSync(paths.approvals);
    const result = restoreStores(paths, dir, { env: {}, now });
    expect(result.plan.find((p) => p.kind === "replay-store")?.action).toBe("keep");
    expect(existsSync(paths.replay)).toBe(false);
    const later = T + 60_000;
    const replay = openDurableNonceCache({ path: paths.replay, now: () => later, skewMs: 30_000 });
    try {
      expect(replay.recoveringUntil).toBe(later + 30_000);
      expect(replay.checkAndInsert(writer.keyId, "nonce-00000000000000002", later + 30_000, later)).toBe("accepted");
    } finally {
      replay.close();
    }
  });

  it("idempotency records are never restored: a lost journal is recreated with a recovery window, so no key is evaluated twice", () => {
    populate();
    const dir = backupDir();
    backupStores(paths, dir, { env: {}, now });
    rmSync(paths.idempotency);
    const result = restoreStores(paths, dir, { env: {}, now });
    expect(result.plan.find((p) => p.kind === "idempotency-store")?.action).toBe("create-recovery-window");
    const store = createIdempotencyStore({ path: paths.idempotency, now: () => T + 1000 });
    try {
      expect(store.recovery?.recoveringUntil).toBe(T + 15 * 60 * 1000);
      // The key used before the backup is not replayed from the backup, and is not evaluated as new.
      expect(store.begin("writer", "idem-key-0000000001", "a".repeat(64), T + 1000).kind).toBe("unavailable");
      expect(store.begin("writer", "idem-key-0000000099", "b".repeat(64), T + 1000).kind).toBe("unavailable");
      expect(store.begin("writer", "idem-key-0000000099", "b".repeat(64), T + 15 * 60 * 1000 + 1).kind).toBe("new");
    } finally {
      store.close();
    }
  });

  it("credentials: restored only when missing and asked; a present store keeps its later revocations", () => {
    populate();
    const dir = backupDir();
    backupStores(paths, dir, { env: {}, now });
    // A revocation after the backup.
    writeFileSync(paths.credentials, serializeCredentialDocument([{ ...writer.record, revokedAt: new Date(T + 1000).toISOString() }]));
    restoreStores(paths, dir, { env: {}, now, restoreCredentials: true });
    expect(readCredentialFile(paths.credentials, T)[0]!.revokedAt).not.toBeNull(); // kept: never replaced
    rmSync(paths.credentials);
    const skipped = restoreStores(paths, dir, { env: {}, now });
    expect(skipped.plan.find((p) => p.kind === "credential-store")?.action).toBe("skip");
    expect(existsSync(paths.credentials)).toBe(false);
    restoreStores(paths, dir, { env: {}, now, restoreCredentials: true });
    expect(readCredentialFile(paths.credentials, T).map((r) => r.keyId)).toEqual([writer.keyId]);
    expect(isRestrictedToCurrentUser(paths.credentials)).toBe(true);
  });
});

describe("M3-E E14: an interrupted restore", () => {
  it("blocks the API from opening the stores until the same restore is run again", () => {
    populate();
    const dir = backupDir();
    backupStores(paths, dir, { env: {}, now });
    rmSync(paths.auditLog);
    rmSync(paths.approvals);
    rmSync(paths.idempotency);
    // A crash right after the audit log was written.
    expect(() =>
      restoreStores(paths, dir, {
        env: {},
        now,
        hooks: {
          afterStep: (step) => {
            if (step === "restored:audit-log") throw new Error("simulated crash");
          },
        },
      }),
    ).toThrow("simulated crash");
    expect(readdirSync(state).filter((n) => n.endsWith(".restoring")).sort()).toEqual(["approvals.journal.restoring", "audit-events.jsonl.restoring", "idempotency.journal.restoring"]);
    // The API refuses to start, rather than creating an empty approval journal (and reusing ids).
    expect(() => openFileAuditLog(paths.auditLog)).toThrow(/restore of the audit log was interrupted/);
    expect(() => openDurableApprovalStore({ path: paths.approvals })).toThrow(/restore of the approval store was interrupted/);
    expect(() => createIdempotencyStore({ path: paths.idempotency })).toThrow(/interrupted/);
    expect(existsSync(paths.approvals)).toBe(false);
    // A backup refuses too, and so does a restore from a different backup.
    expect(() => backupStores(paths, backupDir(), { env: {}, now })).toThrow(/interrupted/);
    const other = backupDir();
    const manifest = JSON.parse(readFileSync(join(dir, MANIFEST_NAME), "utf8"));
    rmSync(other, { recursive: true, force: true });
    cpSync(dir, other, { recursive: true });
    writeFileSync(join(other, MANIFEST_NAME), JSON.stringify({ ...manifest, id: "ffffffffffffffff" }));
    expect(() => restoreStores(paths, other, { env: {}, now })).toThrow(/different backup/);
    // Running the same restore again completes it.
    const resumed = restoreStores(paths, dir, { env: {}, now });
    expect(resumed.plan.filter((p) => p.action !== "keep").map((p) => [p.kind, p.action])).toEqual([
      ["audit-log", "restore"],
      ["approval-store", "restore"],
      ["idempotency-store", "create-recovery-window"],
    ]);
    expect(readdirSync(state).some((n) => n.endsWith(".restoring"))).toBe(false);
    const audit = openFileAuditLog(paths.auditLog);
    const approvals = openDurableApprovalStore({ path: paths.approvals });
    try {
      expect(audit.recovery.records).toBe(3);
      expect(approvals.recovery).toMatchObject({ restored: 2, corrupt: 0 });
    } finally {
      approvals.close();
      audit.close();
    }
  });
});

describe("M3-E E14: the ops CLI", () => {
  it("M3-E E15: status on a fresh installation (no store yet) is ok; a store lost while others hold records needs attention", () => {
    expect(cli(["status"]).code).toBe(0);
    populate();
    rmSync(paths.idempotency);
    const lost = cli(["status"]);
    expect(lost.code).toBe(1);
    expect(lost.out).toMatch(/idempotency-store status=missing[\s\S]*missing while other stores hold records/);
  });

  it("status is read-only, shows sizes, locks and integrity, and never a record", () => {
    populate();
    const before = readFileSync(paths.approvals);
    const { code, out } = cli(["status"]);
    expect(code).toBe(0);
    expect(out).toMatch(/approval-store status=verified bytes=\d+ maxBytes=268435456/);
    expect(out).toMatch(/audit-log status=verified .* lock=free/);
    expect(out).not.toContain(CANARY);
    expect(readFileSync(paths.approvals)).toEqual(before);
  });

  it("status reports a running store's lock, damage and an interrupted restore as needing attention", () => {
    populate();
    const live = openDurableNonceCache({ path: paths.replay, now, skewMs: 30_000 });
    writeFileSync(paths.approvals, readFileSync(paths.approvals, "utf8").replace(`"apr-3"`, `"apr-7"`));
    writeFileSync(`${paths.auditLog}.restoring`, "{}");
    try {
      const { code, out } = cli(["status"]);
      expect(code).toBe(1);
      expect(out).toContain(`replay-store status=verified`);
      expect(out).toContain(`lock=held-by-pid-${process.pid}`);
      expect(out).toMatch(/approval-store status=damaged .*details=unverified=\d/);
      expect(out).toMatch(/audit-log status=verified .*restore=interrupted/);
      expect(out).toContain("ATTENTION");
    } finally {
      live.close();
    }
  });

  it("backup, verify-backup and restore print counts and codes only", () => {
    populate();
    const dir = backupDir();
    const backup = cli(["backup", "--out", dir]);
    expect(backup.code).toBe(0);
    expect(backup.out).toMatch(/backup complete: id=[0-9a-f]{16}/);
    const verify = cli(["verify-backup", "--dir", dir]);
    expect(verify.code).toBe(0);
    expect(verify.out).toContain("approval-store status=verified records=4 pending=2 restorable=yes");
    rmSync(paths.approvals);
    const restore = cli(["restore", "--dir", dir]);
    expect(restore.code).toBe(0);
    expect(restore.out).toContain("Approval ids continue at apr-4.");
    for (const text of [backup.out, verify.out, restore.out]) expect(text).not.toContain(CANARY);
    expect(cli(["restore"]).code).toBe(2);
    expect(cli(["nonsense"]).code).toBe(2);
  });

  it("a failed operation exits 1 with a reason and changes nothing", () => {
    populate();
    const live = openFileAuditLog(paths.auditLog);
    try {
      const result = cli(["backup", "--out", backupDir()]);
      expect(result.code).toBe(1);
      expect(result.err).toMatch(/Stop the AgentShield API first/);
    } finally {
      live.close();
    }
    expect(() => {
      throw new OpsError("x");
    }).toThrow(OpsError);
  });
});

describe("M3-E E14: storage status sizes", () => {
  it("reports usage against each store's limit", () => {
    populate();
    const status = storageStatus(paths, { env: { AUDIT_LOG_MAX_BYTES: String(1024 * 1024) }, now });
    const audit = status.find((s) => s.kind === "audit-log")!;
    expect(audit.maxBytes).toBe(1024 * 1024);
    expect(audit.usedPercent).toBeGreaterThan(0);
    expect(status.find((s) => s.kind === "credential-store")).toMatchObject({ status: "verified", records: 1 });
  });
});

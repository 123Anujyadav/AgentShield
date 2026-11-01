import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { ActivityEvent } from "@agentshield/engine";
import { isRestrictedToCurrentUser } from "../agents/file-security.js";
import {
  AuditConfigError,
  auditLogMaxBytesFromEnv,
  auditLogPathFromEnv,
  AuditWriteError,
  DEFAULT_AUDIT_LOG_MAX_BYTES,
  openFileAuditLog,
  parseAuditRecord,
  serializeAuditRecord,
  type AuditFileIo,
  type AuditLog,
} from "./file-audit-log.js";

/** M3-E E10: the durable audit log on its own. Temporary directories only. */

let dir: string;
let path: string;
const open: AuditLog[] = [];
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "agentshield-audit-test-"));
  path = join(dir, "audit-events.jsonl");
});
afterEach(() => {
  for (const log of open.splice(0)) log.close();
  try {
    chmodSync(path, 0o600);
  } catch {
    // not created
  }
  rmSync(dir, { recursive: true, force: true });
});

const openLog = (...args: Parameters<typeof openFileAuditLog> extends [string, ...infer R] ? R : never) => {
  const log = openFileAuditLog(path, ...args);
  open.push(log);
  return log;
};
const reopen = (log: AuditLog, ...args: Parameters<typeof openLog>) => {
  log.close();
  return openLog(...args);
};

function event(seq: number, extra: Partial<ActivityEvent> = {}): ActivityEvent {
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
    lifecycle: "SIMULATED_EXECUTED",
    agentId: "writer",
    agentPolicy: null,
    actor: { kind: "agent", credentialId: "0123456789abcdef" },
    ...extra,
  };
}

const lines = () => readFileSync(path, "utf8").split("\n").filter((l) => l.length > 0);

describe("M3-E E10: appending and recovering", () => {
  it("creates the file restricted to the current user and appends one checksummed JSON line per event", () => {
    const log = openLog();
    expect(log.recovery).toMatchObject({ records: 0, malformed: 0, truncatedTail: false, permissionsRestricted: true, bytes: 0, maxBytes: DEFAULT_AUDIT_LOG_MAX_BYTES });
    expect(log.nextSequence).toBe(1);
    if (process.platform === "win32") expect(isRestrictedToCurrentUser(path)).toBe(true);
    else expect(statSync(path).mode & 0o077).toBe(0);
    log.append(event(1));
    log.append(event(2));
    expect(log.nextSequence).toBe(3);
    const stored = lines();
    expect(stored).toHaveLength(2);
    expect(stored[0]).toMatch(/^\{"v":1,"seq":1,"sha256":"[0-9a-f]{64}","event":\{"id":"evt-1",/);
    expect(parseAuditRecord(stored[1]!)).toEqual({ seq: 2, event: event(2) });
    expect(readFileSync(path, "utf8").endsWith("\n")).toBe(true);
  });

  it("events survive a restart, in order, and ids continue after the stored ones", () => {
    let log = openLog();
    for (let seq = 1; seq <= 5; seq += 1) log.append(event(seq));
    log = reopen(log);
    expect(log.loaded.map((e) => e.id)).toEqual(["evt-1", "evt-2", "evt-3", "evt-4", "evt-5"]);
    expect(log.loaded[2]).toEqual(event(3));
    expect(log.nextSequence).toBe(6);
    expect(() => log.append(event(5))).toThrow(AuditWriteError); // an id never repeats
    log.append(event(6));
    expect(reopen(log).loaded.map((e) => e.id).at(-1)).toBe("evt-6");
  });

  it("a truncated final record (a crash mid-write) is kept but terminated; later records load normally", () => {
    let log = openLog();
    log.append(event(1));
    log.close();
    const partial = serializeAuditRecord(event(2)).slice(0, 60);
    writeFileSync(path, readFileSync(path, "utf8") + partial);
    log = openLog();
    expect(log.recovery).toMatchObject({ records: 1, malformed: 1, malformedLines: [2], truncatedTail: true });
    expect(readFileSync(path, "utf8").endsWith(`${partial}\n`)).toBe(true); // nothing deleted
    expect(log.nextSequence).toBe(3); // seq 2 was seen in the partial record: never reused
    log.append(event(3));
    const again = reopen(log);
    expect(again.loaded.map((e) => e.id)).toEqual(["evt-1", "evt-3"]);
    expect(again.recovery).toMatchObject({ malformed: 1, truncatedTail: false });
  });

  it("malformed and corrupted records are skipped and counted by line number; valid ones still load", () => {
    const good1 = serializeAuditRecord(event(1));
    const good4 = serializeAuditRecord(event(4));
    const tampered = serializeAuditRecord(event(2)).replace('"Task 2"', '"Task X"'); // checksum no longer matches
    const wrongId = serializeAuditRecord(event(3)).replace('"seq":3', '"seq":30');
    const content = [good1, "not json\n", tampered, wrongId, '{"v":2,"seq":5}\n', "\n", good4].join("");
    writeFileSync(path, content);
    const log = openLog();
    expect(log.loaded.map((e) => e.id)).toEqual(["evt-1", "evt-4"]);
    expect(log.recovery).toMatchObject({ records: 2, malformed: 5, malformedLines: [2, 3, 4, 5, 6], duplicates: 0 });
    expect(log.nextSequence).toBe(31); // after the highest sequence seen, even in a skipped line
    expect(readFileSync(path, "utf8")).toBe(content); // never rewritten
  });

  it("duplicate or out-of-order records are skipped (first one wins) and counted", () => {
    writeFileSync(path, [event(1), event(2), event(2, { intentTask: "dup" }), event(1), event(3)].map(serializeAuditRecord).join(""));
    const log = openLog();
    expect(log.loaded.map((e) => [e.id, e.intentTask])).toEqual([
      ["evt-1", "Task 1"],
      ["evt-2", "Task 2"],
      ["evt-3", "Task 3"],
    ]);
    expect(log.recovery.duplicates).toBe(2);
  });

  it("field content cannot break a line or forge a record (log injection)", () => {
    const sneaky = 'x"}\n{"v":1,"seq":99,"sha256":"' + "0".repeat(64) + '","event":{}}\r\u2028\u0000';
    let log = openLog();
    log.append(event(1, { intentTask: sneaky, explanation: "line1\nline2" }));
    expect(lines()).toHaveLength(1);
    log = reopen(log);
    expect(log.loaded).toEqual([event(1, { intentTask: sneaky, explanation: "line1\nline2" })]);
    expect(log.recovery.malformed).toBe(0);
  });
});

describe("M3-E E10: failures never pass for durable writes", () => {
  function failingIo(fail: { write?: (call: number) => NodeJS.ErrnoException | "partial" | null; fsync?: () => NodeJS.ErrnoException | null }): AuditFileIo {
    let calls = 0;
    return {
      writeSync: (fd, buffer, offset, length) => {
        calls += 1;
        const outcome = fail.write?.(calls) ?? null;
        if (outcome === "partial") {
          // Half the record reaches the disk, then the device fails.
          const half = Math.floor(length / 2);
          const written = require_writeSync(fd, buffer, offset, half);
          fail.write = () => Object.assign(new Error("disk full"), { code: "ENOSPC" });
          return written;
        }
        if (outcome) throw outcome;
        return require_writeSync(fd, buffer, offset, length);
      },
      fsyncSync: (fd) => {
        const error = fail.fsync?.() ?? null;
        if (error) throw error;
        require_fsyncSync(fd);
      },
    };
  }

  it("a disk-full write fails with AuditWriteError, the store refuses further appends, and nothing partial is reported as stored", () => {
    let fail = false;
    const log = openLog({ io: failingIo({ write: () => (fail ? Object.assign(new Error("no space"), { code: "ENOSPC" }) : null) }) });
    log.append(event(1));
    fail = true;
    expect(() => log.append(event(2))).toThrow(expect.objectContaining({ name: "AuditWriteError", code: "ENOSPC" }));
    expect(log.readiness()).toEqual({ ok: false, reason: "audit-unavailable" });
    fail = false;
    expect(() => log.append(event(3))).toThrow(expect.objectContaining({ code: "unavailable" }));
    expect(reopen(log).loaded.map((e) => e.id)).toEqual(["evt-1"]);
  });

  it("a partly written record leaves the store failed; after a restart the partial line is terminated and skipped", () => {
    const log = openLog({ io: failingIo({ write: (call) => (call === 2 ? "partial" : null) }) });
    log.append(event(1));
    expect(() => log.append(event(2))).toThrow(AuditWriteError);
    expect(() => log.append(event(3))).toThrow(AuditWriteError);
    const again = reopen(log);
    expect(again.loaded.map((e) => e.id)).toEqual(["evt-1"]);
    expect(again.recovery).toMatchObject({ truncatedTail: true, malformed: 1 });
    again.append(event(3));
    expect(reopen(again).loaded.map((e) => e.id)).toEqual(["evt-1", "evt-3"]);
  });

  it("an fsync failure is a failed write too (written but not known to be durable)", () => {
    const log = openLog({ io: failingIo({ fsync: () => Object.assign(new Error("io"), { code: "EIO" }) }) });
    expect(() => log.append(event(1))).toThrow(expect.objectContaining({ code: "EIO" }));
    expect(log.readiness()).toEqual({ ok: false, reason: "audit-unavailable" });
  });

  it("a file that cannot be opened for writing (read-only) stops start-up", () => {
    openLog().close();
    open.length = 0;
    chmodSync(path, 0o444);
    expect(() => openFileAuditLog(path)).toThrow(AuditConfigError);
    expect(() => openFileAuditLog(path)).toThrow("The audit log cannot be opened for appending (check its permissions).");
    expect(existsSync(`${path}.lock`)).toBe(false); // the lock is released on failure
  });

  it("the storage limit: full before it would be exceeded, old events are never dropped, the file never grows past it", () => {
    const record = Buffer.byteLength(serializeAuditRecord(event(1)));
    const log = openLog({ maxBytes: record * 3 + 10, maxRecordBytes: record + 5 });
    log.append(event(1));
    log.append(event(2));
    expect(log.readiness()).toEqual({ ok: true });
    log.append(event(3));
    expect(log.readiness()).toEqual({ ok: false, reason: "audit-storage-full" });
    expect(() => log.append(event(4))).toThrow(expect.objectContaining({ code: "storage-full" }));
    expect(statSync(path).size).toBeLessThanOrEqual(record * 3 + 10);
    expect(reopen(log, { maxBytes: record * 3 + 10, maxRecordBytes: record + 5 }).loaded.map((e) => e.id)).toEqual(["evt-1", "evt-2", "evt-3"]);
  });

  it("a file over the limit stops start-up; an oversized record is refused without failing the store", () => {
    writeFileSync(path, "x".repeat(2048));
    expect(() => openFileAuditLog(path, { maxBytes: 1024, maxRecordBytes: 512 })).toThrow(/larger than its limit/);
    rmSync(path);
    const log = openLog({ maxRecordBytes: 800 });
    expect(() => log.append(event(1, { explanation: "y".repeat(1000) }))).toThrow(expect.objectContaining({ code: "record-too-large" }));
    expect(log.readiness()).toEqual({ ok: true });
    log.append(event(2));
  });
});

describe("M3-E E10: file and path safety", () => {
  it("refuses a relative path, a directory, and a symbolic link or junction (not followed)", () => {
    expect(() => openFileAuditLog("audit-events.jsonl")).toThrow("AUDIT_LOG_FILE must be an absolute path.");
    mkdirSync(path);
    expect(() => openFileAuditLog(path)).toThrow("The audit log path is not a regular file.");
    rmSync(path, { recursive: true });
    const target = join(dir, "elsewhere");
    mkdirSync(target);
    symlinkSync(target, path, "junction");
    expect(() => openFileAuditLog(path)).toThrow("The audit log path is a symbolic link or junction; it is not followed.");
    expect(existsSync(`${path}.lock`)).toBe(false);
  });

  it("only one writer: a second open is refused while the first holds the lock; a stale lock from a dead process is replaced", () => {
    const first = openLog();
    expect(() => openFileAuditLog(path)).toThrow(/in use by another AgentShield API process/);
    first.close();
    writeFileSync(`${path}.lock`, "2147483646"); // no such process
    const second = openLog();
    expect(second.recovery.staleLockReplaced).toBe(true);
    expect(readFileSync(`${path}.lock`, "utf8")).toBe(String(process.pid));
    second.close();
    expect(existsSync(`${path}.lock`)).toBe(false);
  });

  it("configuration from the environment: absolute default under the profile, bounded size limit", () => {
    expect(auditLogPathFromEnv({ LOCALAPPDATA: "C:\\Users\\x\\AppData\\Local" })).toBe(join("C:\\Users\\x\\AppData\\Local", "AgentShield", "audit-events.jsonl"));
    expect(auditLogPathFromEnv({ AUDIT_LOG_FILE: "  D:\\audit\\events.jsonl " })).toBe("D:\\audit\\events.jsonl");
    expect(auditLogMaxBytesFromEnv({})).toBe(DEFAULT_AUDIT_LOG_MAX_BYTES);
    expect(auditLogMaxBytesFromEnv({ AUDIT_LOG_MAX_BYTES: "1048576" })).toBe(1048576);
    for (const bad of ["1048575", "1073741825", "64MB", "-1", "1e9"]) expect(() => auditLogMaxBytesFromEnv({ AUDIT_LOG_MAX_BYTES: bad })).toThrow(AuditConfigError);
  });
});

// Plain node:fs calls for the failing-io helper (kept apart so the helper reads clearly).
import { fsyncSync as require_fsyncSync, writeSync as require_writeSync } from "node:fs";

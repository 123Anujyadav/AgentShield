import { createHash } from "node:crypto";
import { closeSync, constants, fstatSync, fsyncSync, lstatSync, mkdirSync, openSync, readSync, writeSync, type Stats } from "node:fs";
import { dirname, isAbsolute, join } from "node:path";
import type { ActivityEvent } from "@agentshield/engine";
import { assertNoLinkedAncestors, FileSecurityError, isRestrictedToCurrentUser, namesAlternateDataStream, writeRestrictedFileAtomically } from "../agents/file-security.js";
import { acquireStoreLock, JournalConfigError, lockStillHeld, releaseStoreLock, restoreMarkerPresent, RESTORE_MARKER_SUFFIX } from "../storage/journal.js";
import type { StoreHealth } from "../storage/health.js";
import { defaultTokenDirectory } from "../security/token.js";

/**
 * Durable audit-event storage (M3-E E10): a local, append-only JSON Lines file for the
 * single-process API.
 *
 * File format: one record per line, UTF-8, each ending in LF:
 *
 *   {"v":1,"seq":<n>,"sha256":"<64 hex>","event":<ActivityEvent JSON>}
 *
 * - `seq` is 1, 2, 3, ... in write order and the event id is `evt-<seq>`, so ids continue
 *   across restarts and the file order is the event order.
 * - `sha256` is the SHA-256 of the exact `event` JSON text. It detects partial or corrupted
 *   records. It is NOT tamper protection: anyone who can write the file can recompute it.
 * - JSON escapes every control character, so no field can break a line or forge a record.
 *
 * Writes: each event is written with writeSync and flushed with fsync before append()
 * returns. A write that fails, or is only partly made, puts the store in a failed state:
 * nothing more is appended in this process (a partial line is never followed by another
 * record), and readiness() reports it so callers refuse state-changing operations.
 *
 * Limits: the file never grows beyond `maxBytes`. Old events are never dropped to make
 * room: when fewer than `maxRecordBytes` remain, readiness() reports the store full and the
 * operator must archive the file. A file already over the limit stops start-up.
 *
 * Recovery at start-up: complete, valid records are loaded in order. A final record without
 * its LF (a crash during a write) is terminated with an LF so it stays in the file as a
 * malformed line, and later records start on a line of their own. Malformed, corrupted,
 * duplicate or out-of-order lines are skipped and counted (their line numbers are reported,
 * never their content); nothing in the file is deleted or rewritten.
 *
 * File safety: the path must be absolute; a symbolic link or anything but a regular file is
 * refused; a new file is created restricted to the current user (Windows ACL / mode 0600)
 * before anything is written; the opened file is checked to be the one inspected. A lock
 * file next to the log (holding the process id) stops a second API process from appending
 * to it at the same time.
 *
 * M3-E E14: a record of a newer format version (v3 or later) stops start-up rather than being
 * skipped, and so does the marker of an interrupted restore. inspectAuditContent() reads a log's
 * content without opening it, for the backup, restore and status tools.
 */

export const AUDIT_LOG_FILE_NAME = "audit-events.jsonl";
export const AUDIT_RECORD_VERSION = 1;
export const DEFAULT_AUDIT_LOG_MAX_BYTES = 64 * 1024 * 1024;
export const MIN_AUDIT_LOG_MAX_BYTES = 1024 * 1024;
export const MAX_AUDIT_LOG_MAX_BYTES = 1024 * 1024 * 1024;
/** No single record may be larger; readiness keeps at least this much room. */
export const MAX_AUDIT_RECORD_BYTES = 256 * 1024;
/** At most this many malformed line numbers are reported. */
const MAX_REPORTED_LINES = 20;

/** The audit log cannot be used: start-up must stop (fail closed). Messages never contain file content. */
export class AuditConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AuditConfigError";
  }
}

/** An event was not durably written. `code` is a fixed reason (or a file-system error code). */
export class AuditWriteError extends Error {
  constructor(readonly code: string) {
    super(`The audit event could not be stored durably (${code}).`);
    this.name = "AuditWriteError";
  }
}

export type AuditReadiness = { ok: true } | { ok: false; reason: "audit-unavailable" | "audit-storage-full" };

export interface AuditRecovery {
  /** Valid records loaded. */
  records: number;
  /** Lines skipped because they are not valid records (including a terminated partial record). */
  malformed: number;
  /**
   * M3-E E13: records whose integrity chain (`prev`) does not match the previous record: modified,
   * inserted, reordered, or following a deleted record. Kept in the file, left out of the API view.
   */
  unverified: number;
  /** 1-based line numbers of the first unverified records. */
  unverifiedLines: number[];
  /** M3-E E13: the file holds pre-E13 (v1, unchained) records; new records are chained after them. */
  legacyRecords: number;
  /** 1-based line numbers of the first skipped lines. */
  malformedLines: number[];
  /** Valid-looking records skipped because their sequence number was not greater than the previous one. */
  duplicates: number;
  /** The file ended inside a record (a crash during a write); an LF was added after it. */
  truncatedTail: boolean;
  /** A lock left by a process that no longer runs was replaced. */
  staleLockReplaced: boolean;
  /** Whether the file is readable by the current user only (false: other accounts may have access). */
  permissionsRestricted: boolean;
  bytes: number;
  maxBytes: number;
  /** M3-E E14: the highest approval id (apr-N) any line names, so a lost approval journal never reuses an id. 0 if none. */
  highestApprovalId: number;
}

/** M3-E E14: what an audit log's content holds, read without opening (or locking) it. */
export interface AuditInspection {
  loaded: ActivityEvent[];
  records: number;
  malformed: number;
  malformedLines: number[];
  unverified: number;
  unverifiedLines: number[];
  legacyRecords: number;
  duplicates: number;
  truncatedTail: boolean;
  /** The highest sequence number seen anywhere, even in a skipped line. */
  highestSeq: number;
  highestApprovalId: number;
  /** The newest record version above 2 found (a newer AgentShield wrote it), or null. */
  unsupportedVersion: number | null;
  /** The hash the next record's `prev` must carry. */
  nextPrev: string;
}

export interface AuditLog {
  /** Events recovered at start-up, oldest first. */
  readonly loaded: readonly ActivityEvent[];
  /** The sequence number the next event must have (its id is `evt-<n>`). */
  readonly nextSequence: number;
  readonly recovery: AuditRecovery;
  /** Whether a state-changing operation may proceed: the store is healthy and has room for a record. */
  readiness(): AuditReadiness;
  /** Durably appends one event (id `evt-<n>`, n greater than every stored one). Throws AuditWriteError otherwise. */
  append(event: ActivityEvent): void;
  /** M3-E E14: capacity and health (numbers only). Optional so test doubles need not implement it. */
  health?(): StoreHealth;
  /** Closes the file and releases the lock. Idempotent. */
  close(): void;
}

/** File operations used for appends; replaceable in tests to simulate failures. */
export interface AuditFileIo {
  writeSync: (fd: number, buffer: Uint8Array, offset: number, length: number) => number;
  fsyncSync: (fd: number) => void;
}

const DEFAULT_IO: AuditFileIo = {
  writeSync: (fd, buffer, offset, length) => writeSync(fd, buffer, offset, length),
  fsyncSync: (fd) => fsyncSync(fd),
};

export interface AuditLogOptions {
  maxBytes?: number;
  maxRecordBytes?: number;
  io?: AuditFileIo;
}

/** AUDIT_LOG_FILE (an absolute path), else %LOCALAPPDATA%\AgentShield\audit-events.jsonl. */
export function auditLogPathFromEnv(env: NodeJS.ProcessEnv = process.env): string {
  const configured = env.AUDIT_LOG_FILE?.trim();
  return configured ? configured : join(defaultTokenDirectory(env), AUDIT_LOG_FILE_NAME);
}

/** AUDIT_LOG_MAX_BYTES: a whole number of bytes from 1 MiB to 1 GiB; unset or empty means 64 MiB. */
export function auditLogMaxBytesFromEnv(env: NodeJS.ProcessEnv = process.env): number {
  const raw = env.AUDIT_LOG_MAX_BYTES?.trim();
  if (!raw) return DEFAULT_AUDIT_LOG_MAX_BYTES;
  const value = /^\d{1,10}$/.test(raw) ? Number(raw) : Number.NaN;
  if (!Number.isSafeInteger(value) || value < MIN_AUDIT_LOG_MAX_BYTES || value > MAX_AUDIT_LOG_MAX_BYTES) {
    throw new AuditConfigError(`AUDIT_LOG_MAX_BYTES must be a whole number of bytes from ${MIN_AUDIT_LOG_MAX_BYTES} to ${MAX_AUDIT_LOG_MAX_BYTES}.`);
  }
  return value;
}

// The `s` flag matters: JSON.stringify leaves U+2028 and U+2029 unescaped, and without it `.` would not
// match them, so a record whose fields contain one would be unreadable after a restart (M3-E E10).
const RECORD = /^\{"v":1,"seq":([1-9][0-9]{0,14}),"sha256":"([0-9a-f]{64})","event":(\{.*\})\}$/s;
/**
 * M3-E E13: v2 adds `prev`, the SHA-256 of the previous valid record line (or of the genesis value), so a
 * modified, deleted, inserted or reordered record is detected. Corruption detection only: no key is
 * involved, so anyone able to rewrite the file can recompute it.
 */
const RECORD_V2 = /^\{"v":2,"seq":([1-9][0-9]{0,14}),"prev":"([0-9a-f]{64})","sha256":"([0-9a-f]{64})","event":(\{.*\})\}$/s;
export const AUDIT_CHAIN_GENESIS = createHash("sha256").update("agentshield-audit-v2 genesis", "utf8").digest("hex");
const EVENT_ID = /^evt-([1-9][0-9]{0,14})$/;
const DECISIONS = new Set(["ALLOW", "CONFIRM", "BLOCK"]);

const sha256 = (text: string) => createHash("sha256").update(text, "utf8").digest("hex");

/** The sequence number in an event id, or null. */
export function sequenceOf(id: unknown): number | null {
  const match = typeof id === "string" ? EVENT_ID.exec(id) : null;
  return match ? Number(match[1]) : null;
}

/** The line a pre-E13 (v1, unchained) log stored for an event. Kept for reading old logs and for tests. */
export function serializeAuditRecord(event: ActivityEvent): string {
  const seq = sequenceOf(event.id);
  if (seq === null) throw new AuditWriteError("invalid-event-id");
  const body = JSON.stringify(event);
  return `{"v":${AUDIT_RECORD_VERSION},"seq":${seq},"sha256":"${sha256(body)}","event":${body}}\n`;
}

/** M3-E E13: the line stored for an event, chained to the previous record line's hash. */
export function serializeChainedAuditRecord(event: ActivityEvent, prev: string): string {
  const seq = sequenceOf(event.id);
  if (seq === null) throw new AuditWriteError("invalid-event-id");
  const body = JSON.stringify(event);
  return `{"v":2,"seq":${seq},"prev":"${prev}","sha256":"${sha256(body)}","event":${body}}\n`;
}

/** The hash a following record's `prev` must carry for this line (the line without its LF). */
export function auditLineHash(line: string): string {
  return sha256(line);
}

/** Parses one line; null when it is not a complete, valid record. `prev` is null for a v1 (legacy) record. */
export function parseAuditRecord(line: string): { seq: number; event: ActivityEvent; prev: string | null } | null {
  const v2 = RECORD_V2.exec(line);
  const match = v2 ? [v2[0], v2[1], v2[3], v2[4]] : RECORD.exec(line);
  if (!match) return null;
  const prev = v2 ? v2[2]! : null;
  const [, seqText, digest, body] = match;
  if (sha256(body!) !== digest) return null;
  let event: unknown;
  try {
    event = JSON.parse(body!);
  } catch {
    return null;
  }
  if (typeof event !== "object" || event === null || Array.isArray(event)) return null;
  const e = event as Record<string, unknown>;
  const seq = Number(seqText);
  if (sequenceOf(e.id) !== seq) return null;
  if (typeof e.timestamp !== "string" || Number.isNaN(Date.parse(e.timestamp))) return null;
  if (typeof e.decision !== "string" || !DECISIONS.has(e.decision) || typeof e.riskScore !== "number" || !Array.isArray(e.findings)) return null;
  for (const field of ["intentTask", "actionType", "tool", "destination", "explanation"]) if (typeof e[field] !== "string") return null;
  return { seq, event: event as ActivityEvent, prev };
}

/**
 * Takes the single-writer lock next to the log (M3-E E14: the journals' implementation, which also never
 * follows a link when reading the process id). Its messages name the audit log.
 */
function acquireLock(lockPath: string): { staleReplaced: boolean } {
  try {
    return acquireStoreLock(lockPath, "audit log");
  } catch (error) {
    throw new AuditConfigError(error instanceof JournalConfigError ? error.message : "The audit log lock could not be taken.");
  }
}

const APPROVAL_REFERENCE = /"approvalId":"apr-([1-9][0-9]{0,8})"/;
const RECORD_VERSION = /^\{"v":([0-9]{1,9}),/;

/**
 * M3-E E14: parses and verifies an audit log's content without opening it. Pure. A final record without
 * its LF counts as malformed (openFileAuditLog then terminates its line).
 */
export function inspectAuditContent(content: Buffer, maxRecordBytes: number = MAX_AUDIT_RECORD_BYTES): AuditInspection {
  const loaded: ActivityEvent[] = [];
  const malformedLines: number[] = [];
  let malformed = 0;
  let duplicates = 0;
  let lastSeq = 0;
  let highestSeen = 0;
  let highestApprovalId = 0;
  let unsupportedVersion: number | null = null;
  const unverifiedLines: number[] = [];
  let unverified = 0;
  let legacyRecords = 0;
  let seenChained = false;
  // The hash the next record's `prev` must carry: the previous valid record line's, or the genesis value.
  let expectedPrev = AUDIT_CHAIN_GENESIS;
  const truncatedTail = content.length > 0 && content[content.length - 1] !== 0x0a;
  const lines = content.toString("utf8").split("\n");
  // After the final LF the split leaves an empty string; a non-empty last part is the partial record.
  const complete = truncatedTail ? lines : lines.slice(0, -1);
  complete.forEach((line, index) => {
    // Any line, even a damaged one, may name an issued approval id: reserving too many is safe.
    const approval = APPROVAL_REFERENCE.exec(line)?.[1];
    if (approval) highestApprovalId = Math.max(highestApprovalId, Number(approval));
    const version = Number(RECORD_VERSION.exec(line)?.[1] ?? 0);
    if (version > 2) unsupportedVersion = Math.max(unsupportedVersion ?? 0, version);
    const record = line.length > 0 && Buffer.byteLength(line, "utf8") < maxRecordBytes ? parseAuditRecord(line) : null;
    if (!record) {
      malformed += 1;
      if (malformedLines.length < MAX_REPORTED_LINES) malformedLines.push(index + 1);
      const seq = /^\{"v":[12],"seq":([1-9][0-9]{0,14}),/.exec(line)?.[1];
      if (seq) highestSeen = Math.max(highestSeen, Number(seq));
      return;
    }
    highestSeen = Math.max(highestSeen, record.seq);
    // M3-E E13: v1 records are accepted only before the first chained record; a chained record must name
    // the previous valid record line. Anything else is kept in the file but not trusted.
    const chainOk = record.prev === null ? !seenChained : record.prev === expectedPrev;
    if (record.prev === null) legacyRecords += 1;
    else seenChained = true;
    expectedPrev = auditLineHash(line);
    if (!chainOk) {
      unverified += 1;
      if (unverifiedLines.length < MAX_REPORTED_LINES) unverifiedLines.push(index + 1);
      return;
    }
    if (record.seq <= lastSeq) {
      duplicates += 1;
      return;
    }
    lastSeq = record.seq;
    loaded.push(record.event);
  });
  return {
    loaded,
    records: loaded.length,
    malformed,
    malformedLines,
    unverified,
    unverifiedLines,
    legacyRecords,
    duplicates,
    truncatedTail,
    highestSeq: Math.max(lastSeq, highestSeen),
    highestApprovalId,
    unsupportedVersion,
    nextPrev: expectedPrev,
  };
}

function sameFile(a: Stats, b: Stats): boolean {
  return a.dev === b.dev && a.ino === b.ino;
}

function permissionsRestricted(path: string, stat: Stats): boolean {
  try {
    if (process.platform === "win32") return isRestrictedToCurrentUser(path);
    return (stat.mode & 0o077) === 0;
  } catch {
    return false;
  }
}

/** Opens (creating if needed) the audit log at `path` and recovers its events. Throws AuditConfigError (fail closed). */
export function openFileAuditLog(path: string, options: AuditLogOptions = {}): AuditLog {
  const maxBytes = options.maxBytes ?? DEFAULT_AUDIT_LOG_MAX_BYTES;
  const maxRecordBytes = options.maxRecordBytes ?? MAX_AUDIT_RECORD_BYTES;
  const io = options.io ?? DEFAULT_IO;
  if (typeof path !== "string" || !isAbsolute(path)) throw new AuditConfigError("AUDIT_LOG_FILE must be an absolute path.");
  if (namesAlternateDataStream(path)) throw new AuditConfigError("The audit log path names an alternate data stream (a \":\" after the drive); use a plain file path.");
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 1 || !Number.isSafeInteger(maxRecordBytes) || maxRecordBytes < 1 || maxRecordBytes > maxBytes) {
    throw new AuditConfigError("The audit log limits are invalid.");
  }
  // M3-E E14: before anything is created, so an interrupted restore never leaves an empty log in its place.
  if (restoreMarkerPresent(path)) {
    throw new AuditConfigError(`A restore of the audit log was interrupted (a ${RESTORE_MARKER_SUFFIX} marker is next to it). Run the same restore again; the API does not start until it completes.`);
  }

  try {
    // M3-E E13: no ancestor directory may be a link (checked again once every directory exists).
    assertNoLinkedAncestors(path);
    mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
    assertNoLinkedAncestors(path);
  } catch (error) {
    if (error instanceof FileSecurityError) throw new AuditConfigError(`The audit log path is not safe: ${error.message}`);
    throw new AuditConfigError("The audit log directory cannot be created.");
  }

  let inspected: Stats;
  try {
    inspected = lstatSync(path);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw new AuditConfigError("The audit log cannot be inspected.");
    try {
      // Created empty and restricted to the current user before anything is written to it.
      writeRestrictedFileAtomically(path, "", { overwrite: false });
      inspected = lstatSync(path);
    } catch (createError) {
      if (createError instanceof FileSecurityError) throw new AuditConfigError("The audit log cannot be created with permissions restricted to the current user.");
      throw new AuditConfigError("The audit log cannot be created.");
    }
  }
  if (inspected.isSymbolicLink()) throw new AuditConfigError("The audit log path is a symbolic link or junction; it is not followed.");
  if (!inspected.isFile()) throw new AuditConfigError("The audit log path is not a regular file.");

  const lockPath = `${path}.lock`;
  const { staleReplaced } = acquireLock(lockPath);
  const releaseLock = () => releaseStoreLock(lockPath);

  let fd: number;
  try {
    fd = openSync(path, constants.O_RDWR | constants.O_APPEND | (constants.O_NOFOLLOW ?? 0));
  } catch {
    releaseLock();
    throw new AuditConfigError("The audit log cannot be opened for appending (check its permissions).");
  }

  try {
    const opened = fstatSync(fd);
    if (!opened.isFile() || !sameFile(opened, inspected)) throw new AuditConfigError("The audit log changed while it was being opened.");
    if (opened.size > maxBytes) throw new AuditConfigError(`The audit log is larger than its limit (${maxBytes} bytes). Archive it, or raise AUDIT_LOG_MAX_BYTES.`);

    const content = Buffer.alloc(opened.size);
    let read = 0;
    while (read < content.length) {
      const n = readSync(fd, content, read, content.length - read, read);
      if (n === 0) break;
      read += n;
    }
    if (read !== content.length) throw new AuditConfigError("The audit log could not be read completely.");

    const inspection = inspectAuditContent(content, maxRecordBytes);
    const { loaded, malformed, malformedLines, unverified, unverifiedLines, legacyRecords, duplicates, truncatedTail } = inspection;
    // M3-E E14: a newer format is never skipped as malformed and appended after: stop instead.
    if (inspection.unsupportedVersion !== null) {
      throw new AuditConfigError(
        `The audit log holds records of format version ${inspection.unsupportedVersion}, written by a newer AgentShield. It was not opened, so nothing in it is lost. Use the AgentShield version that wrote it.`,
      );
    }

    let bytes = content.length;
    if (truncatedTail) {
      // Keep the partial record (never delete), but end its line so the next record starts cleanly.
      if (bytes + 1 > maxBytes) throw new AuditConfigError("The audit log is full; its partial final record cannot be terminated.");
      try {
        if (io.writeSync(fd, Buffer.from("\n"), 0, 1) !== 1) throw new Error("short write");
        io.fsyncSync(fd);
      } catch {
        throw new AuditConfigError("The audit log's partial final record could not be terminated.");
      }
      bytes += 1;
    }

    const recovery: AuditRecovery = {
      records: loaded.length,
      malformed,
      malformedLines,
      unverified,
      unverifiedLines,
      legacyRecords,
      duplicates,
      truncatedTail,
      staleLockReplaced: staleReplaced,
      permissionsRestricted: permissionsRestricted(path, opened),
      bytes,
      maxBytes,
      highestApprovalId: inspection.highestApprovalId,
    };

    // Ids never repeat, even after skipped records: continue after the highest sequence seen.
    let nextSeq = inspection.highestSeq + 1;
    let failed = false;
    let closed = false;
    let prevHash = inspection.nextPrev;

    return {
      loaded,
      get nextSequence() {
        return nextSeq;
      },
      recovery,
      readiness(): AuditReadiness {
        if (failed || closed) return { ok: false, reason: "audit-unavailable" };
        if (bytes + maxRecordBytes > maxBytes) return { ok: false, reason: "audit-storage-full" };
        return { ok: true };
      },
      health: (): StoreHealth => ({
        bytes,
        maxBytes,
        entries: null,
        entryLimit: null,
        writable: !failed && !closed,
        lockHeld: !closed && lockStillHeld(lockPath),
        full: bytes + maxRecordBytes > maxBytes,
      }),
      append(event: ActivityEvent): void {
        if (failed || closed) throw new AuditWriteError("unavailable");
        const seq = sequenceOf(event.id);
        if (seq === null || seq < nextSeq) throw new AuditWriteError("out-of-order");
        // M3-E E13: if the lock was removed or replaced, another process may be writing: stop (fail closed).
        if (!lockStillHeld(lockPath)) {
          failed = true;
          throw new AuditWriteError("lock-lost");
        }
        const text = serializeChainedAuditRecord(event, prevHash);
        const line = Buffer.from(text, "utf8");
        if (line.length > maxRecordBytes) throw new AuditWriteError("record-too-large");
        if (bytes + line.length > maxBytes) throw new AuditWriteError("storage-full");
        let written = 0;
        try {
          while (written < line.length) {
            const n = io.writeSync(fd, line, written, line.length - written);
            if (n <= 0) throw new Error("no progress");
            written += n;
          }
          io.fsyncSync(fd);
        } catch (error) {
          // Not durable (or partly written): stop appending in this process.
          failed = true;
          bytes += written;
          const code = (error as NodeJS.ErrnoException).code;
          throw new AuditWriteError(typeof code === "string" && /^[A-Z0-9_]{1,32}$/.test(code) ? code : "write-failed");
        }
        bytes += line.length;
        nextSeq = seq + 1;
        prevHash = auditLineHash(text.slice(0, -1));
      },
      close(): void {
        if (closed) return;
        closed = true;
        try {
          closeSync(fd);
        } finally {
          releaseLock();
        }
      },
    };
  } catch (error) {
    try {
      closeSync(fd);
    } finally {
      releaseLock();
    }
    if (error instanceof AuditConfigError) throw error;
    throw new AuditConfigError("The audit log could not be opened.");
  }
}

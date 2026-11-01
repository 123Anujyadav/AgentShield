import { createHash } from "node:crypto";
import { closeSync, constants, fstatSync, fsyncSync, lstatSync, mkdirSync, openSync, readFileSync, readSync, rmSync, writeSync, type Stats } from "node:fs";
import { dirname, isAbsolute } from "node:path";
import { assertNoLinkedAncestors, FileSecurityError, isRestrictedToCurrentUser, namesAlternateDataStream, writeRestrictedFileAtomically } from "../agents/file-security.js";

/**
 * A small durable journal (M3-E E11, integrity chain M3-E E13): a local, append-only file of
 * LF-terminated text records, for state that must survive a restart (the replay cache, idempotency
 * records, approvals). Single process.
 *
 * Line format (M3-E E13): `<record>\t<chain>`, where `chain` = SHA-256(previous chain + "\n" + record)
 * in lower-case hex, starting from a per-journal genesis value (so records cannot be moved between
 * journals unnoticed). Records never contain a tab or a line feed.
 *
 * WHAT THE CHAIN IS: corruption detection. It reveals a modified, deleted, inserted or reordered record,
 * whether by disk damage, a partial edit or an unsophisticated change. WHAT IT IS NOT: authenticity.
 * It uses no key, so anyone who can write the file can recompute it; it cannot detect whole records
 * removed from the end of the file. Protection against a deliberate local attacker needs a trust
 * boundary this single-account prototype does not have (see docs/security-assessment.md).
 *
 * - The path must be absolute; no ancestor directory and not the file itself may be a symbolic link or
 *   junction; only a regular file is accepted; a new file is created restricted to the current user
 *   before anything is written to it; the opened file is checked to be the one inspected.
 * - A lock file (holding the process id) keeps a second process from writing the same journal, and is
 *   re-checked before every write: if it was removed or replaced, writing stops (fail closed).
 * - append() writes one record and fsyncs it before returning. A failure (or a partial write) puts the
 *   journal in a failed state: nothing more is written in this process.
 * - rewrite() replaces the whole journal atomically (a restricted temporary file, fsynced, then renamed
 *   over it), re-chained from the genesis value. A crash leaves the old or the new file, never a mix.
 * - At open, complete records are returned in order, each marked verified or not. A final record without
 *   its LF (a crash during a write) is reported and excluded. A journal written before M3-E E13 (no chain
 *   at all) is reported as legacy; its owner verifies it its own way and rewrites it in the chained form.
 * - The file never grows beyond `maxBytes`.
 * - M3-E E14: a record of a newer format version (a downgrade, or a backup from a newer AgentShield)
 *   stops the open instead of being treated as damage and rewritten away; a `.restoring` marker left by
 *   an interrupted restore stops it too (see ops/backup.ts).
 */

export class JournalConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "JournalConfigError";
  }
}

export class JournalWriteError extends Error {
  constructor(readonly code: string) {
    super(`The record could not be stored durably (${code}).`);
    this.name = "JournalWriteError";
  }
}

/** File operations used for writes; replaceable in tests to simulate failures. */
export interface JournalIo {
  writeSync: (fd: number, buffer: Uint8Array, offset: number, length: number) => number;
  fsyncSync: (fd: number) => void;
  /** Atomic replacement of the whole file (default: a restricted temporary file renamed over it). */
  replaceFile: (path: string, content: string) => void;
}

export const DEFAULT_JOURNAL_IO: JournalIo = {
  writeSync: (fd, buffer, offset, length) => writeSync(fd, buffer, offset, length),
  fsyncSync: (fd) => fsyncSync(fd),
  replaceFile: (path, content) => writeRestrictedFileAtomically(path, content, { overwrite: true }),
};

export interface JournalIntegrity {
  /** The file had records but no chain: written before M3-E E13. */
  legacy: boolean;
  /** Complete records whose chain value does not match (modified, inserted, reordered, or following a deletion). */
  unverified: number;
  /** 1-based line number of the first unverified record, or null. */
  firstUnverifiedLine: number | null;
}

/** M3-E E14: what a journal's content holds, read without opening (or locking) the journal. */
export interface JournalInspection {
  records: string[];
  verified: boolean[];
  integrity: JournalIntegrity;
  truncatedTail: boolean;
  /** The highest record version newer than this AgentShield understands, or null. */
  unsupportedVersion: number | null;
}

export interface Journal {
  /** Complete records found at open, oldest first (without the chain value or LF). */
  readonly records: readonly string[];
  /** Per record: whether its chain value verified (always true for a legacy journal). */
  readonly verified: readonly boolean[];
  readonly integrity: JournalIntegrity;
  /** The file did not exist and was created by this open. */
  readonly created: boolean;
  /** The file ended inside a record (a crash during a write); that partial record was excluded. */
  readonly truncatedTail: boolean;
  /** Whether the file is readable by the current user only (only checked when asked; true otherwise). */
  readonly permissionsRestricted: boolean;
  readonly bytes: number;
  /** M3-E E14: the size limit, for capacity reporting. */
  readonly maxBytes: number;
  /** M3-E E14: a lock left by a process that no longer runs was replaced at open. */
  readonly staleLockReplaced: boolean;
  readonly failed: boolean;
  /** M3-E E14: whether the lock file is still this process's (false after it was removed or replaced). */
  lockHeld(): boolean;
  append(record: string): void;
  rewrite(records: readonly string[]): void;
  /** Keeps a restricted copy of the file as found (before a recovery rewrite), for investigation. Returns its path. */
  preserveCopy(): string;
  close(): void;
}

export interface JournalOptions {
  /** Used in error messages and the chain's genesis value, e.g. "replay store". */
  label: string;
  maxBytes: number;
  maxRecordBytes: number;
  io?: JournalIo;
  /** Check that the file is readable by the current user only (Windows ACL / mode). Slow on Windows; the server sets it. */
  checkPermissions?: boolean;
  /** M3-E E14: a record's version when it is newer than the owner understands, else null. Such a record stops the open. */
  unsupportedVersion?: (record: string) => number | null;
}

/** M3-E E14: a restore writes this marker next to each store before replacing it, and removes it when done. */
export const RESTORE_MARKER_SUFFIX = ".restoring";

/** True when a restore of the store at `path` is in progress or was interrupted (an unreadable marker counts). */
export function restoreMarkerPresent(path: string): boolean {
  try {
    lstatSync(`${path}${RESTORE_MARKER_SUFFIX}`);
    return true;
  } catch (error) {
    return (error as NodeJS.ErrnoException).code !== "ENOENT";
  }
}

const CHAINED = /^(.*)\t([0-9a-f]{64})$/s;
const sha256 = (text: string) => createHash("sha256").update(text, "utf8").digest("hex");
export const journalGenesis = (label: string) => sha256(`agentshield-journal-v1\u0000${label}`);
export const chainValue = (previous: string, record: string) => sha256(`${previous}\n${record}`);

function isAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return (error as NodeJS.ErrnoException).code === "EPERM";
  }
}

/** The process id in a lock file, or NaN (a link is never followed to read someone else's file as a pid). */
function lockPid(lockPath: string): number {
  try {
    if (lstatSync(lockPath).isSymbolicLink()) return Number.NaN;
    const text = readFileSync(lockPath, "utf8").trim();
    return /^\d{1,10}$/.test(text) ? Number(text) : Number.NaN;
  } catch {
    return Number.NaN;
  }
}

/** M3-E E14: a store lock as seen from outside (diagnostics, backup and restore). Read only. */
export type LockState = { state: "free" } | { state: "held"; pid: number } | { state: "stale"; pid: number | null };

export function inspectLock(lockPath: string): LockState {
  try {
    lstatSync(lockPath);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return { state: "free" };
  }
  const pid = lockPid(lockPath);
  if (Number.isSafeInteger(pid) && pid > 0 && isAlive(pid)) return { state: "held", pid };
  return { state: "stale", pid: Number.isSafeInteger(pid) && pid > 0 ? pid : null };
}

/**
 * Takes a store's single-writer lock for this process: a new lock file holding the process id. A lock
 * held by a running process (or by this one) is refused; one left by a process that no longer runs is
 * replaced and reported. Shared by the journals, the audit log, and (M3-E E14) backup and restore.
 */
export function acquireStoreLock(lockPath: string, label: string): { staleReplaced: boolean } {
  for (let attempt = 0; attempt < 2; attempt += 1) {
    try {
      const fd = openSync(lockPath, "wx", 0o600);
      try {
        writeSync(fd, String(process.pid));
      } finally {
        closeSync(fd);
      }
      return { staleReplaced: attempt > 0 };
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw new JournalConfigError(`The ${label} lock file cannot be created.`);
    }
    const pid = lockPid(lockPath);
    if (pid === process.pid || (Number.isSafeInteger(pid) && pid > 0 && isAlive(pid))) {
      throw new JournalConfigError(`The ${label} is in use by another AgentShield API process (pid ${pid}). Only one process may write it.`);
    }
    try {
      rmSync(lockPath, { force: true });
    } catch {
      throw new JournalConfigError(`A stale ${label} lock file cannot be removed.`);
    }
  }
  throw new JournalConfigError(`The ${label} lock could not be taken.`);
}

/** M3-E E14: removes a lock this process holds (never another process's). */
export function releaseStoreLock(lockPath: string): void {
  if (lockStillHeld(lockPath)) rmSync(lockPath, { force: true });
}

/**
 * M3-E E14: verifies a journal's content without opening it: the integrity chain, a final record cut short,
 * and record versions. Pure; used by openJournal and by the backup, restore and status tools.
 */
export function inspectJournalContent(content: Buffer, label: string, unsupportedVersion?: (record: string) => number | null): JournalInspection {
  const truncatedTail = content.length > 0 && content[content.length - 1] !== 0x0a;
  // The last part is either the partial record (truncatedTail) or the empty string after the final LF.
  const lines = content.toString("utf8").split("\n").slice(0, -1).filter((line) => line.length > 0);
  // Verify the chain. Each record's chain value is checked against the previous record's stored value,
  // so a damaged record is localised: it, and the record after a deletion or insertion, are unverified.
  const anyChained = lines.some((line) => CHAINED.test(line));
  const legacy = lines.length > 0 && !anyChained;
  const records: string[] = [];
  const verified: boolean[] = [];
  let previous = journalGenesis(label);
  for (const line of lines) {
    const match = CHAINED.exec(line);
    if (legacy) {
      records.push(line);
      verified.push(true);
      continue;
    }
    if (!match) {
      records.push(line);
      verified.push(false);
      continue;
    }
    const [, record, stored] = match;
    records.push(record!);
    verified.push(chainValue(previous, record!) === stored);
    previous = stored!;
  }
  // Any record of a newer version counts, verified or not: refusing to open is safe, rewriting it away is not.
  let newest: number | null = null;
  if (unsupportedVersion) {
    for (const record of records) {
      const version = unsupportedVersion(record);
      if (version !== null && (newest === null || version > newest)) newest = version;
    }
  }
  const firstBad = verified.indexOf(false);
  return {
    records,
    verified,
    integrity: { legacy, unverified: verified.filter((v) => !v).length, firstUnverifiedLine: firstBad === -1 ? null : firstBad + 1 },
    truncatedTail,
    unsupportedVersion: newest,
  };
}

/** M3-E E14: the chain value the next appended record chains from (the last stored one, or the genesis value). */
export function journalHead(content: Buffer, label: string): string {
  let previous = journalGenesis(label);
  for (const line of content.toString("utf8").split("\n").slice(0, -1)) {
    const match = CHAINED.exec(line);
    if (match) previous = match[2]!;
  }
  return previous;
}

/** M3-E E13: true while the lock file is still ours (a regular file holding this process id). */
export function lockStillHeld(lockPath: string): boolean {
  try {
    if (!lstatSync(lockPath).isFile()) return false;
    return readFileSync(lockPath, "utf8").trim() === String(process.pid);
  } catch {
    return false;
  }
}

/** Inspects (creating if needed) a regular, non-link file at an absolute path with no linked ancestor. */
function prepareFile(path: string, label: string): { stat: Stats; created: boolean } {
  if (typeof path !== "string" || !isAbsolute(path)) throw new JournalConfigError(`The ${label} path must be absolute.`);
  if (namesAlternateDataStream(path)) throw new JournalConfigError(`The ${label} path names an alternate data stream (a ":" after the drive); use a plain file path.`);
  // M3-E E14: checked before anything is created, so an interrupted restore never leaves an empty store in its place.
  if (restoreMarkerPresent(path)) {
    throw new JournalConfigError(`A restore of the ${label} was interrupted (a ${RESTORE_MARKER_SUFFIX} marker is next to it). Run the same restore again; the API does not start until it completes.`);
  }
  try {
    assertNoLinkedAncestors(path);
    mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
    assertNoLinkedAncestors(path);
  } catch (error) {
    if (error instanceof FileSecurityError) throw new JournalConfigError(`The ${label} path is not safe: ${error.message}`);
    throw new JournalConfigError(`The ${label} directory cannot be created.`);
  }
  let created = false;
  let stat: Stats;
  try {
    stat = lstatSync(path);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw new JournalConfigError(`The ${label} cannot be inspected.`);
    try {
      writeRestrictedFileAtomically(path, "", { overwrite: false });
      stat = lstatSync(path);
      created = true;
    } catch (createError) {
      if (createError instanceof FileSecurityError) throw new JournalConfigError(`The ${label} cannot be created with permissions restricted to the current user.`);
      throw new JournalConfigError(`The ${label} cannot be created.`);
    }
  }
  if (stat.isSymbolicLink()) throw new JournalConfigError(`The ${label} path is a symbolic link or junction; it is not followed.`);
  if (!stat.isFile()) throw new JournalConfigError(`The ${label} path is not a regular file.`);
  return { stat, created };
}

function openForAppend(path: string, label: string, expected: Stats): number {
  let fd: number;
  try {
    fd = openSync(path, constants.O_RDWR | constants.O_APPEND | (constants.O_NOFOLLOW ?? 0));
  } catch {
    throw new JournalConfigError(`The ${label} cannot be opened for appending (check its permissions).`);
  }
  const opened = fstatSync(fd);
  if (!opened.isFile() || opened.dev !== expected.dev || opened.ino !== expected.ino) {
    closeSync(fd);
    throw new JournalConfigError(`The ${label} changed while it was being opened.`);
  }
  return fd;
}

export function openJournal(path: string, options: JournalOptions): Journal {
  const { label, maxBytes, maxRecordBytes } = options;
  const io = options.io ?? DEFAULT_JOURNAL_IO;
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 1 || !Number.isSafeInteger(maxRecordBytes) || maxRecordBytes < 2 || maxRecordBytes > maxBytes) {
    throw new JournalConfigError(`The ${label} limits are invalid.`);
  }
  const { stat, created } = prepareFile(path, label);
  const lockPath = `${path}.lock`;
  const { staleReplaced } = acquireStoreLock(lockPath, label);
  const releaseLock = () => releaseStoreLock(lockPath);
  const genesis = journalGenesis(label);

  let fd: number;
  try {
    fd = openForAppend(path, label, stat);
  } catch (error) {
    releaseLock();
    throw error;
  }

  try {
    const size = fstatSync(fd).size;
    if (size > maxBytes) throw new JournalConfigError(`The ${label} is larger than its limit (${maxBytes} bytes).`);
    const content = Buffer.alloc(size);
    let read = 0;
    while (read < size) {
      const n = readSync(fd, content, read, size - read, read);
      if (n === 0) break;
      read += n;
    }
    if (read !== size) throw new JournalConfigError(`The ${label} could not be read completely.`);
    const { records, verified, integrity, truncatedTail, unsupportedVersion } = inspectJournalContent(content, label, options.unsupportedVersion);
    // M3-E E14: never treat a newer format as damage (recovery would rewrite it away): stop instead.
    if (unsupportedVersion !== null) {
      throw new JournalConfigError(
        `The ${label} holds records of format version ${unsupportedVersion}, written by a newer AgentShield. It was not opened, so nothing in it is lost. Use the AgentShield version that wrote it.`,
      );
    }

    let bytes = size;
    if (truncatedTail) {
      // The partial record (a crash during its write: what it recorded never took effect) gets its line
      // ended, so nothing can be appended to it; owners then rewrite the journal without it.
      if (bytes + 1 > maxBytes) throw new JournalConfigError(`The ${label} is full; its partial final record cannot be terminated.`);
      try {
        if (io.writeSync(fd, Buffer.from("\n"), 0, 1) !== 1) throw new Error("short write");
        io.fsyncSync(fd);
      } catch {
        throw new JournalConfigError(`The ${label}'s partial final record could not be terminated.`);
      }
      bytes += 1;
    }

    let permissionsRestricted = true;
    if (options.checkPermissions) {
      try {
        permissionsRestricted = process.platform === "win32" ? isRestrictedToCurrentUser(path) : (fstatSync(fd).mode & 0o077) === 0;
      } catch {
        permissionsRestricted = false;
      }
    }

    let failed = false;
    let closed = false;
    let currentFd = fd;
    let lastChain = journalHead(content, label);

    const guardLock = () => {
      if (!lockStillHeld(lockPath)) {
        failed = true;
        throw new JournalWriteError("lock-lost");
      }
    };

    const journal: Journal = {
      records,
      verified,
      integrity,
      created,
      truncatedTail,
      permissionsRestricted,
      get bytes() {
        return bytes;
      },
      maxBytes,
      staleLockReplaced: staleReplaced,
      get failed() {
        return failed || closed;
      },
      lockHeld: () => !closed && lockStillHeld(lockPath),
      append(record: string): void {
        if (failed || closed) throw new JournalWriteError("unavailable");
        if (record.includes("\n") || record.includes("\t")) throw new JournalWriteError("invalid-record");
        guardLock();
        const chain = chainValue(lastChain, record);
        const line = Buffer.from(`${record}\t${chain}\n`, "utf8");
        if (line.length > maxRecordBytes + 65) throw new JournalWriteError("record-too-large");
        if (bytes + line.length > maxBytes) throw new JournalWriteError("full");
        let written = 0;
        try {
          while (written < line.length) {
            const n = io.writeSync(currentFd, line, written, line.length - written);
            if (n <= 0) throw new Error("no progress");
            written += n;
          }
          io.fsyncSync(currentFd);
        } catch (error) {
          failed = true;
          bytes += written;
          const code = (error as NodeJS.ErrnoException).code;
          throw new JournalWriteError(typeof code === "string" && /^[A-Z0-9_]{1,32}$/.test(code) ? code : "write-failed");
        }
        bytes += line.length;
        lastChain = chain;
      },
      rewrite(next: readonly string[]): void {
        if (failed || closed) throw new JournalWriteError("unavailable");
        if (next.some((r) => r.includes("\n") || r.includes("\t"))) throw new JournalWriteError("invalid-record");
        guardLock();
        let chain = genesis;
        const content = next
          .map((record) => {
            chain = chainValue(chain, record);
            return `${record}\t${chain}\n`;
          })
          .join("");
        const size = Buffer.byteLength(content, "utf8");
        if (size > maxBytes) throw new JournalWriteError("full");
        try {
          // Close first: Windows may refuse to replace a file that is open.
          closeSync(currentFd);
          io.replaceFile(path, content);
          assertNoLinkedAncestors(path);
          currentFd = openForAppend(path, label, lstatSync(path));
        } catch {
          failed = true;
          throw new JournalWriteError("rewrite-failed");
        }
        bytes = size;
        lastChain = chain;
      },
      preserveCopy(): string {
        const copy = `${path}.damaged-${new Date().toISOString().replace(/[:.]/g, "-")}`;
        writeRestrictedFileAtomically(copy, content.toString("utf8"), { overwrite: false });
        return copy;
      },
      close(): void {
        if (closed) return;
        closed = true;
        try {
          closeSync(currentFd);
        } catch {
          // already closed by a failed rewrite
        } finally {
          releaseLock();
        }
      },
    };
    return journal;
  } catch (error) {
    try {
      closeSync(fd);
    } finally {
      releaseLock();
    }
    if (error instanceof JournalConfigError) throw error;
    throw new JournalConfigError(`The ${label} could not be opened.`);
  }
}

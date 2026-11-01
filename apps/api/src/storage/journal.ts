import { closeSync, constants, fstatSync, fsyncSync, lstatSync, mkdirSync, openSync, readFileSync, readSync, rmSync, writeSync, type Stats } from "node:fs";
import { dirname, isAbsolute } from "node:path";
import { FileSecurityError, writeRestrictedFileAtomically } from "../agents/file-security.js";

/**
 * A small durable journal (M3-E E11): a local, append-only file of LF-terminated text records,
 * for state that must survive a restart (the replay cache, idempotency records). Single process.
 *
 * - The path must be absolute; a symbolic link, junction or anything but a regular file is refused;
 *   a new file is created restricted to the current user before anything is written to it; the
 *   opened file is checked to be the one inspected. A lock file (holding the process id) keeps a
 *   second process from writing the same journal.
 * - append() writes one record and fsyncs it before returning. A failure (or a partial write)
 *   puts the journal in a failed state: nothing more is written in this process, and callers
 *   refuse the operations that depend on it.
 * - rewrite() replaces the whole journal atomically (a restricted temporary file, fsynced, then
 *   renamed over it), to compact it to its live records. A crash leaves either the old or the new
 *   file, never a mix.
 * - At open, complete records are returned in order. A final record without its LF (a crash during
 *   a write) is reported and terminated with an LF so later records start on their own line.
 * - The file never grows beyond `maxBytes`: an append that would exceed it is refused (the caller
 *   compacts first, or fails closed).
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

export interface Journal {
  /** Complete records found at open, oldest first (without their LF). */
  readonly records: readonly string[];
  /** The file did not exist and was created by this open. */
  readonly created: boolean;
  /** The file ended inside a record (terminated at open). */
  readonly truncatedTail: boolean;
  readonly bytes: number;
  readonly failed: boolean;
  append(record: string): void;
  rewrite(records: readonly string[]): void;
  close(): void;
}

export interface JournalOptions {
  /** Used in error messages, e.g. "replay store". */
  label: string;
  maxBytes: number;
  maxRecordBytes: number;
  io?: JournalIo;
}

function isAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return (error as NodeJS.ErrnoException).code === "EPERM";
  }
}

function acquireLock(lockPath: string, label: string): void {
  for (let attempt = 0; attempt < 2; attempt += 1) {
    try {
      const fd = openSync(lockPath, "wx", 0o600);
      try {
        writeSync(fd, String(process.pid));
      } finally {
        closeSync(fd);
      }
      return;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw new JournalConfigError(`The ${label} lock file cannot be created.`);
    }
    let pid = Number.NaN;
    try {
      const text = readFileSync(lockPath, "utf8").trim();
      if (/^\d{1,10}$/.test(text)) pid = Number(text);
    } catch {
      // unreadable: replaced below if it can be removed
    }
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

/** Inspects (creating if needed) a regular, non-link file at an absolute path. */
function prepareFile(path: string, label: string): { stat: Stats; created: boolean } {
  if (typeof path !== "string" || !isAbsolute(path)) throw new JournalConfigError(`The ${label} path must be absolute.`);
  try {
    mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  } catch {
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
  acquireLock(lockPath, label);
  const releaseLock = () => rmSync(lockPath, { force: true });

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
    const truncatedTail = size > 0 && content[size - 1] !== 0x0a;
    const parts = content.toString("utf8").split("\n");
    // The last part is either the partial record (truncatedTail) or the empty string after the final LF.
    const records = parts.slice(0, -1).filter((line) => line.length > 0);
    let bytes = size;
    if (truncatedTail) {
      // The partial record (a crash during its write: the request it belonged to never proceeded) stays in
      // the file as a separate, unreadable line; the next record starts on its own line.
      if (bytes + 1 > maxBytes) throw new JournalConfigError(`The ${label} is full; its partial final record cannot be terminated.`);
      try {
        if (io.writeSync(fd, Buffer.from("\n"), 0, 1) !== 1) throw new Error("short write");
        io.fsyncSync(fd);
      } catch {
        throw new JournalConfigError(`The ${label}'s partial final record could not be terminated.`);
      }
      bytes += 1;
    }

    let failed = false;
    let closed = false;
    let currentFd = fd;

    const journal: Journal = {
      records,
      created,
      truncatedTail,
      get bytes() {
        return bytes;
      },
      get failed() {
        return failed || closed;
      },
      append(record: string): void {
        if (failed || closed) throw new JournalWriteError("unavailable");
        if (record.includes("\n")) throw new JournalWriteError("invalid-record");
        const line = Buffer.from(`${record}\n`, "utf8");
        if (line.length > maxRecordBytes) throw new JournalWriteError("record-too-large");
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
      },
      rewrite(next: readonly string[]): void {
        if (failed || closed) throw new JournalWriteError("unavailable");
        const content = next.map((record) => `${record}\n`).join("");
        const size = Buffer.byteLength(content, "utf8");
        if (size > maxBytes) throw new JournalWriteError("full");
        try {
          // Close first: Windows may refuse to replace a file that is open.
          closeSync(currentFd);
          io.replaceFile(path, content);
          currentFd = openForAppend(path, label, lstatSync(path));
        } catch {
          failed = true;
          throw new JournalWriteError("rewrite-failed");
        }
        bytes = size;
      },
      close(): void {
        if (closed) return;
        closed = true;
        try {
          if (!failed) closeSync(currentFd);
          else {
            try {
              closeSync(currentFd);
            } catch {
              // already closed by a failed rewrite
            }
          }
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

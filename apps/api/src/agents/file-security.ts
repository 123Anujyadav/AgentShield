import { spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { chmodSync, closeSync, existsSync, fsyncSync, linkSync, mkdirSync, openSync, renameSync, rmSync, writeSync } from "node:fs";
import { basename, dirname, join } from "node:path";

/**
 * Files that only the current user may read (M3-D): the agent credential store
 * and credential output files. On Windows the file's inherited permissions are
 * removed and a single full-control entry for the current user's SID is set
 * (icacls, part of Windows). Elsewhere the file mode is 0600. Every step fails
 * closed: a file whose permissions could not be restricted is deleted, and no
 * content is written until the restriction is in place.
 */

export class FileSecurityError extends Error {}

const ICACLS_TIMEOUT_MS = 15_000;

/**
 * Windows' own tools by absolute path: a PATH lookup could find another program
 * of the same name first (Git for Windows ships a different `whoami`).
 */
function systemTool(name: string): string {
  return join(process.env.SystemRoot ?? process.env.windir ?? "C:\\Windows", "System32", `${name}.exe`);
}

export interface CurrentUser {
  /** DOMAIN\user as Windows reports it (lower case). */
  name: string;
  sid: string;
}

let cachedUser: CurrentUser | null = null;

/** The current Windows account, from `whoami /user` (no network, no dependency). */
export function currentWindowsUser(): CurrentUser {
  if (cachedUser) return cachedUser;
  const result = spawnSync(systemTool("whoami"), ["/user", "/fo", "csv", "/nh"], { encoding: "utf8", windowsHide: true, timeout: ICACLS_TIMEOUT_MS });
  const match = /^"([^"]+)","(S-1-[0-9-]+)"\s*$/m.exec(result.stdout ?? "");
  if (result.error || result.status !== 0 || !match) throw new FileSecurityError("Could not determine the current Windows user.");
  cachedUser = { name: match[1]!, sid: match[2]! };
  return cachedUser;
}

/** Removes inherited permissions and grants only the current user full control. */
export function restrictToCurrentUser(path: string): void {
  if (process.platform !== "win32") {
    chmodSync(path, 0o600);
    return;
  }
  const { sid } = currentWindowsUser();
  const result = spawnSync(systemTool("icacls"), [path, "/inheritance:r", "/grant:r", `*${sid}:(F)`], { encoding: "utf8", windowsHide: true, timeout: ICACLS_TIMEOUT_MS });
  if (result.error || result.status !== 0) throw new FileSecurityError("Could not restrict the file to the current Windows user.");
}

/**
 * The access entries on a file, as icacls lists them ("DOMAIN\user:(F)"), for
 * verification. Windows only.
 */
export function windowsAclEntries(path: string): string[] {
  const result = spawnSync(systemTool("icacls"), [path], { encoding: "utf8", windowsHide: true, timeout: ICACLS_TIMEOUT_MS });
  if (result.error || result.status !== 0) throw new FileSecurityError("Could not read the file's permissions.");
  const lines = result.stdout.split(/\r?\n/);
  const end = lines.findIndex((line) => line.trim() === "");
  const entries = lines.slice(0, end === -1 ? lines.length : end);
  if (entries.length === 0) return [];
  // The first line starts with the path itself.
  entries[0] = entries[0]!.startsWith(path) ? entries[0]!.slice(path.length) : entries[0]!;
  return entries.map((entry) => entry.trim()).filter(Boolean);
}

/** True when the file grants access to the current user only (one explicit, non-inherited entry). */
export function isRestrictedToCurrentUser(path: string): boolean {
  if (process.platform !== "win32") return true;
  const entries = windowsAclEntries(path);
  const { name } = currentWindowsUser();
  return entries.length === 1 && entries[0]!.toLowerCase() === `${name.toLowerCase()}:(f)`;
}

const RENAME_ATTEMPTS = 5;

function pause(ms: number): void {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}

/**
 * Writes `content` to `path` atomically. A temporary file is created empty
 * next to the target, restricted to the current user, then written and flushed,
 * and only then moved into place, so the content never exists in a file other
 * users could read. With `overwrite: false` an existing file is never replaced.
 */
export function writeRestrictedFileAtomically(path: string, content: string, options: { overwrite: boolean }): void {
  const directory = dirname(path);
  mkdirSync(directory, { recursive: true, mode: 0o700 });
  if (!options.overwrite && existsSync(path)) throw new FileSecurityError("The output file already exists; it was not replaced.");
  const temporary = join(directory, `.${basename(path)}.${randomBytes(8).toString("hex")}.tmp`);
  closeSync(openSync(temporary, "wx", 0o600));
  try {
    restrictToCurrentUser(temporary);
    const fd = openSync(temporary, "r+");
    try {
      writeSync(fd, content);
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
    if (!options.overwrite) {
      // A hard link fails if the target appeared meanwhile, so nothing is ever clobbered.
      try {
        linkSync(temporary, path);
      } catch {
        throw new FileSecurityError("The output file already exists or cannot be created; it was not replaced.");
      }
      rmSync(temporary, { force: true });
      return;
    }
    for (let attempt = 1; ; attempt += 1) {
      try {
        renameSync(temporary, path);
        return;
      } catch (error) {
        // Windows refuses a replace while another process briefly has the file open.
        const code = (error as NodeJS.ErrnoException).code;
        if (attempt >= RENAME_ATTEMPTS || (code !== "EPERM" && code !== "EBUSY" && code !== "EACCES")) throw error;
        pause(50 * attempt);
      }
    }
  } finally {
    rmSync(temporary, { force: true });
  }
}

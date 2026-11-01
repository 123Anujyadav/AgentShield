import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { openFileAuditLog } from "../audit/file-audit-log.js";
import { namesAlternateDataStream } from "../agents/file-security.js";
import { openJournal } from "../storage/journal.js";

/**
 * M3-E E15: Windows path handling for the stores, probed in a temporary directory. NTFS alternate data streams
 * (`file:stream`) are refused with a clear reason; the device namespace is refused; reserved device names and
 * trailing dots become ordinary files (Node uses namespaced paths), so records are kept, never discarded.
 */

const win = process.platform === "win32";
let dir: string;
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "agentshield-winpath-"));
});
afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});
const open = (path: string) => openJournal(path, { label: "probe store", maxBytes: 4096, maxRecordBytes: 128 });

describe("M3-E E15: Windows store paths", () => {
  it("recognises an alternate data stream after the drive, in plain and namespaced paths, and only on Windows", () => {
    expect(namesAlternateDataStream("C:\\state\\approvals.journal", "win32")).toBe(false);
    expect(namesAlternateDataStream("C:\\state\\approvals.journal:hidden", "win32")).toBe(true);
    expect(namesAlternateDataStream("\\\\?\\C:\\state\\approvals.journal", "win32")).toBe(false);
    expect(namesAlternateDataStream("\\\\?\\C:\\state\\a.journal:s", "win32")).toBe(true);
    expect(namesAlternateDataStream("\\\\server\\share\\a.journal", "win32")).toBe(false);
    expect(namesAlternateDataStream("/srv/state/a:b.journal", "linux")).toBe(false);
  });

  it.runIf(win)("a store path naming an alternate data stream is refused with that reason (not mistaken for an interrupted restore)", () => {
    writeFileSync(join(dir, "host.journal"), "");
    expect(() => open(join(dir, "host.journal:stream"))).toThrow(/alternate data stream/);
    expect(() => openFileAuditLog(join(dir, "host.journal:stream"))).toThrow(/alternate data stream/);
    expect(readFileSync(join(dir, "host.journal"), "utf8")).toBe("");
  });

  it.runIf(win)("the Win32 device namespace is refused", () => {
    expect(() => open("\\\\.\\NUL")).toThrow(/not safe/);
    expect(() => openFileAuditLog("\\\\.\\NUL")).toThrow(/not safe/);
  });

  it.runIf(win)("reserved device names and trailing dots are ordinary files: records persist across a reopen", () => {
    for (const name of ["nul", "CON.journal", "COM1", "trail.journal."]) {
      const path = join(dir, name);
      const first = open(path);
      first.append("kept");
      first.close();
      const again = open(path);
      expect(again.records, name).toEqual(["kept"]);
      again.close();
    }
  });

  it("a directory at the store path is refused, never replaced", () => {
    const path = join(dir, "approvals.journal");
    mkdirSync(path);
    expect(() => open(path)).toThrow(/not a regular file/);
  });
});

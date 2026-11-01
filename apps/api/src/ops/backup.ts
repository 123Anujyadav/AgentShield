import { createHash, randomBytes } from "node:crypto";
import { closeSync, lstatSync, mkdirSync, mkdtempSync, openSync, readdirSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, isAbsolute, join } from "node:path";
import { APPROVAL_STORE_MAX_BYTES, approvalStorePathFromEnv, openDurableApprovalStore } from "../approval-journal.js";
import { auditLogMaxBytesFromEnv, auditLogPathFromEnv, inspectAuditContent } from "../audit/file-audit-log.js";
import { credentialFilePath, MAX_CREDENTIAL_FILE_BYTES, parseCredentialDocument } from "../agents/credentials.js";
import { newerReplayRecordVersion, REPLAY_STORE_MAX_BYTES, replayStorePathFromEnv } from "../agents/durable-nonce-cache.js";
import { assertNoLinkedAncestors, isRestrictedToCurrentUser, restrictDirectoryToCurrentUser, writeRestrictedFileAtomically } from "../agents/file-security.js";
import { IDEMPOTENCY_STORE_MAX_BYTES, IDEMPOTENCY_TTL_MS, idempotencyStorePathFromEnv } from "../idempotency.js";
import { defaultTokenDirectory } from "../security/token.js";
import { newerJsonVersion } from "../storage/health.js";
import {
  acquireStoreLock,
  chainValue,
  inspectJournalContent,
  inspectLock,
  journalGenesis,
  journalHead,
  JournalConfigError,
  releaseStoreLock,
  RESTORE_MARKER_SUFFIX,
  restoreMarkerPresent,
  type LockState,
} from "../storage/journal.js";

/**
 * Backup, restore and storage status for the operator (M3-E E14). Single process, local files only.
 *
 * CONSISTENCY. The stores have no live snapshot mechanism (each append is fsynced, but four files are
 * written at different moments), so a backup is only ever taken OFFLINE: the tool takes every store's
 * single-writer lock for the whole copy. While the API runs, those locks are held by it and the backup
 * refuses; while the backup runs, an API that starts refuses to open its stores. Every copy therefore
 * comes from the same quiet moment.
 *
 * WHAT A RESTORE DOES (and what it never does):
 * - It only fills in a store that is MISSING, or (with --replace-damaged) one whose integrity check fails.
 *   A present, healthy store is always kept: it holds newer state than any backup, and is never replaced.
 * - Replay protection is never restored: an old nonce list only weakens replay protection, and a missing
 *   replay journal already makes the next start refuse every signed request dated before it (the fence).
 * - Idempotency records are never restored: a missing journal is recreated holding only a recovery window,
 *   so for one retention period no idempotency key is evaluated as new (it may have been used after the
 *   backup was taken).
 * - Restored approvals that were PENDING become OUTCOME_UNKNOWN at the next start (they may have been decided,
 *   or executed, after the backup), and approval ids continue after every id the backup, the replaced file
 *   and the audit log name, so no id is reissued.
 * - The credential store is restored only when asked (--restore-credentials) and missing: an old copy would
 *   bring back credentials revoked since the backup.
 * - The backup is verified completely (manifest, sizes, SHA-256, integrity chains, record versions) before
 *   anything is written; a damaged store is copied aside first; each file is written atomically; and a
 *   `.restoring` marker next to each target makes the API refuse to start until the restore has completed
 *   (running the same restore again resumes it).
 *
 * Nothing here prints, returns or exports a record, a key or a credential: only names, counts, sizes,
 * hashes and fixed status codes. Backup files and directories are restricted to the current user.
 */

export const BACKUP_FORMAT = "agentshield-backup";
export const BACKUP_VERSION = 1;
export const MANIFEST_NAME = "manifest.json";

export type StoreKind = "audit-log" | "approval-store" | "idempotency-store" | "replay-store" | "credential-store";
export type FileStatus = "missing" | "verified" | "damaged" | "unsupported-version" | "unreadable";

export class OpsError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "OpsError";
  }
}

export interface StorePaths {
  auditLog: string;
  approvals: string;
  idempotency: string;
  replay: string;
  credentials: string;
}

/** The store paths the API uses (the same environment variables and defaults as server.ts). */
export function storePathsFromEnv(env: NodeJS.ProcessEnv = process.env): StorePaths {
  return {
    auditLog: auditLogPathFromEnv(env),
    approvals: approvalStorePathFromEnv(env),
    idempotency: idempotencyStorePathFromEnv(env),
    replay: replayStorePathFromEnv(env),
    credentials: credentialFilePath(env),
  };
}

/** A default, timestamped backup directory under the AgentShield state directory. Copy it elsewhere for disaster recovery. */
export function defaultBackupDirectory(env: NodeJS.ProcessEnv = process.env, now = Date.now()): string {
  return join(defaultTokenDirectory(env), "backups", `backup-${new Date(now).toISOString().replace(/[:.]/g, "-")}`);
}

interface StoreDef {
  kind: StoreKind;
  /** The file name inside a backup (fixed: never taken from a manifest). */
  file: string;
  /** The journal label (its chain genesis), or null for the audit log and the credential store. */
  label: string | null;
  /** Restored when missing (or damaged, if asked)? Replay and idempotency state never is. */
  restorable: boolean;
  /** "pid": the API's single-writer lock; "exclusive": the credential CLI's lock (no process id). */
  lock: "pid" | "exclusive";
  path: (p: StorePaths) => string;
}

const STORES: readonly StoreDef[] = [
  { kind: "audit-log", file: "audit-events.jsonl", label: null, restorable: true, lock: "pid", path: (p) => p.auditLog },
  { kind: "approval-store", file: "approvals.journal", label: "approval store", restorable: true, lock: "pid", path: (p) => p.approvals },
  { kind: "idempotency-store", file: "idempotency.journal", label: "idempotency store", restorable: false, lock: "pid", path: (p) => p.idempotency },
  { kind: "replay-store", file: "replay-nonces.journal", label: "replay store", restorable: false, lock: "pid", path: (p) => p.replay },
  { kind: "credential-store", file: "agent-credentials.json", label: null, restorable: true, lock: "exclusive", path: (p) => p.credentials },
];
const byKind = (kind: StoreKind) => STORES.find((s) => s.kind === kind)!;

const sha256 = (data: Uint8Array) => createHash("sha256").update(data).digest("hex");
const stamp = (now: number) => new Date(now).toISOString().replace(/[:.]/g, "-");

export interface FileInspection {
  status: FileStatus;
  bytes: number;
  sha256: string | null;
  /** Valid records (audit events, journal records, credentials). */
  records: number;
  /** Fixed codes with counts, e.g. "unverified=2", "truncated-final-record". Never content. */
  details: string[];
  /** The highest approval number the file names (approvals and audit log), 0 if none. */
  highestApprovalId: number;
}

/** The highest approval number named anywhere in a journal's text (`apr-N`, or a seq/restored record's next - 1). */
function highestApprovalIdIn(text: string): number {
  let highest = 0;
  for (const m of text.matchAll(/apr-([1-9][0-9]{0,8})/g)) highest = Math.max(highest, Number(m[1]));
  for (const m of text.matchAll(/"t":"(?:seq|restored)","next":([1-9][0-9]{0,9})/g)) highest = Math.max(highest, Number(m[1]) - 1);
  return highest;
}

/** Verifies a store file's content (no lock, no write). */
export function inspectContent(kind: StoreKind, content: Buffer, now: number): FileInspection {
  const base = { bytes: content.length, sha256: sha256(content), highestApprovalId: 0 };
  if (kind === "audit-log") {
    const a = inspectAuditContent(content);
    const damaged = a.unverified + a.duplicates + a.malformed - (a.truncatedTail ? 1 : 0);
    const details = [
      ...(a.unverified ? [`unverified=${a.unverified}`] : []),
      ...(a.malformed ? [`malformed=${a.malformed}`] : []),
      ...(a.duplicates ? [`duplicates=${a.duplicates}`] : []),
      ...(a.truncatedTail ? ["truncated-final-record"] : []),
      ...(a.legacyRecords ? [`pre-E13-records=${a.legacyRecords}`] : []),
    ];
    const status: FileStatus = a.unsupportedVersion !== null ? "unsupported-version" : damaged > 0 ? "damaged" : "verified";
    if (a.unsupportedVersion !== null) details.push(`record-version=${a.unsupportedVersion}`);
    return { ...base, status, records: a.records, details, highestApprovalId: a.highestApprovalId };
  }
  if (kind === "credential-store") {
    try {
      const records = parseCredentialDocument(content.toString("utf8"), now);
      return { ...base, status: "verified", records: records.length, details: [] };
    } catch {
      // The validation message may name a field; only a fixed code is reported.
      return { ...base, status: "damaged", records: 0, details: ["invalid-credential-document"] };
    }
  }
  const def = byKind(kind);
  const versions = kind === "replay-store" ? newerReplayRecordVersion : newerJsonVersion(1);
  const j = inspectJournalContent(content, def.label!, versions);
  const details = [
    ...(j.integrity.unverified ? [`unverified=${j.integrity.unverified}`] : []),
    ...(j.integrity.legacy ? ["pre-E13-unchained"] : []),
    ...(j.truncatedTail ? ["truncated-final-record"] : []),
  ];
  let status: FileStatus = "verified";
  if (j.unsupportedVersion !== null) {
    status = "unsupported-version";
    details.push(`record-version=${j.unsupportedVersion}`);
  } else if (j.integrity.unverified > 0 || j.integrity.legacy) {
    // An unchained (pre-E13) journal cannot be verified: it is not restored from a backup.
    status = "damaged";
  }
  const highestApprovalId = kind === "approval-store" ? highestApprovalIdIn(content.toString("utf8")) : 0;
  return { ...base, status, records: j.records.length, details, highestApprovalId };
}

/** Reads a store file safely: absolute, no linked ancestor, not a link, a regular file. Null when missing. */
function readStoreFile(path: string, maxBytes: number): Buffer | null {
  if (!isAbsolute(path)) throw new OpsError(`A store path is not absolute: ${path}`);
  assertNoLinkedAncestors(path);
  let stat;
  try {
    stat = lstatSync(path);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return null;
    throw new OpsError(`A store file cannot be inspected: ${path}`);
  }
  if (stat.isSymbolicLink()) throw new OpsError(`A store path is a symbolic link or junction; it is not followed: ${path}`);
  if (!stat.isFile()) throw new OpsError(`A store path is not a regular file: ${path}`);
  if (stat.size > maxBytes) throw new OpsError(`A store file is larger than its limit (${maxBytes} bytes): ${path}`);
  return readFileSync(path);
}

function maxBytesFor(kind: StoreKind, env: NodeJS.ProcessEnv): number {
  switch (kind) {
    case "audit-log":
      return auditLogMaxBytesFromEnv(env);
    case "approval-store":
      return APPROVAL_STORE_MAX_BYTES;
    case "idempotency-store":
      return IDEMPOTENCY_STORE_MAX_BYTES;
    case "replay-store":
      return REPLAY_STORE_MAX_BYTES;
    case "credential-store":
      return MAX_CREDENTIAL_FILE_BYTES;
  }
}

// ---------------------------------------------------------------- locks

interface HeldLocks {
  release(): void;
  staleReplaced: StoreKind[];
}

/**
 * Takes every store's lock for this process, or none: refuses while the API (or a credential command) runs,
 * and while an interrupted restore is unfinished (unless `allowRestoreMarkers`, for the restore that resumes it).
 */
function takeAllLocks(paths: StorePaths, allowRestoreMarkers: boolean): HeldLocks {
  const held: Array<() => void> = [];
  const staleReplaced: StoreKind[] = [];
  const release = () => {
    for (const undo of held.reverse()) {
      try {
        undo();
      } catch {
        // best effort: a lock that cannot be removed is reported by the next start as stale
      }
    }
    held.length = 0;
  };
  try {
    for (const def of STORES) {
      const path = def.path(paths);
      if (!isAbsolute(path)) throw new OpsError(`The ${def.kind} path must be absolute: ${path}`);
      assertNoLinkedAncestors(path);
      if (!allowRestoreMarkers && restoreMarkerPresent(path)) {
        throw new OpsError(`A restore of the ${def.kind} was interrupted (${path}${RESTORE_MARKER_SUFFIX}). Complete it first by running the same restore again.`);
      }
      const lockPath = `${path}.lock`;
      mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
      assertNoLinkedAncestors(path);
      if (def.lock === "pid") {
        try {
          const { staleReplaced: stale } = acquireStoreLock(lockPath, def.kind);
          if (stale) staleReplaced.push(def.kind);
        } catch (error) {
          const reason = error instanceof JournalConfigError ? error.message : "its lock could not be taken";
          throw new OpsError(`${reason} Stop the AgentShield API first: backups and restores run only while it is stopped.`);
        }
        held.push(() => releaseStoreLock(lockPath));
      } else {
        try {
          closeSync(openSync(lockPath, "wx", 0o600));
        } catch {
          throw new OpsError(`A credential command is running, or one was interrupted (${lockPath} exists). If none is running, delete that lock file.`);
        }
        held.push(() => rmSync(lockPath, { force: true }));
      }
    }
  } catch (error) {
    release();
    throw error;
  }
  return { release, staleReplaced };
}

// ---------------------------------------------------------------- manifest

export interface ManifestEntry {
  kind: StoreKind;
  file: string;
  present: boolean;
  bytes: number;
  sha256: string | null;
  status: FileStatus;
  records: number;
  restorable: boolean;
}

export interface Manifest {
  format: typeof BACKUP_FORMAT;
  version: typeof BACKUP_VERSION;
  id: string;
  createdAt: string;
  consistency: string;
  stores: ManifestEntry[];
}

function parseManifest(text: string): Manifest {
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch {
    throw new OpsError("The backup manifest is not valid JSON: the backup is incomplete or damaged.");
  }
  const m = value as Partial<Manifest> | null;
  if (!m || typeof m !== "object" || m.format !== BACKUP_FORMAT) throw new OpsError("This is not an AgentShield backup (unknown manifest format).");
  if (typeof m.version !== "number" || m.version > BACKUP_VERSION) {
    throw new OpsError(`The backup format version ${String(m.version)} is newer than this AgentShield supports (${BACKUP_VERSION}). Use the AgentShield version that made it.`);
  }
  if (m.version !== BACKUP_VERSION) throw new OpsError("The backup format version is not supported.");
  if (typeof m.id !== "string" || !/^[0-9a-f]{16}$/.test(m.id) || typeof m.createdAt !== "string" || Number.isNaN(Date.parse(m.createdAt))) {
    throw new OpsError("The backup manifest is incomplete.");
  }
  if (!Array.isArray(m.stores) || m.stores.length !== STORES.length) throw new OpsError("The backup manifest does not list every store.");
  const seen = new Set<string>();
  for (const e of m.stores as unknown[]) {
    const entry = e as Partial<ManifestEntry>;
    const def = STORES.find((s) => s.kind === entry?.kind);
    // The file name must be the fixed one for its store: a manifest can never point anywhere else.
    if (!def || seen.has(def.kind) || entry.file !== def.file || typeof entry.present !== "boolean" || typeof entry.bytes !== "number" || typeof entry.records !== "number") {
      throw new OpsError("The backup manifest has an invalid store entry.");
    }
    if (entry.present && (typeof entry.sha256 !== "string" || !/^[0-9a-f]{64}$/.test(entry.sha256))) throw new OpsError("The backup manifest has an invalid checksum.");
    seen.add(def.kind);
  }
  return m as Manifest;
}

// ---------------------------------------------------------------- backup

export interface BackupResult {
  directory: string;
  manifest: Manifest;
  staleLocksReplaced: StoreKind[];
}

/** Hooks for tests: called after each step; throwing simulates a crash at that point. */
export interface OpsHooks {
  afterStep?: (step: string) => void;
}

/**
 * Takes an offline backup of every store into `directory`, which must not exist yet. Refuses while the API
 * runs. The manifest is written last, so a backup without one is incomplete.
 */
export function backupStores(paths: StorePaths, directory: string, options: { env?: NodeJS.ProcessEnv; now?: () => number; hooks?: OpsHooks } = {}): BackupResult {
  const env = options.env ?? process.env;
  const now = options.now ?? Date.now;
  if (!isAbsolute(directory)) throw new OpsError("The backup directory must be an absolute path.");
  assertNoLinkedAncestors(join(directory, MANIFEST_NAME));
  try {
    lstatSync(directory);
    throw new OpsError("The backup directory already exists; a backup never overwrites anything. Choose a new directory.");
  } catch (error) {
    if (error instanceof OpsError) throw error;
  }
  const locks = takeAllLocks(paths, false);
  try {
    mkdirSync(directory, { recursive: true, mode: 0o700 });
    assertNoLinkedAncestors(join(directory, MANIFEST_NAME));
    restrictDirectoryToCurrentUser(directory);
    const entries: ManifestEntry[] = [];
    for (const def of STORES) {
      const content = readStoreFile(def.path(paths), maxBytesFor(def.kind, env));
      if (content === null) {
        entries.push({ kind: def.kind, file: def.file, present: false, bytes: 0, sha256: null, status: "missing", records: 0, restorable: def.restorable });
        continue;
      }
      const inspection = inspectContent(def.kind, content, now());
      const target = join(directory, def.file);
      writeRestrictedFileAtomically(target, content, { overwrite: false });
      // Read the copy back: what is in the backup is what was read.
      if (sha256(readFileSync(target)) !== inspection.sha256) throw new OpsError(`The copy of the ${def.kind} does not match the original; the backup is not usable.`);
      entries.push({
        kind: def.kind,
        file: def.file,
        present: true,
        bytes: inspection.bytes,
        sha256: inspection.sha256,
        status: inspection.status,
        records: inspection.records,
        restorable: def.restorable && inspection.status === "verified",
      });
      options.hooks?.afterStep?.(`copied:${def.kind}`);
    }
    const manifest: Manifest = {
      format: BACKUP_FORMAT,
      version: BACKUP_VERSION,
      id: randomBytes(8).toString("hex"),
      createdAt: new Date(now()).toISOString(),
      consistency: "offline: every store lock was held while the copies were made",
      stores: entries,
    };
    writeRestrictedFileAtomically(join(directory, MANIFEST_NAME), `${JSON.stringify(manifest, null, 2)}\n`, { overwrite: false });
    return { directory, manifest, staleLocksReplaced: locks.staleReplaced };
  } finally {
    locks.release();
  }
}

// ---------------------------------------------------------------- verify

export interface BackupStoreCheck {
  kind: StoreKind;
  present: boolean;
  status: FileStatus;
  records: number;
  restorable: boolean;
  /** Approvals only: the result of opening a copy with the real approval store. */
  pending?: number;
  problems: string[];
}

export interface BackupVerification {
  ok: boolean;
  manifest: Manifest | null;
  stores: BackupStoreCheck[];
  problems: string[];
  warnings: string[];
}

/**
 * Verifies a backup completely without changing it: the manifest (written last, so its absence means an
 * incomplete backup), each file's size and SHA-256, each store's integrity chain and record versions, and
 * (approvals) a trial open of a temporary copy with the real store. Damaged store copies are reported as not
 * restorable; that alone does not fail the backup.
 */
export function verifyBackup(directory: string, options: { now?: () => number; checkPermissions?: boolean } = {}): BackupVerification {
  const now = options.now ?? Date.now;
  const problems: string[] = [];
  const warnings: string[] = [];
  const stores: BackupStoreCheck[] = [];
  if (!isAbsolute(directory)) return { ok: false, manifest: null, stores, problems: ["The backup directory must be an absolute path."], warnings };
  let manifest: Manifest;
  try {
    assertNoLinkedAncestors(join(directory, MANIFEST_NAME));
    const stat = lstatSync(join(directory, MANIFEST_NAME));
    if (!stat.isFile()) throw new OpsError("The backup manifest is not a regular file.");
    manifest = parseManifest(readFileSync(join(directory, MANIFEST_NAME), "utf8"));
  } catch (error) {
    const missing = (error as NodeJS.ErrnoException).code === "ENOENT";
    problems.push(missing ? "The backup has no manifest: it is incomplete (a backup writes its manifest last)." : error instanceof Error ? error.message : "The backup manifest cannot be read.");
    return { ok: false, manifest: null, stores, problems, warnings };
  }
  for (const entry of manifest.stores) {
    const def = byKind(entry.kind);
    const check: BackupStoreCheck = { kind: entry.kind, present: entry.present, status: "missing", records: 0, restorable: false, problems: [] };
    stores.push(check);
    if (!entry.present) continue;
    const file = join(directory, def.file);
    let content: Buffer;
    try {
      const stat = lstatSync(file);
      if (!stat.isFile()) throw new Error("not a regular file");
      content = readFileSync(file);
    } catch {
      check.status = "unreadable";
      check.problems.push(`${def.file} is missing or unreadable: the backup is incomplete.`);
      continue;
    }
    if (content.length !== entry.bytes || sha256(content) !== entry.sha256) {
      check.status = "damaged";
      check.problems.push(`${def.file} does not match the manifest (size or SHA-256): it was changed or truncated after the backup.`);
      continue;
    }
    const inspection = inspectContent(entry.kind, content, now());
    check.status = inspection.status;
    check.records = inspection.records;
    if (inspection.status !== entry.status) check.problems.push(`${def.file}: its integrity status (${inspection.status}) differs from the manifest (${entry.status}).`);
    check.restorable = def.restorable && inspection.status === "verified";
    if (inspection.status === "unsupported-version") check.problems.push(`${def.file} was written by a newer AgentShield (${inspection.details.join(", ")}); it cannot be restored with this version.`);
    if (entry.kind === "approval-store" && inspection.status === "verified") {
      // A trial open with the real store: the exact recovery the API would run, on a temporary copy.
      const trial = mkdtempSync(join(tmpdir(), "agentshield-verify-"));
      try {
        const path = join(trial, def.file);
        writeRestrictedFileAtomically(path, content, { overwrite: false });
        const store = openDurableApprovalStore({ path });
        try {
          check.pending = store.recovery.pending;
          if (store.recovery.corrupt > 0) {
            check.restorable = false;
            check.problems.push(`${def.file}: ${store.recovery.corrupt} record(s) are not valid approval records.`);
          }
        } finally {
          store.close();
        }
      } catch (error) {
        check.restorable = false;
        check.problems.push(`${def.file} cannot be opened as an approval journal (${error instanceof Error ? error.message : "error"}).`);
      } finally {
        rmSync(trial, { recursive: true, force: true });
      }
    }
    if (options.checkPermissions) {
      try {
        if (!isRestrictedToCurrentUser(file)) warnings.push(`${def.file} is readable by other accounts; restrict it to your account.`);
      } catch {
        warnings.push(`${def.file}: its permissions could not be checked.`);
      }
    }
  }
  const known = new Set([MANIFEST_NAME, ...STORES.map((s) => s.file)]);
  for (const name of readdirSync(directory)) if (!known.has(name)) warnings.push(`An unexpected file is in the backup directory: ${name}`);
  for (const check of stores) problems.push(...check.problems);
  return { ok: problems.length === 0, manifest, stores, problems, warnings };
}

// ---------------------------------------------------------------- restore

export type RestoreAction = "restore" | "replace-damaged" | "keep" | "create-recovery-window" | "skip";

export interface RestorePlanEntry {
  kind: StoreKind;
  action: RestoreAction;
  reason: string;
}

export interface RestoreOptions {
  /** Replace a present store whose integrity check fails (it is copied aside first). */
  replaceDamaged?: boolean;
  /** Restore the credential store when it is missing (revocations made after the backup are undone). */
  restoreCredentials?: boolean;
  env?: NodeJS.ProcessEnv;
  now?: () => number;
  hooks?: OpsHooks;
}

export interface RestoreResult {
  backupId: string;
  plan: RestorePlanEntry[];
  /** Where damaged stores were copied before being replaced. */
  preserved: string[];
  /** The next approval id after the restore (approvals restored), else null. */
  nextApprovalId: number | null;
}

interface RestoreMarker {
  backupId: string;
  startedAt: string;
}

function readMarker(path: string): RestoreMarker | null {
  try {
    const value = JSON.parse(readFileSync(`${path}${RESTORE_MARKER_SUFFIX}`, "utf8")) as Partial<RestoreMarker>;
    return typeof value.backupId === "string" ? (value as RestoreMarker) : null;
  } catch {
    return null;
  }
}

/** The journal content ending at its last complete line (a partial final record is never extended). */
function completeLines(content: Buffer): Buffer {
  const last = content.lastIndexOf(0x0a);
  return last === -1 ? Buffer.alloc(0) : content.subarray(0, last + 1);
}

/**
 * Restores missing (or, if asked, damaged) stores from a verified backup. Never replaces a healthy store,
 * never restores replay or idempotency records. Refuses while the API runs.
 */
export function restoreStores(paths: StorePaths, directory: string, options: RestoreOptions = {}): RestoreResult {
  const env = options.env ?? process.env;
  const now = options.now ?? Date.now;
  const verification = verifyBackup(directory, { now });
  if (!verification.ok || !verification.manifest) throw new OpsError(`The backup failed verification; nothing was restored. ${verification.problems.join(" ")}`);
  const manifest = verification.manifest;
  const locks = takeAllLocks(paths, true);
  try {
    // 1. Plan, from the current state of every store. Nothing is written until the whole plan is acceptable.
    const plan: RestorePlanEntry[] = [];
    const refusals: string[] = [];
    const current = new Map<StoreKind, Buffer | null>();
    for (const def of STORES) {
      const path = def.path(paths);
      const marker = restoreMarkerPresent(path) ? readMarker(path) : null;
      if (restoreMarkerPresent(path) && marker?.backupId !== manifest.id) {
        refusals.push(`An interrupted restore of the ${def.kind} came from a different backup (${marker?.backupId ?? "unknown"}); complete that restore first.`);
        continue;
      }
      let content: Buffer | null;
      try {
        content = readStoreFile(path, maxBytesFor(def.kind, env));
      } catch (error) {
        refusals.push(error instanceof Error ? error.message : `The ${def.kind} cannot be read.`);
        continue;
      }
      current.set(def.kind, content);
      const state = content === null ? "missing" : inspectContent(def.kind, content, now()).status;
      const backup = verification.stores.find((s) => s.kind === def.kind)!;
      if (def.kind === "replay-store") {
        plan.push({ kind: def.kind, action: "keep", reason: state === "missing" ? "never restored; the next start applies the replay fence" : "never restored; the current journal is kept" });
        continue;
      }
      if (def.kind === "idempotency-store") {
        plan.push(
          state === "missing" || marker
            ? { kind: def.kind, action: "create-recovery-window", reason: "records never restored; new keys are refused for one retention period" }
            : { kind: def.kind, action: "keep", reason: "never restored; the current journal is kept" },
        );
        continue;
      }
      let action: RestoreAction;
      let reason: string;
      if (marker) {
        action = "restore";
        reason = "resuming an interrupted restore";
      } else if (state === "missing") {
        action = "restore";
        reason = "the store is missing";
      } else if (state === "verified") {
        action = "keep";
        reason = "the current store is present and healthy (newer than any backup); it is never replaced";
      } else if (options.replaceDamaged) {
        action = "replace-damaged";
        reason = `the current store is ${state}; it is copied aside, then replaced`;
      } else {
        refusals.push(`The current ${def.kind} is ${state}. Start-up recovery handles damage without losing newer records; to replace it with the backup anyway, add --replace-damaged.`);
        continue;
      }
      if (def.kind === "credential-store" && action !== "keep" && !options.restoreCredentials && !marker) {
        plan.push({ kind: def.kind, action: "skip", reason: "credentials are restored only with --restore-credentials (an old copy undoes later revocations)" });
        continue;
      }
      if (action !== "keep" && (!backup.present || !backup.restorable)) {
        refusals.push(`The ${def.kind} needs restoring, but the backup has no usable copy of it (${backup.present ? backup.status : "not in the backup"}).`);
        continue;
      }
      plan.push({ kind: def.kind, action, reason });
    }
    if (refusals.length > 0) throw new OpsError(`Nothing was restored. ${refusals.join(" ")}`);
    const writes = plan.filter((p) => p.action === "restore" || p.action === "replace-damaged" || p.action === "create-recovery-window");
    if (writes.length === 0) return { backupId: manifest.id, plan, preserved: [], nextApprovalId: null };

    // 2. Markers first: until they are removed, the API refuses to open these stores.
    const startedAt = new Date(now()).toISOString();
    for (const p of writes) {
      writeRestrictedFileAtomically(`${byKind(p.kind).path(paths)}${RESTORE_MARKER_SUFFIX}`, `${JSON.stringify({ backupId: manifest.id, startedAt })}\n`, { overwrite: true });
    }
    options.hooks?.afterStep?.("markers");

    // 3. Damaged stores are copied aside, never deleted.
    const preserved: string[] = [];
    for (const p of writes) {
      const content = current.get(p.kind);
      if (p.action !== "replace-damaged" || !content) continue;
      const aside = `${byKind(p.kind).path(paths)}.before-restore-${stamp(now())}`;
      writeRestrictedFileAtomically(aside, content, { overwrite: false });
      preserved.push(aside);
    }

    // 4. Write each store atomically, in order: the audit log first (approval ids are checked against it).
    const backupFile = (kind: StoreKind) => readFileSync(join(directory, byKind(kind).file));
    let nextApprovalId: number | null = null;
    for (const kind of ["audit-log", "approval-store", "idempotency-store", "credential-store"] as const) {
      const p = writes.find((w) => w.kind === kind);
      if (!p) continue;
      const path = byKind(kind).path(paths);
      if (kind === "audit-log" || kind === "credential-store") {
        writeRestrictedFileAtomically(path, backupFile(kind), { overwrite: true });
      } else if (kind === "approval-store") {
        const content = completeLines(backupFile(kind));
        const auditNow = readStoreFile(paths.auditLog, maxBytesFor("audit-log", env));
        const replaced = current.get(kind);
        const highest = Math.max(
          highestApprovalIdIn(content.toString("utf8")),
          replaced ? highestApprovalIdIn(replaced.toString("utf8")) : 0,
          auditNow ? inspectAuditContent(auditNow).highestApprovalId : 0,
        );
        nextApprovalId = highest + 1;
        const label = byKind(kind).label!;
        const record = JSON.stringify({ v: 1, t: "restored", next: nextApprovalId, at: startedAt });
        const line = `${record}\t${chainValue(journalHead(content, label), record)}\n`;
        writeRestrictedFileAtomically(path, Buffer.concat([content, Buffer.from(line, "utf8")]), { overwrite: true });
      } else {
        const label = byKind(kind).label!;
        const record = JSON.stringify({ v: 1, t: "r", u: now() + IDEMPOTENCY_TTL_MS });
        writeRestrictedFileAtomically(path, `${record}\t${chainValue(journalGenesis(label), record)}\n`, { overwrite: true });
      }
      options.hooks?.afterStep?.(`restored:${kind}`);
    }

    // 5. Verify what was written; only then remove the markers. A failure leaves them (the API stays stopped).
    for (const p of writes) {
      const content = readStoreFile(byKind(p.kind).path(paths), maxBytesFor(p.kind, env));
      const check = content ? inspectContent(p.kind, content, now()) : null;
      if (!check || check.status !== "verified") throw new OpsError(`The restored ${p.kind} did not verify; the restore markers were left in place. Run the restore again.`);
    }
    for (const p of writes) rmSync(`${byKind(p.kind).path(paths)}${RESTORE_MARKER_SUFFIX}`, { force: true });
    options.hooks?.afterStep?.("done");
    return { backupId: manifest.id, plan, preserved, nextApprovalId };
  } finally {
    locks.release();
  }
}

// ---------------------------------------------------------------- status

export interface StoreStatus {
  kind: StoreKind;
  path: string;
  present: boolean;
  bytes: number;
  maxBytes: number | null;
  usedPercent: number | null;
  status: FileStatus;
  records: number;
  details: string[];
  lock: LockState;
  restoreMarker: boolean;
  permissionsRestricted: boolean | null;
}

/**
 * Read-only status of every store, for the operator's own terminal (it shows local paths, like the API's
 * start-up log). Safe while the API runs: nothing is locked or written. A record being appended at that
 * moment may show as a truncated final record.
 */
export function storageStatus(paths: StorePaths, options: { env?: NodeJS.ProcessEnv; now?: () => number; checkPermissions?: boolean } = {}): StoreStatus[] {
  const env = options.env ?? process.env;
  const now = options.now ?? Date.now;
  return STORES.map((def) => {
    const path = def.path(paths);
    let maxBytes: number | null = null;
    try {
      maxBytes = maxBytesFor(def.kind, env);
    } catch {
      maxBytes = null;
    }
    const base = { kind: def.kind, path, lock: inspectLock(`${path}.lock`), restoreMarker: restoreMarkerPresent(path) };
    let content: Buffer | null;
    try {
      content = readStoreFile(path, maxBytes ?? Number.MAX_SAFE_INTEGER);
    } catch (error) {
      return { ...base, present: true, bytes: 0, maxBytes, usedPercent: null, status: "unreadable" as const, records: 0, details: [error instanceof Error ? error.message : "unreadable"], permissionsRestricted: null };
    }
    if (content === null) return { ...base, present: false, bytes: 0, maxBytes, usedPercent: null, status: "missing" as const, records: 0, details: [], permissionsRestricted: null };
    const inspection = inspectContent(def.kind, content, now());
    let permissionsRestricted: boolean | null = null;
    if (options.checkPermissions) {
      try {
        permissionsRestricted = isRestrictedToCurrentUser(path);
      } catch {
        permissionsRestricted = false;
      }
    }
    return {
      ...base,
      present: true,
      bytes: content.length,
      maxBytes,
      usedPercent: maxBytes ? Math.floor((content.length / maxBytes) * 1000) / 10 : null,
      status: inspection.status,
      records: inspection.records,
      details: inspection.details,
      permissionsRestricted,
    };
  });
}

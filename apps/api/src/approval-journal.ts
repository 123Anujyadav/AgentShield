import { join } from "node:path";
import type { ApprovalStatus, SimulatedExecution } from "@agentshield/engine";
import {
  ApprovalStoreError,
  createApprovalStore,
  makeRoom,
  MAX_APPROVAL_RECORDS,
  MAX_PENDING_APPROVALS_PER_AGENT,
  type ApprovalPersistence,
  type ApprovalRecord,
  type ApprovalStore,
} from "./approvals.js";
import { IDEMPOTENCY_TTL_MS } from "./idempotency.js";
import { defaultTokenDirectory } from "./security/token.js";
import { JournalWriteError, openJournal, type Journal, type JournalIo } from "./storage/journal.js";
import { newerJsonVersion, type StoreHealth } from "./storage/health.js";

/**
 * Durable approvals (M3-E E12): the approval lifecycle survives a restart.
 *
 * A journal (storage/journal.ts: restricted file, fsync per record, single writer, atomic compaction)
 * holds one JSON record per line:
 *
 *   {"v":1,"t":"create","r":{...the full server-side approval record...}}
 *   {"v":1,"t":"approving","id":"apr-N"}          write-ahead: recheck passed, about to execute
 *   {"v":1,"t":"to","id":"apr-N","s":"<final status>","e":{...execution or null}}
 *   {"v":1,"t":"expiry-recorded","id":"apr-N"}    the EXPIRED audit event was written
 *   {"v":1,"t":"seq","next":N}                    the next approval number (ids are never reused)
 *   {"v":1,"t":"restored","next":N,"at":"<iso>"}  M3-E E14: written by a restore from a backup
 *
 * Every change is recorded before memory changes and before a response is sent, so an id is never
 * returned for an approval that was not stored, and a decision is never reported before it is stored.
 *
 * Recovery (fail-safe, never executes anything):
 * - Only PENDING -> final transitions are honoured; a rejected, expired, blocked or executed approval can
 *   never become pending or approved again, whatever the journal says later.
 * - An `approving` record without its outcome (the API stopped while the approved action was running)
 *   becomes OUTCOME_UNKNOWN.
 * - An unreadable record: the approvals it names (any `apr-N` in it) that are still PENDING become
 *   OUTCOME_UNKNOWN; if it names none, every PENDING approval does (a lost decision must never be undone
 *   by a restart). Their ids are reserved.
 * - A final record cut short by a crash was never acted on (the write completes first), so it is ignored.
 * - After any such recovery the journal is rewritten (atomically) to the recovered state.
 * - A PENDING approval past its expiry is expired as usual on the next access.
 * - M3-E E14: a `restored` record (a restore from a backup) makes every approval still PENDING at that
 *   point OUTCOME_UNKNOWN (it may have been decided, or even executed, after the backup was taken) and
 *   moves the next id past every id that may have been issued since. An older AgentShield reads the
 *   unknown record as damage naming no approval, which quarantines every pending approval as well.
 */

export const APPROVAL_STORE_FILE_NAME = "approvals.journal";
export const APPROVAL_STORE_MAX_BYTES = 256 * 1024 * 1024;
export const APPROVAL_STORE_COMPACT_AT_BYTES = 8 * 1024 * 1024;
export const MAX_APPROVAL_RECORD_BYTES = 128 * 1024;
const APPROVAL_ID = /^apr-([1-9][0-9]{0,8})$/;
const FINAL: ReadonlySet<ApprovalStatus> = new Set(["EXECUTED", "APPROVED_NOT_EXECUTED", "REJECTED", "EXPIRED", "BLOCKED_ON_RECHECK", "OUTCOME_UNKNOWN"]);
const ALL: ReadonlySet<string> = new Set(["PENDING", ...FINAL]);

const UNKNOWN_EXECUTION = (reason: string): SimulatedExecution => ({ executed: false, handler: null, result: null, reason });
const INTERRUPTED = "The API stopped while this approval was being carried out, so whether the simulated action ran is unknown. It will not run.";
const DAMAGED = "This approval's stored record was damaged, so its outcome is unknown. It will not run.";
const RESTORED = "This approval was restored from a backup; whether it was decided after the backup was taken is unknown. It will not run.";

/** APPROVAL_STORE_FILE (an absolute path), else %LOCALAPPDATA%\AgentShield\approvals.journal. */
export function approvalStorePathFromEnv(env: NodeJS.ProcessEnv = process.env): string {
  const configured = env.APPROVAL_STORE_FILE?.trim();
  return configured ? configured : join(defaultTokenDirectory(env), APPROVAL_STORE_FILE_NAME);
}

export interface ApprovalRecovery {
  /** Approvals loaded. */
  records: number;
  pending: number;
  /** Approvals that were being carried out when the API stopped (now OUTCOME_UNKNOWN). */
  interrupted: number;
  /** Unreadable or invalid records, including (M3-E E13) records whose integrity chain did not verify. */
  corrupt: number;
  unverified: number;
  legacyMigrated: boolean;
  damagedCopy: string | null;
  permissionsRestricted: boolean;
  /** PENDING approvals made OUTCOME_UNKNOWN because a damaged record may have held their decision. */
  quarantined: number;
  truncatedTail: boolean;
  /** M3-E E14: PENDING approvals made OUTCOME_UNKNOWN because they came from a restored backup. */
  restored: number;
  /** M3-E E14: a lock left by a process that no longer runs was replaced. */
  staleLockReplaced: boolean;
  /** M3-E E14: the journal did not exist and was created by this start. */
  created: boolean;
}

export interface DurableApprovalStore extends ApprovalStore {
  readonly recovery: ApprovalRecovery;
  /**
   * M3-E E14: makes sure the next id is above `highest` (an id another store, the audit log, shows was
   * issued), recording it durably. Returns true when the next id moved. Ids are never reused.
   */
  reserveIdsThrough(highest: number): boolean;
  /** M3-E E14: capacity and health (numbers only). */
  health(): StoreHealth;
  close(): void;
}

export interface DurableApprovalStoreOptions {
  path: string;
  limit?: number;
  perAgentPendingLimit?: number;
  /** Finished approvals younger than this are not evicted (default: the idempotency retention). */
  finishedRetentionMs?: number;
  maxBytes?: number;
  compactAtBytes?: number;
  io?: JournalIo;
  checkPermissions?: boolean;
}

function idNumber(id: unknown): number {
  const match = typeof id === "string" ? APPROVAL_ID.exec(id) : null;
  return match ? Number(match[1]) : 0;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** A stored approval record with the fields the API relies on. */
function validRecord(value: unknown): value is ApprovalRecord {
  if (!isRecord(value)) return false;
  return (
    idNumber(value.id) > 0 &&
    typeof value.status === "string" &&
    ALL.has(value.status) &&
    typeof value.createdAt === "string" &&
    !Number.isNaN(Date.parse(value.createdAt)) &&
    typeof value.expiresAt === "string" &&
    !Number.isNaN(Date.parse(value.expiresAt)) &&
    isRecord(value.intent) &&
    isRecord(value.action) &&
    Array.isArray(value.findings)
  );
}

export function openDurableApprovalStore(options: DurableApprovalStoreOptions): DurableApprovalStore {
  const maxBytes = options.maxBytes ?? APPROVAL_STORE_MAX_BYTES;
  const journal: Journal = openJournal(options.path, {
    label: "approval store",
    maxBytes,
    maxRecordBytes: Math.min(MAX_APPROVAL_RECORD_BYTES, maxBytes),
    checkPermissions: options.checkPermissions === true,
    unsupportedVersion: newerJsonVersion(1),
    ...(options.io ? { io: options.io } : {}),
  });
  const records = new Map<string, ApprovalRecord>();
  /** M3-E E14: approvals PENDING when a `restored` record was written. */
  const restoredPending = new Set<string>();
  let restoredMarker = false;
  const approving = new Set<string>();
  const damagedIds = new Set<string>();
  let damagedUnknown = false;
  let corrupt = 0;
  let highest = 0;

  for (const [index, line] of journal.records.entries()) {
    // M3-E E13: an unverified record is applied only as far as it is safe (a transition to a final state),
    // and every pending approval it names is quarantined below, exactly like a damaged record.
    const trusted = journal.verified[index] === true;
    let entry: unknown;
    try {
      entry = JSON.parse(line);
    } catch {
      entry = null;
    }
    let ok = false;
    if (isRecord(entry) && entry.v === 1) {
      const id = typeof entry.id === "string" ? entry.id : "";
      const record = id ? records.get(id) : undefined;
      if (entry.t === "create" && validRecord(entry.r) && !records.has(entry.r.id)) {
        const created: ApprovalRecord = { ...entry.r };
        if (created.status !== "EXPIRED") created.expiryEventPending = false;
        records.set(created.id, created);
        highest = Math.max(highest, idNumber(created.id));
        ok = true;
      } else if (entry.t === "approving" && record && record.status === "PENDING") {
        approving.add(id);
        ok = true;
      } else if (entry.t === "to" && record && typeof entry.s === "string" && FINAL.has(entry.s as ApprovalStatus) && (entry.e === null || isRecord(entry.e))) {
        // Only PENDING -> final. A later line can never reopen or change a final decision.
        if (record.status === "PENDING") {
          record.status = entry.s as ApprovalStatus;
          record.execution = (entry.e as SimulatedExecution | null) ?? record.execution ?? null;
          if (record.status === "EXPIRED") record.expiryEventPending = true;
          approving.delete(id);
          ok = true;
        }
      } else if (entry.t === "expiry-recorded" && record && record.status === "EXPIRED") {
        record.expiryEventPending = false;
        ok = true;
      } else if (entry.t === "seq" && Number.isSafeInteger(entry.next) && (entry.next as number) > 0) {
        highest = Math.max(highest, (entry.next as number) - 1);
        ok = true;
      } else if (entry.t === "restored" && Number.isSafeInteger(entry.next) && (entry.next as number) > 0) {
        for (const r of records.values()) if (r.status === "PENDING") restoredPending.add(r.id);
        highest = Math.max(highest, (entry.next as number) - 1);
        restoredMarker = true;
        ok = true;
      }
    }
    if (!ok || !trusted) {
      corrupt += 1;
      const named = [...line.matchAll(/apr-([1-9][0-9]{0,8})/g)].map((m) => `apr-${m[1]}`);
      if (named.length === 0) damagedUnknown = true;
      for (const id of named) {
        damagedIds.add(id);
        highest = Math.max(highest, idNumber(id));
      }
    }
  }

  // Recovery: never execute, never undo a decision.
  let interrupted = 0;
  let quarantined = 0;
  for (const id of approving) {
    const record = records.get(id);
    if (record && record.status === "PENDING") {
      record.status = "OUTCOME_UNKNOWN";
      record.execution = UNKNOWN_EXECUTION(INTERRUPTED);
      interrupted += 1;
    }
  }
  let restored = 0;
  for (const record of records.values()) {
    if (record.status === "PENDING" && restoredPending.has(record.id)) {
      record.status = "OUTCOME_UNKNOWN";
      record.execution = UNKNOWN_EXECUTION(RESTORED);
      restored += 1;
    } else if (record.status === "PENDING" && (damagedUnknown || damagedIds.has(record.id))) {
      record.status = "OUTCOME_UNKNOWN";
      record.execution = UNKNOWN_EXECUTION(DAMAGED);
      quarantined += 1;
    }
  }

  const store = createApprovalStore(options.limit ?? MAX_APPROVAL_RECORDS, options.perAgentPendingLimit ?? MAX_PENDING_APPROVALS_PER_AGENT, {
    finishedRetentionMs: options.finishedRetentionMs ?? IDEMPOTENCY_TTL_MS,
  });
  for (const record of records.values()) store.records.set(record.id, record);
  store.nextId = highest + 1;
  if (store.records.size > store.limit) {
    // More finished records than the limit (it was lowered): drop the oldest evictable ones from memory.
    while (store.records.size > store.limit && makeRoom({ ...store, limit: store.records.size })) {
      if (store.records.size <= store.limit) break;
    }
  }

  const compactAt = options.compactAtBytes ?? APPROVAL_STORE_COMPACT_AT_BYTES;
  const snapshot = () => [JSON.stringify({ v: 1, t: "seq", next: store.nextId }), ...[...store.records.values()].map((r) => JSON.stringify({ v: 1, t: "create", r }))];
  // Record the recovered state, and drop unreadable lines so they are not re-read at every start. A damaged
  // journal is preserved first; a cut-short final record or a pre-E13 journal is rewritten too (M3-E E13).
  const damagedCopy = corrupt > 0 ? journal.preserveCopy() : null;
  if (interrupted > 0 || quarantined > 0 || restoredMarker || corrupt > 0 || journal.truncatedTail || journal.integrity.legacy) journal.rewrite(snapshot());
  let nextCompactAt = Math.max(compactAt, journal.bytes * 2);

  const append = (entry: object) => {
    const line = JSON.stringify(entry);
    try {
      if (journal.bytes >= nextCompactAt) {
        journal.rewrite(snapshot());
        nextCompactAt = Math.max(compactAt, journal.bytes * 2);
      }
      journal.append(line);
    } catch (error) {
      if (error instanceof JournalWriteError && error.code === "full" && !journal.failed) {
        try {
          journal.rewrite(snapshot());
          nextCompactAt = Math.max(compactAt, journal.bytes * 2);
          journal.append(line);
          return;
        } catch (retry) {
          if (retry instanceof JournalWriteError && retry.code === "full" && !journal.failed) throw new ApprovalStoreError("approval-store-full");
          throw new ApprovalStoreError("approval-store-unavailable");
        }
      }
      if (error instanceof JournalWriteError && error.code === "record-too-large") throw new ApprovalStoreError("approval-store-full");
      throw new ApprovalStoreError("approval-store-unavailable");
    }
  };

  const persistence: ApprovalPersistence = {
    readiness: () => (journal.failed ? { ok: false, reason: "approval-store-unavailable" } : { ok: true }),
    created: (record) => append({ v: 1, t: "create", r: record }),
    approving: (id) => append({ v: 1, t: "approving", id }),
    transitioned: (id, status, execution) => append({ v: 1, t: "to", id, s: status, e: execution }),
    expiryRecorded: (id) => append({ v: 1, t: "expiry-recorded", id }),
  };
  store.persistence = persistence;

  let pending = 0;
  for (const record of store.records.values()) if (record.status === "PENDING") pending += 1;
  return Object.assign(store, {
    recovery: {
      records: store.records.size,
      pending,
      interrupted,
      corrupt,
      quarantined,
      unverified: journal.integrity.unverified,
      legacyMigrated: journal.integrity.legacy,
      damagedCopy,
      permissionsRestricted: journal.permissionsRestricted,
      truncatedTail: journal.truncatedTail,
      restored,
      staleLockReplaced: journal.staleLockReplaced,
      created: journal.created,
    },
    reserveIdsThrough(highestIssued: number): boolean {
      if (!Number.isSafeInteger(highestIssued) || highestIssued < store.nextId) return false;
      append({ v: 1, t: "seq", next: highestIssued + 1 });
      store.nextId = highestIssued + 1;
      return true;
    },
    health: (): StoreHealth => ({
      bytes: journal.bytes,
      maxBytes: journal.maxBytes,
      entries: store.records.size,
      entryLimit: store.limit,
      writable: !journal.failed,
      lockHeld: journal.lockHeld(),
      full: false,
    }),
    close: () => journal.close(),
  });
}

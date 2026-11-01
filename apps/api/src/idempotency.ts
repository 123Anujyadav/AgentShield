import { createHash } from "node:crypto";
import { join } from "node:path";
import { openJournal, type Journal, type JournalIo } from "./storage/journal.js";
import { newerJsonVersion, type StoreHealth } from "./storage/health.js";
import { defaultTokenDirectory } from "./security/token.js";

/**
 * Evaluation idempotency (M3-E E11).
 *
 * An agent may put `idempotencyKey` in the body of POST /api/evaluate (the body is signed, so the
 * key is covered by the request signature). The key is scoped to the authenticated agent and bound
 * to a digest of the request's content:
 *
 * - First use: a "started" record is stored durably BEFORE the evaluation runs; the result is stored
 *   as "completed" after it. Only a 200 result or the 503 approval-queue-full answer is stored.
 * - Same agent, same key, same request, completed: the stored result is returned (`idempotentReplay:
 *   true`). Nothing is evaluated or executed again; a CONFIRM returns the original approval reference.
 * - Same key with a different request: refused (409 idempotency-key-reused). Nothing is evaluated.
 * - A duplicate arriving while the first is still running (one process): it waits for the first and
 *   returns the same result. Two evaluations never run for one key.
 * - Started but never completed (the server stopped during the evaluation, or it failed): the outcome
 *   is unknown and the evaluation is NOT repeated (409 idempotency-outcome-unknown).
 * - Records expire IDEMPOTENCY_TTL_MS after they were started; a key used again after that is a new
 *   evaluation. Live records are never evicted: at the per-agent or global limit, new keys are refused
 *   (503 idempotency-capacity) until records expire.
 * - Another agent can never see or reuse an agent's records (the agent id is part of the record key).
 *
 * Idempotency never bypasses checks: authentication, the identity check, request validation, the audit
 * readiness check and rate limits all run before it, and approvals still recheck the current policy and
 * credential when they are approved.
 */

export const IDEMPOTENCY_TTL_MS = 15 * 60 * 1000;
export const MAX_IDEMPOTENCY_KEYS_PER_AGENT = 1_000;
export const MAX_IDEMPOTENCY_KEYS = 10_000;
/** The largest stored record (a completed result); a larger result is not stored, so a retry gets outcome-unknown. */
export const MAX_IDEMPOTENCY_RECORD_BYTES = 16 * 1024;
export const IDEMPOTENCY_STORE_MAX_BYTES = 192 * 1024 * 1024;
export const IDEMPOTENCY_STORE_COMPACT_AT_BYTES = 4 * 1024 * 1024;
export const IDEMPOTENCY_STORE_FILE_NAME = "idempotency.journal";
/** 16 to 64 base64url characters (the SDK uses 22: 128 random bits). */
export const IDEMPOTENCY_KEY = /^[A-Za-z0-9_-]{16,64}$/;

export interface StoredOutcome {
  status: 200 | 503;
  body: Record<string, unknown>;
}

export type IdempotencyBegin =
  | { kind: "new" }
  | { kind: "replay"; outcome: StoredOutcome }
  | { kind: "in-progress"; wait: Promise<StoredOutcome | null> }
  | { kind: "unknown" }
  | { kind: "conflict" }
  | { kind: "full" }
  | { kind: "unavailable" };

export interface IdempotencyStore {
  /** Looks up (agentId, key). On "new" the caller must evaluate and then call complete() or abandon(). */
  begin(agentId: string, key: string, digest: string, now: number): IdempotencyBegin;
  /** Stores the result of a "new" evaluation and releases any waiting duplicates. */
  complete(agentId: string, key: string, outcome: StoredOutcome): void;
  /** The evaluation failed without a storable result: waiting duplicates get null (outcome unknown). */
  abandon(agentId: string, key: string): void;
  /** Live records (for tests and diagnostics). */
  readonly size: number;
  readonly recovery?: IdempotencyRecovery;
  /** M3-E E14: capacity and health of the durable journal (absent in memory-only mode). */
  health?: () => StoreHealth;
  close(): void;
}

export interface IdempotencyRecovery {
  records: number;
  corrupt: number;
  /** M3-E E13: records whose integrity chain did not verify: their keys are outcome-unknown. */
  unverified: number;
  legacyMigrated: boolean;
  damagedCopy: string | null;
  permissionsRestricted: boolean;
  truncatedTail: boolean;
  /** M3-E E14: a lock left by a process that no longer runs was replaced. */
  staleLockReplaced: boolean;
  /**
   * M3-E E14: the journal was missing although other stores hold history (it was deleted or lost), so
   * the records it held are unknown: the recovery window below applies.
   */
  missingWithHistory: boolean;
  /** While recovering (a corrupted record was found, or the journal was lost), keys without a record are refused until then. */
  recoveringUntil: number;
}

/** A canonical digest of the evaluation content: sorted keys, so property order does not matter. */
export function evaluationDigest(content: unknown): string {
  const canonical = (value: unknown): unknown => {
    if (Array.isArray(value)) return value.map(canonical);
    if (value !== null && typeof value === "object") {
      return Object.fromEntries(Object.keys(value).sort().map((k) => [k, canonical((value as Record<string, unknown>)[k])]));
    }
    return value;
  };
  return createHash("sha256").update(JSON.stringify(canonical(content)), "utf8").digest("hex");
}

/** IDEMPOTENCY_STORE_FILE (an absolute path), else %LOCALAPPDATA%\AgentShield\idempotency.journal. */
export function idempotencyStorePathFromEnv(env: NodeJS.ProcessEnv = process.env): string {
  const configured = env.IDEMPOTENCY_STORE_FILE?.trim();
  return configured ? configured : join(defaultTokenDirectory(env), IDEMPOTENCY_STORE_FILE_NAME);
}

interface Entry {
  agentId: string;
  key: string;
  digest: string;
  createdAt: number;
  outcome: StoredOutcome | null;
}

export interface IdempotencyStoreOptions {
  ttlMs?: number;
  perAgentLimit?: number;
  globalLimit?: number;
  maxRecordBytes?: number;
  /** Durable journal; without one the store is in memory only (tests, demos). */
  path?: string;
  maxBytes?: number;
  compactAtBytes?: number;
  now?: () => number;
  io?: JournalIo;
  checkPermissions?: boolean;
  /**
   * M3-E E14: other stores already hold history (the server passes "the audit log has records"). A journal
   * that has to be created then was lost, not new: keys it may have held are refused for one retention
   * period instead of being evaluated a second time.
   */
  historyExpected?: boolean;
}

// A space never occurs in an agent id or a key, so this cannot collide.
const id = (agentId: string, key: string) => `${agentId} ${key}`;

export function createIdempotencyStore(options: IdempotencyStoreOptions = {}): IdempotencyStore {
  const ttlMs = options.ttlMs ?? IDEMPOTENCY_TTL_MS;
  const perAgentLimit = options.perAgentLimit ?? MAX_IDEMPOTENCY_KEYS_PER_AGENT;
  const globalLimit = options.globalLimit ?? MAX_IDEMPOTENCY_KEYS;
  const maxRecordBytes = options.maxRecordBytes ?? MAX_IDEMPOTENCY_RECORD_BYTES;
  const now = options.now ?? Date.now;

  const entries = new Map<string, Entry>();
  const perAgent = new Map<string, number>();
  /** Started in this process and still running: duplicates wait on these. */
  const running = new Map<string, { promise: Promise<StoredOutcome | null>; resolve: (o: StoredOutcome | null) => void }>();
  /** Started but never completed, or completed with a result too large to store: retries get "unknown". */
  const unrecorded = new Set<string>();

  const add = (entry: Entry) => {
    const k = id(entry.agentId, entry.key);
    if (!entries.has(k)) perAgent.set(entry.agentId, (perAgent.get(entry.agentId) ?? 0) + 1);
    entries.set(k, entry);
  };
  const remove = (k: string) => {
    const entry = entries.get(k);
    if (!entry) return;
    entries.delete(k);
    unrecorded.delete(k);
    const left = (perAgent.get(entry.agentId) ?? 1) - 1;
    if (left > 0) perAgent.set(entry.agentId, left);
    else perAgent.delete(entry.agentId);
  };
  const expired = (entry: Entry, at: number) => at - entry.createdAt >= ttlMs;
  const prune = (at: number) => {
    for (const [k, entry] of entries) if (expired(entry, at) && !running.has(k)) remove(k);
  };

  let journal: Journal | null = null;
  let recovery: IdempotencyRecovery | undefined;
  let nextCompactAt = Number.POSITIVE_INFINITY;
  const compactAt = options.compactAtBytes ?? IDEMPOTENCY_STORE_COMPACT_AT_BYTES;
  const beginRecord = (e: Entry) => JSON.stringify({ v: 1, t: "b", a: e.agentId, k: e.key, d: e.digest, c: e.createdAt });
  const completeRecord = (e: Entry, outcome: StoredOutcome) => JSON.stringify({ v: 1, t: "c", a: e.agentId, k: e.key, s: outcome.status, b: outcome.body });

  if (options.path) {
    journal = openJournal(options.path, {
      label: "idempotency store",
      maxBytes: options.maxBytes ?? IDEMPOTENCY_STORE_MAX_BYTES,
      maxRecordBytes: Math.max(maxRecordBytes, 512),
      checkPermissions: options.checkPermissions === true,
      unsupportedVersion: newerJsonVersion(1),
      ...(options.io ? { io: options.io } : {}),
    });
    const startedAt = now();
    let corrupt = 0;
    let markedUntil = 0;
    /** M3-E E13: keys named by unverified records: never replayed from storage, never evaluated as new. */
    const untrusted = new Set<string>();
    for (const [index, line] of journal.records.entries()) {
      const trusted = journal.verified[index] === true;
      if (!trusted) corrupt += 1;
      let record: Record<string, unknown>;
      try {
        record = JSON.parse(line) as Record<string, unknown>;
      } catch {
        if (trusted) corrupt += 1;
        continue;
      }
      const valid =
        record !== null && typeof record === "object" && record.v === 1 && typeof record.a === "string" && typeof record.k === "string" && IDEMPOTENCY_KEY.test(record.k);
      if (record !== null && typeof record === "object" && record.v === 1 && record.t === "r" && Number.isSafeInteger(record.u)) {
        markedUntil = Math.max(markedUntil, record.u as number);
        continue;
      }
      if (!valid) {
        if (trusted) corrupt += 1;
        continue;
      }
      const k = id(record.a as string, record.k as string);
      if (!trusted) untrusted.add(k);
      if (record.t === "b" && typeof record.d === "string" && /^[0-9a-f]{64}$/.test(record.d) && Number.isSafeInteger(record.c)) {
        const entry: Entry = { agentId: record.a as string, key: record.k as string, digest: record.d, createdAt: record.c as number, outcome: null };
        if (!expired(entry, startedAt) && !entries.has(k)) {
          add(entry);
          unrecorded.add(k); // until its completion record is read
        }
      } else if (record.t === "c" && (record.s === 200 || record.s === 503) && record.b !== null && typeof record.b === "object" && !Array.isArray(record.b)) {
        const entry = entries.get(k);
        if (entry && entry.outcome === null) {
          entry.outcome = { status: record.s, body: record.b as Record<string, unknown> };
          unrecorded.delete(k);
        }
      } else if (trusted) {
        corrupt += 1;
      }
    }
    // An unverified record may be a forged result or a forged start: such a key is outcome-unknown.
    for (const k of untrusted) {
      const entry = entries.get(k);
      if (entry) {
        entry.outcome = null;
        unrecorded.add(k);
      }
    }
    // A corrupted record may have been a key's "started" record: until such records could have expired,
    // keys without a record are refused rather than evaluated a second time.
    const missingWithHistory = journal.created && options.historyExpected === true;
    const recoveringUntil = Math.max(markedUntil >= startedAt ? markedUntil : 0, corrupt > 0 || missingWithHistory ? startedAt + ttlMs : 0);
    const damagedCopy = corrupt > 0 ? journal.preserveCopy() : null;
    recovery = {
      records: entries.size,
      corrupt,
      unverified: journal.integrity.unverified,
      legacyMigrated: journal.integrity.legacy,
      damagedCopy,
      permissionsRestricted: journal.permissionsRestricted,
      truncatedTail: journal.truncatedTail,
      staleLockReplaced: journal.staleLockReplaced,
      missingWithHistory,
      recoveringUntil,
    };
    // Record the window durably and drop unreadable lines, so a restart neither forgets nor restarts the
    // window; a cut-short final record or a pre-E13 journal is rewritten too (M3-E E13).
    if (corrupt > 0 || missingWithHistory || journal.truncatedTail || journal.integrity.legacy) journal.rewrite(liveRecords(startedAt));
    nextCompactAt = Math.max(compactAt, journal.bytes * 2);
  }

  /** The records that keep the current state: live entries, and a recovery window still in force. */
  function liveRecords(at: number): string[] {
    prune(at);
    const live: string[] = [];
    for (const [k, e] of entries) {
      live.push(beginRecord(e));
      if (e.outcome && !unrecorded.has(k)) live.push(completeRecord(e, e.outcome));
    }
    if (recovery && recovery.recoveringUntil >= at) live.push(JSON.stringify({ v: 1, t: "r", u: recovery.recoveringUntil }));
    return live;
  }

  /** Durable append (when durable). Throws on failure. */
  function persist(record: string, at: number): void {
    if (!journal) return;
    if (journal.bytes >= nextCompactAt) {
      journal.rewrite(liveRecords(at));
      nextCompactAt = Math.max(compactAt, journal.bytes * 2);
    }
    journal.append(record);
  }

  return {
    get size() {
      return entries.size;
    },
    recovery,
    ...(journal
      ? {
          health: (): StoreHealth => ({
            bytes: journal!.bytes,
            maxBytes: journal!.maxBytes,
            entries: entries.size,
            entryLimit: globalLimit,
            writable: !journal!.failed,
            lockHeld: journal!.lockHeld(),
            full: false,
          }),
        }
      : {}),
    begin(agentId, key, digest, at) {
      const k = id(agentId, key);
      let entry = entries.get(k);
      if (entry && expired(entry, at) && !running.has(k)) {
        remove(k);
        entry = undefined;
      }
      if (entry) {
        if (entry.digest !== digest) return { kind: "conflict" };
        const run = running.get(k);
        if (run) return { kind: "in-progress", wait: run.promise };
        if (entry.outcome && !unrecorded.has(k)) return { kind: "replay", outcome: entry.outcome };
        return { kind: "unknown" };
      }
      if (journal?.failed) return { kind: "unavailable" };
      if (recovery && recovery.recoveringUntil > 0 && at <= recovery.recoveringUntil) return { kind: "unavailable" };
      if ((perAgent.get(agentId) ?? 0) >= perAgentLimit || entries.size >= globalLimit) {
        prune(at);
        if ((perAgent.get(agentId) ?? 0) >= perAgentLimit || entries.size >= globalLimit) return { kind: "full" };
      }
      const created: Entry = { agentId, key, digest, createdAt: at, outcome: null };
      try {
        persist(beginRecord(created), at);
      } catch {
        return { kind: "unavailable" };
      }
      add(created);
      unrecorded.add(k);
      let resolve!: (o: StoredOutcome | null) => void;
      const promise = new Promise<StoredOutcome | null>((r) => (resolve = r));
      running.set(k, { promise, resolve });
      return { kind: "new" };
    },
    complete(agentId, key, outcome) {
      const k = id(agentId, key);
      const entry = entries.get(k);
      const run = running.get(k);
      running.delete(k);
      if (!entry) {
        run?.resolve(null);
        return;
      }
      entry.outcome = outcome;
      const record = completeRecord(entry, outcome);
      let stored = Buffer.byteLength(record, "utf8") + 1 <= maxRecordBytes;
      if (stored) {
        try {
          persist(record, now());
        } catch {
          stored = false;
          console.error(`idempotency-store status=write-failed effect=idempotent-evaluations-refused`);
        }
      }
      if (stored) unrecorded.delete(k);
      // Duplicates already waiting in this process get the result either way; later retries get it only if stored.
      run?.resolve(outcome);
    },
    abandon(agentId, key) {
      const k = id(agentId, key);
      const run = running.get(k);
      running.delete(k);
      run?.resolve(null);
    },
    close() {
      journal?.close();
    },
  };
}

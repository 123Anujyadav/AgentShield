import type { StoreHealth } from "../storage/health.js";

/**
 * Storage health (M3-E E14): one operator-facing view of the four persistent stores' capacity, write
 * health, lock ownership, and what start-up recovery found.
 *
 * - Numbers, flags and fixed warning codes only: never a path, a file name, a record, a key id or anything
 *   an agent sent. It is served on an operator-only route (agents get 403 like every non-agent route).
 * - Read only: nothing is deleted, compacted, rotated or archived because of what it reports.
 * - Levels: "failed" (no more writes: a write failed or the lock was lost), "critical" (full, or at least
 *   95% of a limit), "warning" (at least 80% of a limit, an integrity failure found at start-up, a recovery
 *   window in force, or permissions not restricted), else "ok". The overall level is the worst store's.
 */

export const STORAGE_WARNING_PERCENT = 80;
export const STORAGE_CRITICAL_PERCENT = 95;

export type StoreName = "audit-log" | "replay-store" | "idempotency-store" | "approval-store";
export type HealthLevel = "ok" | "warning" | "critical" | "failed";
const RANK: Record<HealthLevel, number> = { ok: 0, warning: 1, critical: 2, failed: 3 };

/** What start-up recovery found (counts and flags; the path of a preserved copy is never included). */
export interface StartupFindings {
  /** Damaged, unverified, duplicate or unreadable records found when the store was opened. */
  integrityFailures: number;
  damagedCopyPreserved: boolean;
  truncatedRecordRecovered: boolean;
  legacyMigrated: boolean;
  staleLockReplaced: boolean;
  permissionsRestricted: boolean;
  /** Approvals made OUTCOME_UNKNOWN at start-up (interrupted, damaged or restored). Approval store only. */
  approvalsMadeOutcomeUnknown?: number;
  /** The journal was missing although the audit log holds history (idempotency store only). */
  missingWithHistory?: boolean;
}

/** A durable store, as the report reads it. */
export interface StoreSource {
  store: StoreName;
  health(): StoreHealth;
  startup: StartupFindings;
  /** A recovery window still in force (replay: signed requests refused; idempotency: new keys refused), 0 when none. */
  recoveringUntil?: number;
}

export interface StoreHealthReport {
  store: StoreName;
  /** False in memory-only mode (tests and demos): nothing is stored, every number is null. */
  durable: boolean;
  level: HealthLevel;
  bytes: number | null;
  maxBytes: number | null;
  remainingBytes: number | null;
  bytesUsedPercent: number | null;
  entries: number | null;
  entryLimit: number | null;
  entriesUsedPercent: number | null;
  writable: boolean | null;
  lockHeld: boolean | null;
  full: boolean | null;
  recoveringUntil: string | null;
  startup: StartupFindings | null;
  warnings: string[];
}

export interface StorageHealthReport {
  level: HealthLevel;
  generatedAt: string;
  thresholds: { warningPercent: number; criticalPercent: number };
  stores: StoreHealthReport[];
}

const ORDER: readonly StoreName[] = ["audit-log", "approval-store", "idempotency-store", "replay-store"];
const percent = (used: number, limit: number) => (limit > 0 ? Math.floor((used / limit) * 1000) / 10 : 0);

function reportStore(source: StoreSource, now: number): StoreHealthReport {
  const h = source.health();
  const s = source.startup;
  const warnings: string[] = [];
  let level: HealthLevel = "ok";
  const raise = (to: HealthLevel, code: string) => {
    warnings.push(code);
    if (RANK[to] > RANK[level]) level = to;
  };
  const bytesUsed = percent(h.bytes, h.maxBytes);
  const entriesUsed = h.entries !== null && h.entryLimit !== null ? percent(h.entries, h.entryLimit) : null;

  if (!h.lockHeld) raise("failed", "lock-lost");
  if (!h.writable) raise("failed", "write-failed");
  if (h.full) raise("critical", "storage-full");
  else if (bytesUsed >= STORAGE_CRITICAL_PERCENT) raise("critical", "bytes-above-critical");
  else if (bytesUsed >= STORAGE_WARNING_PERCENT) raise("warning", "bytes-above-warning");
  if (entriesUsed !== null && entriesUsed >= STORAGE_CRITICAL_PERCENT) raise("critical", "entries-above-critical");
  else if (entriesUsed !== null && entriesUsed >= STORAGE_WARNING_PERCENT) raise("warning", "entries-above-warning");
  if (s.integrityFailures > 0) raise("warning", "integrity-failure-at-startup");
  const recovering = source.recoveringUntil !== undefined && source.recoveringUntil >= now;
  if (recovering) raise("warning", "recovering");
  if (!s.permissionsRestricted) raise("warning", "permissions-not-restricted");
  if (s.missingWithHistory) raise("warning", "journal-missing-at-startup");
  // Informational: reported, but not a reason to raise the level.
  if ((s.approvalsMadeOutcomeUnknown ?? 0) > 0) warnings.push("approvals-made-outcome-unknown-at-startup");
  if (s.staleLockReplaced) warnings.push("stale-lock-replaced-at-startup");
  if (s.truncatedRecordRecovered) warnings.push("truncated-record-recovered-at-startup");
  if (s.legacyMigrated) warnings.push("migrated-at-startup");

  return {
    store: source.store,
    durable: true,
    level,
    bytes: h.bytes,
    maxBytes: h.maxBytes,
    remainingBytes: Math.max(0, h.maxBytes - h.bytes),
    bytesUsedPercent: bytesUsed,
    entries: h.entries,
    entryLimit: h.entryLimit,
    entriesUsedPercent: entriesUsed,
    writable: h.writable,
    lockHeld: h.lockHeld,
    full: h.full,
    recoveringUntil: recovering ? new Date(source.recoveringUntil!).toISOString() : null,
    startup: { ...s },
    warnings,
  };
}

const memoryOnly = (store: StoreName): StoreHealthReport => ({
  store,
  durable: false,
  level: "ok",
  bytes: null,
  maxBytes: null,
  remainingBytes: null,
  bytesUsedPercent: null,
  entries: null,
  entryLimit: null,
  entriesUsedPercent: null,
  writable: null,
  lockHeld: null,
  full: null,
  recoveringUntil: null,
  startup: null,
  warnings: [],
});

export function storageHealthReport(sources: readonly StoreSource[], now: number): StorageHealthReport {
  const stores = ORDER.map((name) => {
    const source = sources.find((s) => s.store === name);
    return source ? reportStore(source, now) : memoryOnly(name);
  });
  const level = stores.reduce<HealthLevel>((worst, s) => (RANK[s.level] > RANK[worst] ? s.level : worst), "ok");
  return {
    level,
    generatedAt: new Date(now).toISOString(),
    thresholds: { warningPercent: STORAGE_WARNING_PERCENT, criticalPercent: STORAGE_CRITICAL_PERCENT },
    stores,
  };
}

/** One log line per store: `storage store=<name> level=<level> ... warnings=<codes>`. Numbers only. */
export function storageLogLine(s: StoreHealthReport): string {
  const parts = [`storage store=${s.store}`, `level=${s.level}`];
  if (s.bytesUsedPercent !== null) parts.push(`bytesUsedPercent=${s.bytesUsedPercent}`, `remainingBytes=${s.remainingBytes}`);
  if (s.entriesUsedPercent !== null) parts.push(`entries=${s.entries}/${s.entryLimit}`);
  parts.push(`warnings=${s.warnings.length > 0 ? s.warnings.join(",") : "none"}`);
  return parts.join(" ");
}

/**
 * Logs a store's line whenever its level or warnings change (and every store that is not ok on the first
 * check). Never deletes, rotates or compacts anything. `check` is called at start-up and on a timer.
 */
export function createStorageMonitor(report: () => StorageHealthReport, log: (line: string, level: HealthLevel) => void): { check(): void } {
  const last = new Map<StoreName, string>();
  return {
    check() {
      for (const s of report().stores) {
        if (!s.durable) continue;
        const key = `${s.level}|${s.warnings.join(",")}`;
        const previous = last.get(s.store);
        last.set(s.store, key);
        if (previous === key) continue;
        if (previous === undefined && s.level === "ok") continue;
        log(storageLogLine(s), s.level);
      }
    },
  };
}

import type { DurableApprovalStore } from "../approval-journal.js";
import type { ApprovalStore } from "../approvals.js";
import type { AuditLog } from "../audit/file-audit-log.js";
import type { DurableNonceCache } from "../agents/durable-nonce-cache.js";
import type { NonceCache } from "../agents/nonce-cache.js";
import type { IdempotencyStore } from "../idempotency.js";
import type { StoreSource } from "./storage-health.js";

/**
 * M3-E E14: the storage-health sources for the stores an app was given. Memory-only stores (tests, demos)
 * have no `health()` and are reported as not durable. Paths (such as a preserved damaged copy) are reduced
 * to flags here, so they can never reach a response.
 */
export function storeSources(deps: { auditLog?: AuditLog; nonceCache?: NonceCache; idempotencyStore?: IdempotencyStore; approvalStore?: ApprovalStore }): StoreSource[] {
  const sources: StoreSource[] = [];
  const audit = deps.auditLog;
  if (audit?.health) {
    const r = audit.recovery;
    sources.push({
      store: "audit-log",
      health: () => audit.health!(),
      startup: {
        // A terminated partial record is a crash artifact, reported on its own below.
        integrityFailures: r.unverified + r.duplicates + r.malformed - (r.truncatedTail ? 1 : 0),
        damagedCopyPreserved: false,
        truncatedRecordRecovered: r.truncatedTail,
        legacyMigrated: false,
        staleLockReplaced: r.staleLockReplaced,
        permissionsRestricted: r.permissionsRestricted,
      },
    });
  }
  const replay = deps.nonceCache as Partial<DurableNonceCache> | undefined;
  if (replay?.health && replay.recovery) {
    const r = replay.recovery;
    sources.push({
      store: "replay-store",
      health: () => replay.health!(),
      startup: {
        integrityFailures: r.corrupt,
        damagedCopyPreserved: r.damagedCopy !== null,
        truncatedRecordRecovered: r.truncatedTail,
        legacyMigrated: r.legacyMigrated,
        staleLockReplaced: r.staleLockReplaced,
        permissionsRestricted: replay.permissionsRestricted !== false,
      },
      recoveringUntil: r.recoveringUntil,
    });
  }
  const idem = deps.idempotencyStore;
  if (idem?.health && idem.recovery) {
    const r = idem.recovery;
    sources.push({
      store: "idempotency-store",
      health: () => idem.health!(),
      startup: {
        integrityFailures: r.corrupt,
        damagedCopyPreserved: r.damagedCopy !== null,
        truncatedRecordRecovered: r.truncatedTail,
        legacyMigrated: r.legacyMigrated,
        staleLockReplaced: r.staleLockReplaced,
        permissionsRestricted: r.permissionsRestricted,
        missingWithHistory: r.missingWithHistory,
      },
      recoveringUntil: r.recoveringUntil,
    });
  }
  const approvals = deps.approvalStore as Partial<DurableApprovalStore> | undefined;
  if (approvals?.health && approvals.recovery) {
    const r = approvals.recovery;
    sources.push({
      store: "approval-store",
      health: () => approvals.health!(),
      startup: {
        integrityFailures: r.corrupt,
        damagedCopyPreserved: r.damagedCopy !== null,
        truncatedRecordRecovered: r.truncatedTail,
        legacyMigrated: r.legacyMigrated,
        staleLockReplaced: r.staleLockReplaced,
        permissionsRestricted: r.permissionsRestricted,
        approvalsMadeOutcomeUnknown: r.interrupted + r.quarantined + r.restored,
      },
    });
  }
  return sources;
}

import { createNonceCache, DEFAULT_NONCE_GLOBAL_LIMIT, DEFAULT_NONCE_PER_KEY_LIMIT, type NonceCache, type NonceCheck } from "./nonce-cache.js";
import { openJournal, type Journal, type JournalIo } from "../storage/journal.js";
import { join } from "node:path";
import { defaultTokenDirectory } from "../security/token.js";

/**
 * Durable replay protection (M3-E E11).
 *
 * The in-memory replay cache (nonce-cache.ts) decides, with its limits unchanged. Every nonce it
 * accepts is then appended to a journal and fsynced BEFORE the request may proceed, so a restart
 * cannot reset replay protection: at start-up the still-live nonces are loaded back.
 *
 * Records (one per line): `n1 <keyId> <nonce> <expiresAt ms>`, and `r1 <until ms>` for a recovery
 * window still in force. Nonces and key ids are not secret.
 *
 * Fail closed:
 * - The journal cannot be written (disk full, I/O error, full store): the request is refused with
 *   "store-unavailable" (HTTP 503) and the journal stops accepting writes until a restart.
 * - Replay state may be incomplete at start-up (the store is new or was deleted, a record is
 *   corrupted, or a loaded nonce no longer fits the limits): `recoveringUntil` is set to start-up
 *   time + the allowed skew, and every request with a timestamp up to then is refused (503). Any
 *   request a previous process accepted has a timestamp no later than that, so none can be accepted
 *   again; requests signed after that moment are unaffected.
 * - A final record cut short by a crash belongs to a request that never proceeded (the write is
 *   completed before a request continues), so it is skipped without the fallback.
 *
 * Bounded: live nonces are capped by the cache limits (600 per key, 100,000 in total); the journal
 * is compacted to its live records when it grows, and never exceeds REPLAY_STORE_MAX_BYTES.
 */

export const REPLAY_STORE_FILE_NAME = "replay-nonces.journal";
export const REPLAY_STORE_MAX_BYTES = 32 * 1024 * 1024;
export const REPLAY_STORE_COMPACT_AT_BYTES = 1024 * 1024;
const RECORD = /^n1 ([0-9a-f]{16}) ([A-Za-z0-9_-]{22}) ([1-9][0-9]{12})$/;
const MARKER = /^r1 ([1-9][0-9]{12})$/;

/** REPLAY_STORE_FILE (an absolute path), else %LOCALAPPDATA%\AgentShield\replay-nonces.journal. */
export function replayStorePathFromEnv(env: NodeJS.ProcessEnv = process.env): string {
  const configured = env.REPLAY_STORE_FILE?.trim();
  return configured ? configured : join(defaultTokenDirectory(env), REPLAY_STORE_FILE_NAME);
}

export interface ReplayRecovery {
  /** Live nonces loaded back into the cache. */
  loaded: number;
  /** Lines that are not valid records (excluding a final record cut short by a crash). */
  corrupt: number;
  /** Valid, live records that could not be loaded (limits lowered since they were written). */
  dropped: number;
  truncatedTail: boolean;
  created: boolean;
  /** Requests with a timestamp up to (and including) this time are refused; 0 when not recovering. */
  recoveringUntil: number;
}

export interface DurableNonceCache extends NonceCache {
  readonly recovery: ReplayRecovery;
  readonly recoveringUntil: number;
  close(): void;
}

export interface DurableNonceCacheOptions {
  path: string;
  now: () => number;
  /** The allowed clock skew, in ms (the verifier's). */
  skewMs: number;
  perKeyLimit?: number;
  globalLimit?: number;
  maxBytes?: number;
  compactAtBytes?: number;
  io?: JournalIo;
}

const recordOf = (keyId: string, nonce: string, expiresAt: number) => `n1 ${keyId} ${nonce} ${expiresAt}`;

export function openDurableNonceCache(options: DurableNonceCacheOptions): DurableNonceCache {
  const { now, skewMs } = options;
  const memory = createNonceCache({ now, perKeyLimit: options.perKeyLimit ?? DEFAULT_NONCE_PER_KEY_LIMIT, globalLimit: options.globalLimit ?? DEFAULT_NONCE_GLOBAL_LIMIT });
  const journal: Journal = openJournal(options.path, { label: "replay store", maxBytes: options.maxBytes ?? REPLAY_STORE_MAX_BYTES, maxRecordBytes: 128, ...(options.io ? { io: options.io } : {}) });
  const compactAt = options.compactAtBytes ?? REPLAY_STORE_COMPACT_AT_BYTES;

  // Live records, for compaction.
  const live = new Map<string, { keyId: string; nonce: string; expiresAt: number }>();
  const startedAt = now();
  let corrupt = 0;
  let dropped = 0;
  let loaded = 0;
  let markedUntil = 0;
  for (const line of journal.records) {
    const marker = MARKER.exec(line);
    if (marker) {
      markedUntil = Math.max(markedUntil, Number(marker[1]));
      continue;
    }
    const match = RECORD.exec(line);
    if (!match) {
      corrupt += 1;
      continue;
    }
    const [, keyId, nonce, expiresText] = match;
    const expiresAt = Number(expiresText);
    if (expiresAt < startedAt) continue;
    const outcome = memory.checkAndInsert(keyId!, nonce!, expiresAt, startedAt);
    if (outcome === "accepted") {
      loaded += 1;
      live.set(`${keyId} ${nonce}`, { keyId: keyId!, nonce: nonce!, expiresAt });
    } else if (outcome !== "replay") {
      dropped += 1;
    }
  }
  // A recovery window from an earlier start that has not passed yet stays in force.
  const recoveringUntil = Math.max(markedUntil >= startedAt ? markedUntil : 0, journal.created || corrupt > 0 || dropped > 0 ? startedAt + skewMs : 0);
  const liveRecords = (at: number) => {
    for (const [id, entry] of live) if (entry.expiresAt < at) live.delete(id);
    const records = [...live.values()].map((e) => recordOf(e.keyId, e.nonce, e.expiresAt));
    if (recoveringUntil >= at) records.push(`r1 ${recoveringUntil}`);
    return records;
  };
  // While recovering, record the window durably (so a restart inside it keeps it) and drop unreadable lines
  // (so they do not start a new window at every restart). A failure here stops start-up.
  if (recoveringUntil > 0 && (journal.created || corrupt > 0 || dropped > 0)) journal.rewrite(liveRecords(startedAt));
  let nextCompactAt = Math.max(compactAt, journal.bytes * 2);

  function compact(at: number): void {
    journal.rewrite(liveRecords(at));
    nextCompactAt = Math.max(compactAt, journal.bytes * 2);
  }

  return {
    recovery: { loaded, corrupt, dropped, truncatedTail: journal.truncatedTail, created: journal.created, recoveringUntil },
    recoveringUntil,
    checkAndInsert(keyId: string, nonce: string, expiresAt: number, at?: number): NonceCheck {
      if (journal.failed) return "store-unavailable";
      const current = at ?? now();
      const outcome = memory.checkAndInsert(keyId, nonce, expiresAt, current);
      if (outcome !== "accepted") return outcome;
      // Persist before the request may proceed. On failure the nonce stays in memory (a resend is still a
      // replay) and the request is refused.
      try {
        if (journal.bytes >= nextCompactAt) compact(current);
        journal.append(recordOf(keyId, nonce, expiresAt));
      } catch {
        return "store-unavailable";
      }
      live.set(`${keyId} ${nonce}`, { keyId, nonce, expiresAt });
      return "accepted";
    },
    get size() {
      return memory.size;
    },
    sizeFor(keyId: string) {
      return memory.sizeFor(keyId);
    },
    close() {
      journal.close();
    },
  };
}

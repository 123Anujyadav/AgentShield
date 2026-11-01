/**
 * M3-E E14: what each persistent store reports about its own capacity and health, for the operator
 * storage-health route, start-up warnings and the storage monitor. Numbers and flags only: never a
 * path, a record, or anything an agent sent.
 */
export interface StoreHealth {
  /** Bytes in the file now, and the hard limit it never exceeds. */
  bytes: number;
  maxBytes: number;
  /** Live entries held, and the limit at which new ones are refused (null when bytes are the only limit). */
  entries: number | null;
  entryLimit: number | null;
  /** False after a failed write or a lost lock: the store accepts no more writes in this process. */
  writable: boolean;
  /** Whether this process still holds the store's single-writer lock. */
  lockHeld: boolean;
  /** The store has no room for another record (the audit log; journals compact instead). */
  full: boolean;
}

/** A record version newer than `supported` in a JSON record written as {"v":N,...}, else null. */
export function newerJsonVersion(supported: number): (record: string) => number | null {
  return (record) => {
    const match = /^\{"v":([0-9]{1,9})[,}]/.exec(record);
    return match && Number(match[1]) > supported ? Number(match[1]) : null;
  };
}

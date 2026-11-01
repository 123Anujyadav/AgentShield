import { FileSecurityError } from "../agents/file-security.js";
import { backupStores, defaultBackupDirectory, OpsError, restoreStores, storageStatus, storePathsFromEnv, verifyBackup, type StorePaths } from "./backup.js";

/**
 * `npm run ops -- <command>` (M3-E E14): storage status, offline backup, backup verification and restore.
 *
 *   status                                    read-only status of every store (safe while the API runs)
 *   backup [--out <absolute dir>]             offline backup (the API must be stopped)
 *   verify-backup --dir <absolute dir>        verify a backup without changing anything
 *   restore --dir <absolute dir> [--replace-damaged] [--restore-credentials]
 *                                             fill in missing stores from a backup (the API must be stopped)
 *
 * Output: names, counts, sizes, fixed status codes and local paths (this is the operator's own terminal,
 * like the API's start-up log). Never a record, a key or a credential. Exit code 0 on success, 1 when
 * something needs attention or failed, 2 for a usage error.
 */

export interface OpsCliDeps {
  env: NodeJS.ProcessEnv;
  now: () => number;
  out: (line: string) => void;
  err: (line: string) => void;
  /** Overrides the store paths (tests); defaults to the API's own (environment and defaults). */
  paths?: StorePaths;
  /** Check Windows ACLs (slow); the real CLI does. */
  checkPermissions?: boolean;
}

const USAGE = [
  "Usage: npm run ops -- <command>",
  "  status",
  "  backup [--out <absolute dir>]",
  "  verify-backup --dir <absolute dir>",
  "  restore --dir <absolute dir> [--replace-damaged] [--restore-credentials]",
];

function parse(args: readonly string[], values: readonly string[], switches: readonly string[]): { values: Map<string, string>; switches: Set<string> } | null {
  const v = new Map<string, string>();
  const s = new Set<string>();
  for (let i = 0; i < args.length; i += 1) {
    const arg = args[i]!;
    const name = arg.startsWith("--") ? arg.slice(2) : null;
    if (name && values.includes(name) && i + 1 < args.length && !v.has(name)) v.set(name, args[++i]!);
    else if (name && switches.includes(name)) s.add(name);
    else return null;
  }
  return { values: v, switches: s };
}

export function runOpsCli(argv: readonly string[], deps: OpsCliDeps): number {
  const [command, ...rest] = argv;
  const paths = deps.paths ?? storePathsFromEnv(deps.env);
  const usage = () => {
    for (const line of USAGE) deps.err(line);
    return 2;
  };
  try {
    if (command === "status") {
      if (rest.length > 0) return usage();
      let attention = false;
      const statuses = storageStatus(paths, { env: deps.env, now: deps.now, checkPermissions: deps.checkPermissions === true });
      // M3-E E15: a store missing while another holds records was lost (a fresh installation has none at all).
      const history = statuses.some((s) => s.present && s.records > 0);
      for (const s of statuses) {
        const size = s.present ? ` bytes=${s.bytes}${s.maxBytes ? ` maxBytes=${s.maxBytes} usedPercent=${s.usedPercent}` : ""} records=${s.records}` : "";
        const lock = s.lock.state === "free" ? "free" : s.lock.state === "held" ? `held-by-pid-${s.lock.pid}` : `stale${s.lock.pid ? `-pid-${s.lock.pid}` : ""}`;
        const perms = s.permissionsRestricted === false ? " permissions=not-restricted" : "";
        deps.out(`${s.kind} status=${s.status}${size} lock=${lock}${s.restoreMarker ? " restore=interrupted" : ""}${perms}${s.details.length ? ` details=${s.details.join(",")}` : ""}`);
        deps.out(`  path=${s.path}`);
        if (!s.present && history) deps.out("  note: missing while other stores hold records: it was lost or deleted (see docs/operations.md, Restore)");
        if (s.status === "damaged" || s.status === "unsupported-version" || s.status === "unreadable" || s.restoreMarker || s.permissionsRestricted === false || (s.usedPercent ?? 0) >= 80) attention = true;
        if (!s.present && history) attention = true;
      }
      deps.out(attention ? "storage status: ATTENTION (see docs/operations.md)" : "storage status: ok");
      return attention ? 1 : 0;
    }

    if (command === "backup") {
      const options = parse(rest, ["out"], []);
      if (!options) return usage();
      const directory = options.values.get("out") ?? defaultBackupDirectory(deps.env, deps.now());
      const result = backupStores(paths, directory, { env: deps.env, now: deps.now });
      for (const kind of result.staleLocksReplaced) deps.out(`note: a stale ${kind} lock (from a process that no longer runs) was replaced`);
      for (const e of result.manifest.stores) {
        deps.out(`${e.kind} ${e.present ? `copied bytes=${e.bytes} records=${e.records} status=${e.status}${e.restorable ? "" : " restorable=no"}` : "not present"}`);
      }
      deps.out(`backup complete: id=${result.manifest.id} directory=${result.directory}`);
      deps.out("Keep a copy on another disk; it is restricted to your Windows account. Verify it with: npm run ops -- verify-backup --dir <directory>");
      const damaged = result.manifest.stores.filter((e) => e.present && e.status !== "verified");
      if (damaged.length > 0) deps.out(`warning: ${damaged.map((e) => e.kind).join(", ")} failed integrity checks and cannot be restored from this backup`);
      return damaged.length > 0 ? 1 : 0;
    }

    if (command === "verify-backup") {
      const options = parse(rest, ["dir"], []);
      if (!options || !options.values.has("dir")) return usage();
      const v = verifyBackup(options.values.get("dir")!, { now: deps.now, checkPermissions: deps.checkPermissions === true });
      if (v.manifest) deps.out(`backup id=${v.manifest.id} createdAt=${v.manifest.createdAt}`);
      for (const s of v.stores) {
        deps.out(`${s.kind} ${s.present ? `status=${s.status} records=${s.records}${s.pending !== undefined ? ` pending=${s.pending}` : ""} restorable=${s.restorable ? "yes" : "no"}` : "not in backup"}`);
      }
      for (const w of v.warnings) deps.out(`warning: ${w}`);
      for (const p of v.problems) deps.err(`problem: ${p}`);
      deps.out(v.ok ? "backup verified" : "backup verification FAILED");
      return v.ok ? 0 : 1;
    }

    if (command === "restore") {
      const options = parse(rest, ["dir"], ["replace-damaged", "restore-credentials"]);
      if (!options || !options.values.has("dir")) return usage();
      const result = restoreStores(paths, options.values.get("dir")!, {
        env: deps.env,
        now: deps.now,
        replaceDamaged: options.switches.has("replace-damaged"),
        restoreCredentials: options.switches.has("restore-credentials"),
      });
      for (const p of result.plan) deps.out(`${p.kind} ${p.action}: ${p.reason}`);
      for (const path of result.preserved) deps.out(`preserved the replaced store at ${path}`);
      const wrote = result.plan.some((p) => p.action !== "keep" && p.action !== "skip");
      if (!wrote) {
        deps.out("nothing to restore: every restorable store is present and healthy");
        return 0;
      }
      deps.out(`restore complete from backup ${result.backupId}.`);
      if (result.nextApprovalId !== null) deps.out(`Approval ids continue at apr-${result.nextApprovalId}. Pending approvals from the backup become OUTCOME_UNKNOWN at the next start.`);
      deps.out("Start the API and read its start-up log; signed requests dated before the start are refused for the replay fence, and new idempotency keys may be refused for 15 minutes.");
      return 0;
    }
  } catch (error) {
    if (error instanceof OpsError || error instanceof FileSecurityError) {
      deps.err(`error: ${error.message}`);
      return 1;
    }
    deps.err("error: the operation failed unexpectedly; nothing further was changed.");
    return 1;
  }
  return usage();
}

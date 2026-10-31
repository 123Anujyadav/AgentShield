import { closeSync, mkdirSync, openSync, rmSync } from "node:fs";
import { dirname } from "node:path";
import {
  CredentialConfigError,
  credentialFilePath,
  issueCredential,
  KEY_ID_PATTERN,
  MAX_ACTIVE_PER_AGENT,
  readCredentialFile,
  recordStatus,
  serializeCredentialDocument,
  validateCredentialRecords,
  type CredentialRecord,
} from "./credentials.js";
import { FileSecurityError, writeRestrictedFileAtomically } from "./file-security.js";

/**
 * Agent credential administration (M3-D):
 *
 *   npm run agent-credential -w @agentshield/api -- <command> [options]
 *
 *   create --agent <id> [--label <text>] [--days <1-365>] [--out <file>]
 *   list   [--json]
 *   revoke --key <keyId>
 *   rotate --key <keyId> [--label <text>] [--days <1-365>] [--out <file>] [--revoke-old]
 *
 * Every command accepts --file <store> (default: AGENT_CREDENTIAL_FILE, else
 * %LOCALAPPDATA%\AgentShield\agent-credentials.json).
 *
 * A new credential is shown exactly once: on standard output, or written to
 * --out (a new file readable only by the current user) and then not shown.
 * No command takes a secret as an argument, and list and revoke never show
 * secrets or hashes. The store is validated before every write, written
 * atomically, restricted to the current user, and revoked records are kept.
 */

export interface CliIo {
  env: NodeJS.ProcessEnv;
  now: () => number;
  out: (line: string) => void;
  err: (line: string) => void;
}

class CliError extends Error {}
class UsageError extends Error {}

const COMMANDS: Record<string, { values: string[]; switches: string[] }> = {
  create: { values: ["agent", "label", "days", "out", "file"], switches: [] },
  list: { values: ["file"], switches: ["json"] },
  revoke: { values: ["key", "file"], switches: [] },
  rotate: { values: ["key", "label", "days", "out", "file"], switches: ["revoke-old"] },
};

const USAGE = [
  "Usage: agent-credential <command> [options]",
  "  create --agent <id> [--label <text>] [--days <1-365>] [--out <file>]",
  "  list   [--json]",
  "  revoke --key <keyId>",
  "  rotate --key <keyId> [--label <text>] [--days <1-365>] [--out <file>] [--revoke-old]",
  "All commands accept --file <store>. The default store is AGENT_CREDENTIAL_FILE, else %LOCALAPPDATA%\\AgentShield\\agent-credentials.json.",
];

type Options = { values: Map<string, string>; switches: Set<string> };

function parseArgs(command: string, args: string[]): Options {
  const spec = COMMANDS[command]!;
  const values = new Map<string, string>();
  const switches = new Set<string>();
  for (let i = 0; i < args.length; i += 1) {
    const arg = args[i]!;
    const name = arg.startsWith("--") ? arg.slice(2) : null;
    if (name !== null && spec.switches.includes(name)) {
      if (switches.has(name)) throw new UsageError(`--${name} is given more than once.`);
      switches.add(name);
    } else if (name !== null && spec.values.includes(name)) {
      const value = args[i + 1];
      if (value === undefined || value.startsWith("--")) throw new UsageError(`--${name} needs a value.`);
      if (values.has(name)) throw new UsageError(`--${name} is given more than once.`);
      values.set(name, value);
      i += 1;
    } else {
      // The argument itself is never echoed: it could be something pasted by mistake.
      throw new UsageError(`Unknown or misplaced argument at position ${i + 1} for "${command}".`);
    }
  }
  return { values, switches };
}

function days(options: Options): number | undefined {
  const raw = options.values.get("days");
  if (raw === undefined) return undefined;
  if (!/^\d{1,3}$/.test(raw)) throw new UsageError("--days must be a whole number from 1 to 365.");
  return Number(raw);
}

/** One credential command at a time: a second one refuses to run rather than lose an update. */
function withStoreLock<T>(storePath: string, run: () => T): T {
  const lock = `${storePath}.lock`;
  mkdirSync(dirname(storePath), { recursive: true, mode: 0o700 });
  try {
    closeSync(openSync(lock, "wx"));
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "EEXIST") {
      throw new CliError(`Another credential command is running, or one was interrupted. If none is running, delete ${lock}.`);
    }
    throw error;
  }
  try {
    return run();
  } finally {
    rmSync(lock, { force: true });
  }
}

function findRecord(records: CredentialRecord[], options: Options): CredentialRecord {
  const keyId = options.values.get("key");
  if (keyId === undefined) throw new UsageError("--key <keyId> is required.");
  if (!KEY_ID_PATTERN.test(keyId)) throw new UsageError("--key must be a 16-digit lower-case hex key id (see list).");
  const record = records.find((r) => r.keyId === keyId);
  if (!record) throw new CliError("No credential has that key id.");
  return record;
}

/**
 * Writes a new credential's secret (to --out, or to standard output) and the
 * updated store. With --out the secret file is written first, and removed again
 * if the store cannot be written, so a stored credential always has its secret delivered.
 */
function deliver(io: CliIo, storePath: string, next: CredentialRecord[], issued: { credential: string; record: CredentialRecord }, outPath: string | undefined): void {
  if (outPath !== undefined) writeRestrictedFileAtomically(outPath, `${issued.credential}\n`, { overwrite: false });
  try {
    writeRestrictedFileAtomically(storePath, serializeCredentialDocument(next), { overwrite: true });
  } catch (error) {
    if (outPath !== undefined) rmSync(outPath, { force: true });
    throw error;
  }
  const { record } = issued;
  io.out(`Created credential ${record.keyId} for agent ${record.agentId}; it expires ${record.expiresAt}.`);
  if (outPath !== undefined) {
    io.out(`The credential was written to ${outPath} (readable only by the current user). It is not shown here.`);
  } else {
    io.out("This is the only time the credential is shown. Deliver it to the agent now; it cannot be recovered:");
    io.out(issued.credential);
  }
}

function create(io: CliIo, storePath: string, options: Options): void {
  const agentId = options.values.get("agent");
  if (agentId === undefined) throw new UsageError("--agent <id> is required.");
  withStoreLock(storePath, () => {
    const now = io.now();
    const records = readCredentialFile(storePath, now);
    const active = records.filter((r) => r.agentId === agentId && recordStatus(r, now) === "active").length;
    if (active >= MAX_ACTIVE_PER_AGENT) throw new CliError(`That agent already has ${MAX_ACTIVE_PER_AGENT} active credentials. Revoke one first.`);
    const issued = issueCredential({ agentId, now, takenKeyIds: new Set(records.map((r) => r.keyId)), label: options.values.get("label") ?? null, days: days(options) });
    const next = validateCredentialRecords([...records, issued.record], now);
    deliver(io, storePath, next, issued, options.values.get("out"));
  });
}

function rotate(io: CliIo, storePath: string, options: Options): void {
  withStoreLock(storePath, () => {
    const now = io.now();
    const records = readCredentialFile(storePath, now);
    const old = findRecord(records, options);
    if (recordStatus(old, now) !== "active") throw new CliError("That credential is not active; use create for a new one.");
    const revokeOld = options.switches.has("revoke-old");
    const kept = revokeOld ? records.map((r) => (r.keyId === old.keyId ? { ...r, revokedAt: new Date(now).toISOString() } : r)) : records;
    const active = kept.filter((r) => r.agentId === old.agentId && recordStatus(r, now) === "active").length;
    if (active >= MAX_ACTIVE_PER_AGENT) throw new CliError(`That agent already has ${MAX_ACTIVE_PER_AGENT} active credentials. Revoke one first, or use --revoke-old.`);
    const issued = issueCredential({
      agentId: old.agentId,
      now,
      takenKeyIds: new Set(records.map((r) => r.keyId)),
      label: options.values.get("label") ?? old.label,
      days: days(options),
    });
    const next = validateCredentialRecords([...kept, issued.record], now);
    deliver(io, storePath, next, issued, options.values.get("out"));
    io.out(
      revokeOld
        ? `Credential ${old.keyId} was revoked.`
        : `Credential ${old.keyId} is still active. Revoke it once the agent uses the new one: revoke --key ${old.keyId}`,
    );
  });
}

function revoke(io: CliIo, storePath: string, options: Options): void {
  withStoreLock(storePath, () => {
    const now = io.now();
    const records = readCredentialFile(storePath, now);
    const record = findRecord(records, options);
    if (record.revokedAt !== null) {
      io.out(`Credential ${record.keyId} was already revoked at ${record.revokedAt}.`);
      return;
    }
    const revokedAt = new Date(now).toISOString();
    const next = validateCredentialRecords(records.map((r) => (r.keyId === record.keyId ? { ...r, revokedAt } : r)), now);
    writeRestrictedFileAtomically(storePath, serializeCredentialDocument(next), { overwrite: true });
    io.out(`Revoked credential ${record.keyId} for agent ${record.agentId} at ${revokedAt}. A running API stops accepting it within 2 seconds.`);
  });
}

function list(io: CliIo, storePath: string, options: Options): void {
  const now = io.now();
  // Never the hash: only public metadata.
  const rows = readCredentialFile(storePath, now).map((r) => ({
    keyId: r.keyId,
    agentId: r.agentId,
    status: recordStatus(r, now),
    label: r.label,
    createdAt: r.createdAt,
    expiresAt: r.expiresAt,
    revokedAt: r.revokedAt,
  }));
  if (options.switches.has("json")) {
    io.out(JSON.stringify(rows, null, 2));
    return;
  }
  if (rows.length === 0) {
    io.out("No agent credentials.");
    return;
  }
  for (const r of rows) {
    io.out(`${r.keyId}  ${r.agentId}  ${r.status}  created ${r.createdAt}  expires ${r.expiresAt}${r.revokedAt ? `  revoked ${r.revokedAt}` : ""}${r.label ? `  "${r.label}"` : ""}`);
  }
}

/** Runs one command. Returns the exit code: 0 success, 1 failure, 2 usage error. */
export function runCli(argv: string[], io: CliIo): number {
  const [command, ...args] = argv;
  if (command === undefined || command === "help" || command === "--help") {
    USAGE.forEach((line) => io.out(line));
    return command === undefined ? 2 : 0;
  }
  try {
    if (!(command in COMMANDS)) throw new UsageError("Unknown command.");
    const options = parseArgs(command, args);
    const storePath = options.values.get("file") ?? credentialFilePath(io.env);
    if (command === "create") create(io, storePath, options);
    else if (command === "list") list(io, storePath, options);
    else if (command === "revoke") revoke(io, storePath, options);
    else rotate(io, storePath, options);
    return 0;
  } catch (error) {
    if (error instanceof UsageError) {
      io.err(error.message);
      USAGE.forEach((line) => io.err(line));
      return 2;
    }
    // Known errors carry fixed text without file contents or secrets; anything else is reported generically.
    const known = error instanceof CliError || error instanceof CredentialConfigError || error instanceof FileSecurityError;
    io.err(known ? (error as Error).message : "The command failed; the credential store was not changed.");
    return 1;
  }
}

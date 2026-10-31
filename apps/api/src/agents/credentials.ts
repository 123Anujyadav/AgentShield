import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { AGENT_ID_PATTERN } from "../policies/store.js";
import { defaultTokenDirectory } from "../security/token.js";

/**
 * Agent credentials (M3-D).
 *
 * A credential is `asag_<keyId>.<secret>`: a public 16-hex-digit key id and a
 * 256-bit random secret. The server stores only a SHA-256 of the secret, bound
 * to its key id and to this scheme (domain separation), and compares digests in
 * constant time. An unknown key id still costs one comparison against a dummy
 * digest, so timing does not reveal which key ids exist. The authenticated agent
 * id comes from the matching record, never from the request.
 */

export const CREDENTIAL_PREFIX = "asag_";
export const CREDENTIAL_PATTERN = /^asag_([0-9a-f]{16})\.([A-Za-z0-9_-]{43})$/;
export const KEY_ID_PATTERN = /^[0-9a-f]{16}$/;
export const CREDENTIAL_FILE_NAME = "agent-credentials.json";
export const MAX_CREDENTIAL_FILE_BYTES = 256 * 1024;
export const MAX_CREDENTIALS = 1000;
export const MAX_ACTIVE_PER_AGENT = 4;
export const MAX_LABEL_LENGTH = 100;
export const DEFAULT_EXPIRY_DAYS = 90;
export const MAX_EXPIRY_DAYS = 365;
export const CREDENTIAL_SCHEMA_VERSION = 1;
export const RELOAD_INTERVAL_MS = 2000;

const DAY_MS = 24 * 60 * 60 * 1000;
const HASH_DOMAIN = "agentshield-agent-credential-v1";
const SHA256_HEX = /^[0-9a-f]{64}$/;
const ISO_INSTANT = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const CONTROL = /[\u0000-\u001f\u007f]/;
const RECORD_KEYS = new Set(["keyId", "agentId", "sha256", "label", "createdAt", "expiresAt", "revokedAt"]);
const DOCUMENT_KEYS = new Set(["schemaVersion", "credentials"]);

/** One stored credential. Holds the hash only; the secret is never stored. */
export interface CredentialRecord {
  keyId: string;
  agentId: string;
  sha256: string;
  label: string | null;
  createdAt: string;
  expiresAt: string;
  revokedAt: string | null;
}

export type CredentialStatus = "active" | "revoked" | "expired" | "unknown" | "unavailable";

export type VerifyResult =
  | { ok: true; agentId: string; keyId: string }
  | { ok: false; reason: "malformed" | "unknown-key" | "wrong-secret" | "revoked" | "expired" | "store-unavailable" };

export interface CredentialStore {
  /** Verifies a presented credential. Every failure is the same to the caller; `reason` is for server logs only. */
  verify(credential: string): VerifyResult;
  /** The current status of a key id (used when an approval is rechecked). */
  status(keyId: string): CredentialStatus;
  /** Stored records (hashes included): for the CLI and the server, never for API responses. */
  list(): readonly CredentialRecord[];
}

/** Raised for any invalid credential store. Messages name the field, never echo file contents. */
export class CredentialConfigError extends Error {}

/** The stored digest for a key id and secret. */
export function credentialHash(keyId: string, secret: string): string {
  return createHash("sha256").update(`${HASH_DOMAIN}\0${keyId}\0${secret}`, "utf8").digest("hex");
}

/** Constant-time comparison of two SHA-256 digests (always 32 bytes each). */
export function digestsMatch(actualHex: string, expectedHex: string): boolean {
  return timingSafeEqual(Buffer.from(actualHex, "hex"), Buffer.from(expectedHex, "hex"));
}

/** Splits a presented credential, or null if it is not exactly the credential format. */
export function parseCredential(value: string): { keyId: string; secret: string } | null {
  const match = value.length === 65 ? CREDENTIAL_PATTERN.exec(value) : null;
  return match ? { keyId: match[1]!, secret: match[2]! } : null;
}

/** A new credential (32 random bytes of secret) whose key id is not in `takenKeyIds`. */
export function generateCredential(takenKeyIds: ReadonlySet<string>): { credential: string; keyId: string; sha256: string } {
  let keyId = randomBytes(8).toString("hex");
  while (takenKeyIds.has(keyId)) keyId = randomBytes(8).toString("hex");
  const secret = randomBytes(32).toString("base64url");
  return { credential: `${CREDENTIAL_PREFIX}${keyId}.${secret}`, keyId, sha256: credentialHash(keyId, secret) };
}

/**
 * A new credential and its store record (U4: default 90 days, at most 365).
 * The plaintext credential is returned once, to be handed to the agent; only
 * the record is ever stored.
 */
export function issueCredential(input: {
  agentId: string;
  now: number;
  takenKeyIds: ReadonlySet<string>;
  label?: string | null;
  days?: number;
}): { credential: string; record: CredentialRecord } {
  const days = input.days ?? DEFAULT_EXPIRY_DAYS;
  if (!Number.isSafeInteger(days) || days < 1 || days > MAX_EXPIRY_DAYS) {
    throw new CredentialConfigError(`Expiry must be a whole number of days from 1 to ${MAX_EXPIRY_DAYS}.`);
  }
  const { credential, keyId, sha256 } = generateCredential(input.takenKeyIds);
  const createdAt = new Date(input.now).toISOString();
  const record = validateCredentialRecord({
    keyId,
    agentId: input.agentId,
    sha256,
    label: input.label ?? null,
    createdAt,
    expiresAt: new Date(input.now + days * DAY_MS).toISOString(),
    revokedAt: null,
  });
  return { credential, record };
}

/** Compared against when a key id is unknown, so the unknown path does the same work. */
const DUMMY_DIGEST = credentialHash("0000000000000000", "dummy-digest-never-matches-a-real-credential");

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isInstant(value: unknown): value is string {
  return typeof value === "string" && ISO_INSTANT.test(value) && !Number.isNaN(Date.parse(value)) && new Date(value).toISOString() === value;
}

/** Whether a record is usable at `now` (not revoked, not expired). */
export function recordStatus(record: CredentialRecord, now: number): "active" | "revoked" | "expired" {
  if (record.revokedAt !== null) return "revoked";
  return Date.parse(record.expiresAt) <= now ? "expired" : "active";
}

/** Validates one record strictly and returns a clean copy. */
export function validateCredentialRecord(value: unknown, where = "credential"): CredentialRecord {
  if (!isRecord(value)) throw new CredentialConfigError(`${where} must be an object.`);
  for (const key of Object.keys(value)) {
    // The field name comes from the file and is never echoed (M3-D audit L4).
    if (!RECORD_KEYS.has(key)) throw new CredentialConfigError(`${where} has an unknown field.`);
  }
  for (const key of RECORD_KEYS) {
    if (!(key in value)) throw new CredentialConfigError(`${where}.${key} is required.`);
  }
  const { keyId, agentId, sha256, label, createdAt, expiresAt, revokedAt } = value;
  if (typeof keyId !== "string" || !KEY_ID_PATTERN.test(keyId)) throw new CredentialConfigError(`${where}.keyId must be 16 lower-case hex digits.`);
  if (typeof agentId !== "string" || !AGENT_ID_PATTERN.test(agentId)) throw new CredentialConfigError(`${where}.agentId must match ${AGENT_ID_PATTERN.source}.`);
  if (typeof sha256 !== "string" || !SHA256_HEX.test(sha256)) throw new CredentialConfigError(`${where}.sha256 must be 64 lower-case hex digits.`);
  if (label !== null && (typeof label !== "string" || label.length === 0 || label.length > MAX_LABEL_LENGTH || CONTROL.test(label))) {
    throw new CredentialConfigError(`${where}.label must be null or text of 1 to ${MAX_LABEL_LENGTH} characters without control characters.`);
  }
  if (!isInstant(createdAt)) throw new CredentialConfigError(`${where}.createdAt must be an ISO 8601 UTC timestamp with milliseconds.`);
  if (!isInstant(expiresAt)) throw new CredentialConfigError(`${where}.expiresAt must be an ISO 8601 UTC timestamp with milliseconds.`);
  const lifetime = Date.parse(expiresAt) - Date.parse(createdAt);
  if (lifetime <= 0 || lifetime > MAX_EXPIRY_DAYS * DAY_MS) {
    throw new CredentialConfigError(`${where}.expiresAt must be after createdAt and at most ${MAX_EXPIRY_DAYS} days later.`);
  }
  if (revokedAt !== null && !isInstant(revokedAt)) throw new CredentialConfigError(`${where}.revokedAt must be null or an ISO 8601 UTC timestamp with milliseconds.`);
  return { keyId, agentId, sha256, label: label as string | null, createdAt, expiresAt, revokedAt: revokedAt as string | null };
}

/** Validates a whole set of records: duplicates, counts and the per-agent active limit. */
export function validateCredentialRecords(values: readonly unknown[], now: number): CredentialRecord[] {
  if (values.length > MAX_CREDENTIALS) throw new CredentialConfigError(`credentials has more than ${MAX_CREDENTIALS} entries.`);
  const keyIds = new Set<string>();
  const hashes = new Set<string>();
  const activePerAgent = new Map<string, number>();
  return values.map((value, index) => {
    const where = `credentials[${index}]`;
    const record = validateCredentialRecord(value, where);
    if (keyIds.has(record.keyId)) throw new CredentialConfigError(`${where}.keyId duplicates an earlier credential.`);
    if (hashes.has(record.sha256)) throw new CredentialConfigError(`${where}.sha256 duplicates an earlier credential.`);
    keyIds.add(record.keyId);
    hashes.add(record.sha256);
    if (recordStatus(record, now) === "active") {
      const active = (activePerAgent.get(record.agentId) ?? 0) + 1;
      if (active > MAX_ACTIVE_PER_AGENT) throw new CredentialConfigError(`${where}: agent has more than ${MAX_ACTIVE_PER_AGENT} active credentials.`);
      activePerAgent.set(record.agentId, active);
    }
    return record;
  });
}

/** Parses and validates a credential store document. */
export function parseCredentialDocument(text: string, now: number): CredentialRecord[] {
  if (Buffer.byteLength(text, "utf8") > MAX_CREDENTIAL_FILE_BYTES) {
    throw new CredentialConfigError(`The credential store is larger than ${MAX_CREDENTIAL_FILE_BYTES} bytes.`);
  }
  let document: unknown;
  try {
    document = JSON.parse(text.replace(/^﻿/, ""));
  } catch {
    throw new CredentialConfigError("The credential store is not valid JSON.");
  }
  if (!isRecord(document)) throw new CredentialConfigError("The credential store must be a JSON object.");
  for (const key of Object.keys(document)) {
    if (!DOCUMENT_KEYS.has(key)) throw new CredentialConfigError("The credential store has an unknown top-level field.");
  }
  if (document.schemaVersion !== CREDENTIAL_SCHEMA_VERSION) throw new CredentialConfigError(`schemaVersion must be ${CREDENTIAL_SCHEMA_VERSION}.`);
  if (!Array.isArray(document.credentials)) throw new CredentialConfigError("credentials must be an array.");
  return validateCredentialRecords(document.credentials, now);
}

/** The store document for a set of records, as the CLI writes it. */
export function serializeCredentialDocument(records: readonly CredentialRecord[]): string {
  const credentials = records.map((r) => ({
    keyId: r.keyId,
    agentId: r.agentId,
    sha256: r.sha256,
    label: r.label,
    createdAt: r.createdAt,
    expiresAt: r.expiresAt,
    revokedAt: r.revokedAt,
  }));
  return `${JSON.stringify({ schemaVersion: CREDENTIAL_SCHEMA_VERSION, credentials }, null, 2)}\n`;
}

/** An in-memory store over already-validated records. `now` is read on every check, so expiry is live. */
export function createCredentialStore(records: readonly CredentialRecord[], now: () => number = Date.now): CredentialStore {
  const validated = validateCredentialRecords(records, now());
  const byKeyId = new Map<string, Readonly<CredentialRecord>>(validated.map((r) => [r.keyId, Object.freeze({ ...r })]));
  return {
    verify(credential) {
      const parsed = typeof credential === "string" ? parseCredential(credential) : null;
      const keyId = parsed?.keyId ?? "0000000000000000";
      const record = byKeyId.get(keyId);
      // Always exactly one constant-time comparison, whether or not the key id exists.
      const matches = digestsMatch(credentialHash(keyId, parsed?.secret ?? ""), record?.sha256 ?? DUMMY_DIGEST);
      if (!parsed) return { ok: false, reason: "malformed" };
      if (!record) return { ok: false, reason: "unknown-key" };
      if (!matches) return { ok: false, reason: "wrong-secret" };
      const status = recordStatus(record, now());
      if (status !== "active") return { ok: false, reason: status };
      return { ok: true, agentId: record.agentId, keyId: record.keyId };
    },
    status(keyId) {
      const record = byKeyId.get(keyId);
      return record ? recordStatus(record, now()) : "unknown";
    },
    list: () => [...byKeyId.values()],
  };
}

/** No agent credentials at all: every agent credential is rejected. */
export function emptyCredentialStore(): CredentialStore {
  return createCredentialStore([]);
}

/** A store that rejects everything: used while a changed credential file is invalid. */
function unavailableCredentialStore(): CredentialStore {
  return {
    verify(credential) {
      // Same work as a real check, so an outage is not visible through timing either.
      const parsed = typeof credential === "string" ? parseCredential(credential) : null;
      digestsMatch(credentialHash(parsed?.keyId ?? "0000000000000000", parsed?.secret ?? ""), DUMMY_DIGEST);
      return { ok: false, reason: "store-unavailable" };
    },
    status: () => "unavailable",
    list: () => [],
  };
}

/** AGENT_CREDENTIAL_FILE when set, otherwise %LOCALAPPDATA%\AgentShield\agent-credentials.json. */
export function credentialFilePath(env: NodeJS.ProcessEnv = process.env): string {
  const configured = env.AGENT_CREDENTIAL_FILE?.trim();
  return configured ? configured : join(defaultTokenDirectory(env), CREDENTIAL_FILE_NAME);
}

/** Reads and validates the credential file. A missing file means no credentials. */
export function readCredentialFile(path: string, now: number): CredentialRecord[] {
  let size: number;
  try {
    size = statSync(path).size;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return [];
    throw new CredentialConfigError("The credential store cannot be read.");
  }
  if (size > MAX_CREDENTIAL_FILE_BYTES) throw new CredentialConfigError(`The credential store is larger than ${MAX_CREDENTIAL_FILE_BYTES} bytes.`);
  let text: string;
  try {
    text = readFileSync(path, "utf8");
  } catch {
    throw new CredentialConfigError("The credential store cannot be read.");
  }
  return parseCredentialDocument(text, now);
}

/** Size, timestamps and file id: an edit or an atomic replacement changes at least one of them. */
function fileSignature(path: string): string {
  try {
    const s = statSync(path, { bigint: true });
    return `${s.size}:${s.mtimeNs}:${s.ctimeNs}:${s.birthtimeNs}:${s.ino}:${s.dev}`;
  } catch (error) {
    return (error as NodeJS.ErrnoException).code === "ENOENT" ? "missing" : "unreadable";
  }
}

export type CredentialReloadEvent =
  | { kind: "reloaded"; count: number }
  | { kind: "invalid"; reason: string }
  | { kind: "no-policy"; agentId: string; keyId: string };

export interface ReloadingCredentialStore extends CredentialStore {
  /** "invalid" while a changed file fails validation: every agent credential is then rejected. */
  readonly state: "ok" | "invalid";
}

/**
 * The server's credential store, loaded from a file and re-read when the file
 * changes (checked at most every RELOAD_INTERVAL_MS, on use). The initial load
 * throws on an invalid file so start-up fails closed. A later invalid file
 * rejects every agent credential until the file is valid again; it never falls
 * back to the previously loaded credentials.
 */
export function createReloadingCredentialStore(
  path: string,
  options: {
    now?: () => number;
    intervalMs?: number;
    /** U8: whether an agent has a policy. Credentials without one load, with a warning. */
    hasPolicy?: (agentId: string) => boolean;
    onEvent?: (event: CredentialReloadEvent) => void;
  } = {},
): ReloadingCredentialStore {
  const now = options.now ?? Date.now;
  const intervalMs = options.intervalMs ?? RELOAD_INTERVAL_MS;
  const onEvent = options.onEvent ?? (() => {});

  function warnAboutMissingPolicies(store: CredentialStore): void {
    if (!options.hasPolicy) return;
    for (const record of store.list()) {
      if (recordStatus(record, now()) === "active" && !options.hasPolicy(record.agentId)) {
        onEvent({ kind: "no-policy", agentId: record.agentId, keyId: record.keyId });
      }
    }
  }

  let signature = fileSignature(path);
  let current: CredentialStore = createCredentialStore(readCredentialFile(path, now()), now);
  let state: "ok" | "invalid" = "ok";
  let lastCheck = now();
  warnAboutMissingPolicies(current);

  function refresh(): void {
    const at = now();
    if (at - lastCheck < intervalMs) return;
    lastCheck = at;
    const next = fileSignature(path);
    if (next === signature) return;
    try {
      const store = createCredentialStore(readCredentialFile(path, at), now);
      current = store;
      state = "ok";
      signature = next;
      onEvent({ kind: "reloaded", count: store.list().length });
      warnAboutMissingPolicies(store);
    } catch (error) {
      current = unavailableCredentialStore();
      state = "invalid";
      // Not recorded as seen: the file is read again at the next check, until it is valid.
      signature = "invalid";
      onEvent({ kind: "invalid", reason: error instanceof CredentialConfigError ? error.message : "unexpected error" });
    }
  }

  return {
    verify(credential) {
      refresh();
      return current.verify(credential);
    },
    status(keyId) {
      refresh();
      return current.status(keyId);
    },
    list() {
      refresh();
      return current.list();
    },
    get state() {
      refresh();
      return state;
    },
  };
}

import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, randomBytes, timingSafeEqual, type KeyObject } from "node:crypto";
import { readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { AGENT_ID_PATTERN } from "../policies/store.js";
import { isAcceptableEd25519PublicKey } from "./ed25519.js";
import { defaultTokenDirectory } from "../security/token.js";

/**
 * Agent credentials (M3-D, extended in M3-E E2).
 *
 * Two schemes, never interchangeable:
 *
 * - `ed25519` (default for new credentials, M3-E): the agent holds an Ed25519
 *   private key and the server stores only the public key. The agent's
 *   credential is `asag2_<keyId>.<base64url PKCS#8 DER private key>`. It is used to
 *   sign requests (verification arrives in E3) and is never sent to the server.
 * - `bearer` (legacy, M3-D): `asag_<keyId>.<secret>`, a 256-bit secret sent with
 *   each request. The server stores only a domain-separated SHA-256 of it and
 *   compares digests in constant time. Bearer credentials authenticate only when
 *   AGENT_BEARER_ALLOWED is exactly "true" (default: they do not).
 *
 * Store schema v2 records each credential's scheme explicitly. A schema v1 store
 * (M3-D) is still read: its records keep their meaning, bearer, and are never
 * reinterpreted as Ed25519. The CLI writes schema v2.
 */

export const CREDENTIAL_PREFIX = "asag_";
export const CREDENTIAL_PATTERN = /^asag_([0-9a-f]{16})\.([A-Za-z0-9_-]{43})$/;
/** M3-E: an agent's Ed25519 signing credential (private; stays on the agent machine). */
export const SIGNING_CREDENTIAL_PREFIX = "asag2_";
export const SIGNING_CREDENTIAL_PATTERN = /^asag2_([0-9a-f]{16})\.([A-Za-z0-9_-]{64})$/;
export const KEY_ID_PATTERN = /^[0-9a-f]{16}$/;
export const CREDENTIAL_FILE_NAME = "agent-credentials.json";
export const MAX_CREDENTIAL_FILE_BYTES = 256 * 1024;
export const MAX_CREDENTIALS = 1000;
export const MAX_ACTIVE_PER_AGENT = 4;
export const MAX_LABEL_LENGTH = 100;
export const DEFAULT_EXPIRY_DAYS = 90;
export const MAX_EXPIRY_DAYS = 365;
/** The schema version the CLI writes. Version 1 (M3-D, bearer only) is still read. */
export const CREDENTIAL_SCHEMA_VERSION = 2;
export const RELOAD_INTERVAL_MS = 2000;

const DAY_MS = 24 * 60 * 60 * 1000;
const HASH_DOMAIN = "agentshield-agent-credential-v1";
const SHA256_HEX = /^[0-9a-f]{64}$/;
const BASE64URL = /^[A-Za-z0-9_-]+$/;
const ISO_INSTANT = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const CONTROL = /[\u0000-\u001f\u007f]/;
/** The fixed DER prefix of an Ed25519 PKCS#8 private key (RFC 8410); the last 32 bytes are the seed. */
const ED25519_PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");
const COMMON_KEYS = ["keyId", "agentId", "label", "createdAt", "expiresAt", "revokedAt"];
const RECORD_KEYS: Record<"v1" | "bearer" | "ed25519", ReadonlySet<string>> = {
  v1: new Set([...COMMON_KEYS, "sha256"]),
  bearer: new Set(["scheme", ...COMMON_KEYS, "sha256"]),
  ed25519: new Set(["scheme", ...COMMON_KEYS, "publicKey"]),
};
const DOCUMENT_KEYS = new Set(["schemaVersion", "credentials"]);

interface CommonRecordFields {
  keyId: string;
  agentId: string;
  label: string | null;
  createdAt: string;
  expiresAt: string;
  revokedAt: string | null;
}

/** A legacy bearer credential: holds the hash only; the secret is never stored. */
export interface BearerCredentialRecord extends CommonRecordFields {
  scheme: "bearer";
  sha256: string;
}

/** An Ed25519 credential: holds the public key only (raw 32 bytes, base64url); the private key is never stored. */
export interface Ed25519CredentialRecord extends CommonRecordFields {
  scheme: "ed25519";
  publicKey: string;
}

export type CredentialRecord = BearerCredentialRecord | Ed25519CredentialRecord;
export type CredentialScheme = CredentialRecord["scheme"];

export type CredentialStatus = "active" | "revoked" | "expired" | "unknown" | "unavailable";

export type VerifyResult =
  | { ok: true; agentId: string; keyId: string }
  | {
      ok: false;
      reason: "malformed" | "unknown-key" | "wrong-secret" | "scheme-mismatch" | "bearer-disabled" | "revoked" | "expired" | "store-unavailable";
    };

export type PublicKeyLookup =
  | { ok: true; agentId: string; keyId: string; publicKey: KeyObject }
  | { ok: false; reason: "unknown-key" | "scheme-mismatch" | "revoked" | "expired" | "store-unavailable" };

export interface CredentialStore {
  /**
   * Verifies a presented legacy bearer credential. Every failure is the same to the
   * caller; `reason` is for server logs only. Ed25519 records never match here.
   */
  verify(credential: string): VerifyResult;
  /** The active Ed25519 public key for a key id, for signature verification (E3). Independent of the bearer setting. */
  publicKeyFor(keyId: string): PublicKeyLookup;
  /** The current lifecycle status of a key id of either scheme (used when an approval is rechecked). */
  status(keyId: string): CredentialStatus;
  /** Stored records (hashes and public keys included): for the CLI and the server, never for API responses. */
  list(): readonly CredentialRecord[];
}

export interface CredentialStoreOptions {
  now?: () => number;
  /** Whether legacy bearer credentials may authenticate. Defaults to false (M3-E E2). */
  bearerAllowed?: boolean;
}

/** Raised for any invalid credential store. Messages name the field, never echo file contents. */
export class CredentialConfigError extends Error {}

/** AGENT_BEARER_ALLOWED: only exactly "true" enables legacy bearer credentials. */
export function bearerAllowedFromEnv(env: NodeJS.ProcessEnv = process.env): boolean {
  return env.AGENT_BEARER_ALLOWED === "true";
}

/** The stored digest for a key id and secret. */
export function credentialHash(keyId: string, secret: string): string {
  return createHash("sha256").update(`${HASH_DOMAIN}\0${keyId}\0${secret}`, "utf8").digest("hex");
}

/** Constant-time comparison of two SHA-256 digests (always 32 bytes each). */
export function digestsMatch(actualHex: string, expectedHex: string): boolean {
  return timingSafeEqual(Buffer.from(actualHex, "hex"), Buffer.from(expectedHex, "hex"));
}

/** Splits a presented bearer credential, or null if it is not exactly the bearer format. */
export function parseCredential(value: string): { keyId: string; secret: string } | null {
  const match = value.length === 65 ? CREDENTIAL_PATTERN.exec(value) : null;
  return match ? { keyId: match[1]!, secret: match[2]! } : null;
}

function isCanonicalBase64url(value: unknown, bytes: number): value is string {
  if (typeof value !== "string" || value.length !== Math.ceil((bytes * 4) / 3) || !BASE64URL.test(value)) return false;
  const decoded = Buffer.from(value, "base64url");
  return decoded.length === bytes && decoded.toString("base64url") === value;
}

/**
 * The KeyObject for a stored Ed25519 public key (raw 32 bytes, canonical base64url), or null.
 * The point itself is checked first (M3-E audit M1): it must be a canonical encoding of a
 * point on the curve (RFC 8032) and not one of the small-order points, which Node would
 * otherwise accept and which allow forged signatures.
 */
export function ed25519PublicKey(publicKey: unknown): KeyObject | null {
  if (!isCanonicalBase64url(publicKey, 32)) return null;
  if (!isAcceptableEd25519PublicKey(Buffer.from(publicKey, "base64url"))) return null;
  try {
    const key = createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: publicKey }, format: "jwk" });
    return key.asymmetricKeyType === "ed25519" ? key : null;
  } catch {
    return null;
  }
}

/**
 * Splits an agent's Ed25519 signing credential into its key id and private key.
 * For the agent side (tests now, the SDK in E5); the server never receives one.
 */
export function parseSigningCredential(value: unknown): { keyId: string; privateKey: KeyObject } | null {
  if (typeof value !== "string" || value.length !== 87) return null;
  const match = SIGNING_CREDENTIAL_PATTERN.exec(value);
  if (!match || !isCanonicalBase64url(match[2], 48)) return null;
  const der = Buffer.from(match[2]!, "base64url");
  if (!der.subarray(0, ED25519_PKCS8_PREFIX.length).equals(ED25519_PKCS8_PREFIX)) return null;
  try {
    const privateKey = createPrivateKey({ key: der, format: "der", type: "pkcs8" });
    return privateKey.asymmetricKeyType === "ed25519" ? { keyId: match[1]!, privateKey } : null;
  } catch {
    return null;
  }
}

function uniqueKeyId(takenKeyIds: ReadonlySet<string>): string {
  let keyId = randomBytes(8).toString("hex");
  while (takenKeyIds.has(keyId)) keyId = randomBytes(8).toString("hex");
  return keyId;
}

/** A new bearer credential (32 random bytes of secret) whose key id is not in `takenKeyIds`. */
export function generateCredential(takenKeyIds: ReadonlySet<string>): { credential: string; keyId: string; sha256: string } {
  const keyId = uniqueKeyId(takenKeyIds);
  const secret = randomBytes(32).toString("base64url");
  return { credential: `${CREDENTIAL_PREFIX}${keyId}.${secret}`, keyId, sha256: credentialHash(keyId, secret) };
}

interface IssueInput {
  agentId: string;
  now: number;
  takenKeyIds: ReadonlySet<string>;
  label?: string | null;
  days?: number;
}

function lifetime(input: IssueInput): { createdAt: string; expiresAt: string } {
  const days = input.days ?? DEFAULT_EXPIRY_DAYS;
  if (!Number.isSafeInteger(days) || days < 1 || days > MAX_EXPIRY_DAYS) {
    throw new CredentialConfigError(`Expiry must be a whole number of days from 1 to ${MAX_EXPIRY_DAYS}.`);
  }
  return { createdAt: new Date(input.now).toISOString(), expiresAt: new Date(input.now + days * DAY_MS).toISOString() };
}

/**
 * A new legacy bearer credential and its record (U4: default 90 days, at most 365).
 * The plaintext credential is returned once; only the record is ever stored.
 */
export function issueCredential(input: IssueInput): { credential: string; record: BearerCredentialRecord } {
  const dates = lifetime(input);
  const { credential, keyId, sha256 } = generateCredential(input.takenKeyIds);
  const record = validateCredentialRecord({ scheme: "bearer", keyId, agentId: input.agentId, sha256, label: input.label ?? null, ...dates, revokedAt: null });
  return { credential, record: record as BearerCredentialRecord };
}

/**
 * A new Ed25519 credential (M3-E E2). The key pair is generated with node:crypto;
 * the private key is returned once, as `asag2_<keyId>.<base64url PKCS#8 DER>`, and
 * only the public key goes into the record.
 */
export function issueEd25519Credential(input: IssueInput): { credential: string; record: Ed25519CredentialRecord } {
  const dates = lifetime(input);
  const keyId = uniqueKeyId(input.takenKeyIds);
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const x = publicKey.export({ format: "jwk" }).x;
  const der = privateKey.export({ format: "der", type: "pkcs8" });
  const record = validateCredentialRecord({ scheme: "ed25519", keyId, agentId: input.agentId, publicKey: x, label: input.label ?? null, ...dates, revokedAt: null });
  return { credential: `${SIGNING_CREDENTIAL_PREFIX}${keyId}.${der.toString("base64url")}`, record: record as Ed25519CredentialRecord };
}

/** Compared against when a key id is unknown or not a bearer key, so those paths do the same work. */
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

/**
 * Validates one record strictly and returns a clean copy. Schema 2 records name
 * their scheme; schema 1 records (M3-D) have no scheme field and are bearer.
 */
export function validateCredentialRecord(value: unknown, where = "credential", schemaVersion: 1 | 2 = 2): CredentialRecord {
  if (!isRecord(value)) throw new CredentialConfigError(`${where} must be an object.`);
  let kind: "v1" | "bearer" | "ed25519";
  if (schemaVersion === 1) {
    kind = "v1";
  } else if (value.scheme === "bearer" || value.scheme === "ed25519") {
    kind = value.scheme;
  } else {
    throw new CredentialConfigError(`${where}.scheme must be "bearer" or "ed25519".`);
  }
  const allowed = RECORD_KEYS[kind];
  for (const key of Object.keys(value)) {
    // The field name comes from the file and is never echoed (M3-D audit L4).
    if (!allowed.has(key)) throw new CredentialConfigError(`${where} has an unknown field.`);
  }
  for (const key of allowed) {
    if (!(key in value)) throw new CredentialConfigError(`${where}.${key} is required.`);
  }
  const { keyId, agentId, label, createdAt, expiresAt, revokedAt } = value;
  if (typeof keyId !== "string" || !KEY_ID_PATTERN.test(keyId)) throw new CredentialConfigError(`${where}.keyId must be 16 lower-case hex digits.`);
  if (typeof agentId !== "string" || !AGENT_ID_PATTERN.test(agentId)) throw new CredentialConfigError(`${where}.agentId must match ${AGENT_ID_PATTERN.source}.`);
  if (label !== null && (typeof label !== "string" || label.length === 0 || label.length > MAX_LABEL_LENGTH || CONTROL.test(label))) {
    throw new CredentialConfigError(`${where}.label must be null or text of 1 to ${MAX_LABEL_LENGTH} characters without control characters.`);
  }
  if (!isInstant(createdAt)) throw new CredentialConfigError(`${where}.createdAt must be an ISO 8601 UTC timestamp with milliseconds.`);
  if (!isInstant(expiresAt)) throw new CredentialConfigError(`${where}.expiresAt must be an ISO 8601 UTC timestamp with milliseconds.`);
  const span = Date.parse(expiresAt) - Date.parse(createdAt);
  if (span <= 0 || span > MAX_EXPIRY_DAYS * DAY_MS) {
    throw new CredentialConfigError(`${where}.expiresAt must be after createdAt and at most ${MAX_EXPIRY_DAYS} days later.`);
  }
  if (revokedAt !== null && !isInstant(revokedAt)) throw new CredentialConfigError(`${where}.revokedAt must be null or an ISO 8601 UTC timestamp with milliseconds.`);
  const common = { keyId, agentId, label: label as string | null, createdAt, expiresAt, revokedAt: revokedAt as string | null };
  if (kind === "ed25519") {
    if (ed25519PublicKey(value.publicKey) === null) throw new CredentialConfigError(`${where}.publicKey must be a raw 32-byte Ed25519 public key in base64url.`);
    return { scheme: "ed25519", ...common, publicKey: value.publicKey as string };
  }
  if (typeof value.sha256 !== "string" || !SHA256_HEX.test(value.sha256)) throw new CredentialConfigError(`${where}.sha256 must be 64 lower-case hex digits.`);
  return { scheme: "bearer", ...common, sha256: value.sha256 };
}

/** Validates a whole set of records: duplicates, counts and the per-agent active limit (both schemes count). */
export function validateCredentialRecords(values: readonly unknown[], now: number, schemaVersion: 1 | 2 = 2): CredentialRecord[] {
  if (values.length > MAX_CREDENTIALS) throw new CredentialConfigError(`credentials has more than ${MAX_CREDENTIALS} entries.`);
  const keyIds = new Set<string>();
  const hashes = new Set<string>();
  const publicKeys = new Set<string>();
  const activePerAgent = new Map<string, number>();
  return values.map((value, index) => {
    const where = `credentials[${index}]`;
    const record = validateCredentialRecord(value, where, schemaVersion);
    if (keyIds.has(record.keyId)) throw new CredentialConfigError(`${where}.keyId duplicates an earlier credential.`);
    keyIds.add(record.keyId);
    if (record.scheme === "bearer") {
      if (hashes.has(record.sha256)) throw new CredentialConfigError(`${where}.sha256 duplicates an earlier credential.`);
      hashes.add(record.sha256);
    } else {
      if (publicKeys.has(record.publicKey)) throw new CredentialConfigError(`${where}.publicKey duplicates an earlier credential.`);
      publicKeys.add(record.publicKey);
    }
    if (recordStatus(record, now) === "active") {
      const active = (activePerAgent.get(record.agentId) ?? 0) + 1;
      if (active > MAX_ACTIVE_PER_AGENT) throw new CredentialConfigError(`${where}: agent has more than ${MAX_ACTIVE_PER_AGENT} active credentials.`);
      activePerAgent.set(record.agentId, active);
    }
    return record;
  });
}

/** Parses and validates a credential store document of schema version 1 or 2. */
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
  const version = document.schemaVersion;
  if (version !== 1 && version !== 2) throw new CredentialConfigError("schemaVersion must be 1 or 2.");
  if (!Array.isArray(document.credentials)) throw new CredentialConfigError("credentials must be an array.");
  return validateCredentialRecords(document.credentials, now, version);
}

/** The store document for a set of records, as the CLI writes it (schema 2, each record naming its scheme). */
export function serializeCredentialDocument(records: readonly CredentialRecord[]): string {
  const credentials = records.map((r) =>
    r.scheme === "ed25519"
      ? { scheme: r.scheme, keyId: r.keyId, agentId: r.agentId, publicKey: r.publicKey, label: r.label, createdAt: r.createdAt, expiresAt: r.expiresAt, revokedAt: r.revokedAt }
      : { scheme: r.scheme, keyId: r.keyId, agentId: r.agentId, sha256: r.sha256, label: r.label, createdAt: r.createdAt, expiresAt: r.expiresAt, revokedAt: r.revokedAt },
  );
  return `${JSON.stringify({ schemaVersion: CREDENTIAL_SCHEMA_VERSION, credentials }, null, 2)}\n`;
}

/** An in-memory store over already-validated records. `now` is read on every check, so expiry is live. */
export function createCredentialStore(records: readonly CredentialRecord[], options: CredentialStoreOptions = {}): CredentialStore {
  const now = options.now ?? Date.now;
  const bearerAllowed = options.bearerAllowed === true;
  const validated = validateCredentialRecords(records, now());
  const byKeyId = new Map<string, Readonly<CredentialRecord>>(validated.map((r) => [r.keyId, Object.freeze({ ...r })]));
  const publicKeys = new Map<string, KeyObject>();
  for (const r of validated) if (r.scheme === "ed25519") publicKeys.set(r.keyId, ed25519PublicKey(r.publicKey)!);
  return {
    verify(credential) {
      const parsed = typeof credential === "string" ? parseCredential(credential) : null;
      const keyId = parsed?.keyId ?? "0000000000000000";
      const record = byKeyId.get(keyId);
      // Always exactly one constant-time comparison, whatever the key id, scheme or input.
      const matches = digestsMatch(credentialHash(keyId, parsed?.secret ?? ""), record?.scheme === "bearer" ? record.sha256 : DUMMY_DIGEST);
      if (!parsed) return { ok: false, reason: "malformed" };
      if (!record) return { ok: false, reason: "unknown-key" };
      if (record.scheme !== "bearer") return { ok: false, reason: "scheme-mismatch" };
      if (!matches) return { ok: false, reason: "wrong-secret" };
      if (!bearerAllowed) return { ok: false, reason: "bearer-disabled" };
      const status = recordStatus(record, now());
      if (status !== "active") return { ok: false, reason: status };
      return { ok: true, agentId: record.agentId, keyId: record.keyId };
    },
    publicKeyFor(keyId) {
      const record = byKeyId.get(keyId);
      if (!record) return { ok: false, reason: "unknown-key" };
      if (record.scheme !== "ed25519") return { ok: false, reason: "scheme-mismatch" };
      const status = recordStatus(record, now());
      if (status !== "active") return { ok: false, reason: status };
      return { ok: true, agentId: record.agentId, keyId: record.keyId, publicKey: publicKeys.get(keyId)! };
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
    publicKeyFor: () => ({ ok: false, reason: "store-unavailable" }),
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
  | { kind: "no-policy"; agentId: string; keyId: string }
  /** M3-E E2: active legacy bearer credentials that cannot authenticate because bearer is disabled. */
  | { kind: "bearer-disabled"; count: number };

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
    /** Whether legacy bearer credentials may authenticate. Defaults to false. */
    bearerAllowed?: boolean;
    /** U8: whether an agent has a policy. Credentials without one load, with a warning. */
    hasPolicy?: (agentId: string) => boolean;
    onEvent?: (event: CredentialReloadEvent) => void;
  } = {},
): ReloadingCredentialStore {
  const now = options.now ?? Date.now;
  const intervalMs = options.intervalMs ?? RELOAD_INTERVAL_MS;
  const bearerAllowed = options.bearerAllowed === true;
  const onEvent = options.onEvent ?? (() => {});
  const build = (records: CredentialRecord[]) => createCredentialStore(records, { now, bearerAllowed });

  function warn(store: CredentialStore): void {
    const active = store.list().filter((record) => recordStatus(record, now()) === "active");
    if (options.hasPolicy) {
      for (const record of active) {
        if (!options.hasPolicy(record.agentId)) onEvent({ kind: "no-policy", agentId: record.agentId, keyId: record.keyId });
      }
    }
    const bearer = active.filter((record) => record.scheme === "bearer").length;
    if (!bearerAllowed && bearer > 0) onEvent({ kind: "bearer-disabled", count: bearer });
  }

  let signature = fileSignature(path);
  let current: CredentialStore = build(readCredentialFile(path, now()));
  let state: "ok" | "invalid" = "ok";
  let lastCheck = now();
  warn(current);

  function refresh(): void {
    const at = now();
    if (at - lastCheck < intervalMs) return;
    lastCheck = at;
    const next = fileSignature(path);
    if (next === signature) return;
    try {
      const store = build(readCredentialFile(path, at));
      current = store;
      state = "ok";
      signature = next;
      onEvent({ kind: "reloaded", count: store.list().length });
      warn(store);
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
    publicKeyFor(keyId) {
      refresh();
      return current.publicKeyFor(keyId);
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

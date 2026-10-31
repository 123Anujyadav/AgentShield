import { generateKeyPairSync, verify, type KeyObject } from "node:crypto";
import type { Request } from "express";
import { canonicalHost, canonicalRequestBytes, DEFAULT_TIMESTAMP_WINDOW_MS, parseAuthorization, sha256Hex } from "@agentshield/agent-protocol";
import type { CredentialStore } from "./credentials.js";
import { isAcceptableEd25519Signature } from "./ed25519.js";
import type { NonceCache } from "./nonce-cache.js";

/**
 * Server-side verification of signed agent requests (M3-E E3).
 *
 * The Authorization header, canonical request and body hash come from
 * @agentshield/agent-protocol, the same code the agent SDK signs with. In order:
 *
 * 1. Parse the header strictly (E1).
 * 2. Timestamp: not earlier than this server's start (the start-up fence), and
 *    within the allowed clock skew of the server clock (default ±30 s).
 * 3. Raw body: the exact bytes as received (captured before JSON parsing), no
 *    Content-Encoding; a body that was not captured is refused.
 * 4. Canonical request: method, Host (lower-cased), the exact request target as
 *    received, timestamp, nonce, key id and the body's SHA-256 (E1).
 * 5. Key: the key id's active Ed25519 public key from the credential store. One
 *    Ed25519 verification always runs, against a dummy key when the key id is
 *    unknown, revoked, expired, a bearer key or the store is unavailable, so the
 *    response time does not reveal which key ids exist.
 * 6. Signature: crypto.verify (Ed25519) over the canonical bytes, accepted only if R is
 *    not a small-order point and S is below the group order (M3-E audit M1).
 * 7. Replay: only after a valid signature, the key id and nonce are recorded in
 *    the nonce cache; a nonce already live for that key is a replay.
 *
 * Failures return a reason for the server log (never the header, signature or
 * key material). The client always sees the same 401, except the nonce-cache
 * limits: 429 for a key over its quota, 503 when the cache is full.
 */

export const DEFAULT_SIGNATURE_SKEW_SECONDS = DEFAULT_TIMESTAMP_WINDOW_MS / 1000;
export const MIN_SIGNATURE_SKEW_SECONDS = 5;
export const MAX_SIGNATURE_SKEW_SECONDS = 300;

export class SignatureConfigError extends Error {}

/**
 * AGENT_SIGNATURE_MAX_SKEW_SECONDS: a whole number of seconds from 5 to 300.
 * Unset (or empty) means the default of 30. Anything else is refused, so start-up fails.
 */
export function signatureSkewMsFromEnv(env: NodeJS.ProcessEnv = process.env): number {
  const raw = env.AGENT_SIGNATURE_MAX_SKEW_SECONDS;
  if (raw === undefined || raw === "") return DEFAULT_SIGNATURE_SKEW_SECONDS * 1000;
  const seconds = /^[1-9][0-9]{0,2}$/.test(raw) ? Number(raw) : Number.NaN;
  if (!(seconds >= MIN_SIGNATURE_SKEW_SECONDS && seconds <= MAX_SIGNATURE_SKEW_SECONDS)) {
    throw new SignatureConfigError(
      `AGENT_SIGNATURE_MAX_SKEW_SECONDS must be a whole number of seconds from ${MIN_SIGNATURE_SKEW_SECONDS} to ${MAX_SIGNATURE_SKEW_SECONDS}.`,
    );
  }
  return seconds * 1000;
}

const rawBodies = new WeakMap<object, Buffer>();

/** express.json `verify` hook: keeps the exact body bytes as received, before parsing. */
export function captureRawBody(req: object, _res: unknown, buf: Buffer): void {
  rawBodies.set(req, buf);
}

/** The captured raw body; zero bytes when the request has no body; null when it has one that was not captured. */
function rawBodyOf(req: Request): Uint8Array | null {
  const captured = rawBodies.get(req);
  if (captured) return captured;
  const length = req.headers["content-length"];
  const hasBody = req.headers["transfer-encoding"] !== undefined || (length !== undefined && length !== "0");
  return hasBody ? null : new Uint8Array(0);
}

/** Used when the key id has no usable public key, so the work done is the same. */
const DUMMY_PUBLIC_KEY: KeyObject = generateKeyPairSync("ed25519").publicKey;

export type SignatureRejection =
  | "bad-header"
  | "before-startup"
  | "stale"
  | "future"
  | "content-encoding"
  | "unreadable-body"
  | "bad-host"
  | "bad-request"
  | "unknown-key"
  | "scheme-mismatch"
  | "revoked"
  | "expired"
  | "store-unavailable"
  | "bad-signature"
  | "replay"
  | "nonce-key-quota"
  | "nonce-capacity";

export type SignedVerification =
  | { ok: true; agentId: string; keyId: string }
  | { ok: false; status: 401 | 429 | 503; reason: SignatureRejection; keyId: string | null };

export interface SignatureVerifierDeps {
  credentials: CredentialStore;
  nonces: NonceCache;
  now: () => number;
  /** Allowed clock skew in ms (see signatureSkewMsFromEnv). */
  skewMs: number;
  /** Server start time in ms: earlier timestamps are refused (the start-up fence). */
  startedAt: number;
}

export function createSignatureVerifier(deps: SignatureVerifierDeps): (req: Request) => SignedVerification {
  return (req) => {
    const fail = (reason: SignatureRejection, keyId: string | null, status: 401 | 429 | 503 = 401): SignedVerification => ({ ok: false, status, reason, keyId });

    const parsed = parseAuthorization(req.headers.authorization);
    if (!parsed.ok) return fail("bad-header", null);
    const { keyId, timestamp, nonce, signature } = parsed.value;

    const ts = Number(timestamp);
    const now = deps.now();
    if (ts < deps.startedAt) return fail("before-startup", keyId);
    if (ts < now - deps.skewMs) return fail("stale", keyId);
    if (ts > now + deps.skewMs) return fail("future", keyId);

    const encoding = req.headers["content-encoding"];
    if (encoding !== undefined && encoding !== "identity") return fail("content-encoding", keyId);
    const body = rawBodyOf(req);
    if (body === null) return fail("unreadable-body", keyId);
    const host = canonicalHost(req.headers.host);
    if (host === null) return fail("bad-host", keyId);
    let message: Uint8Array;
    try {
      message = canonicalRequestBytes({ method: req.method, host, target: req.originalUrl, timestamp, nonce, keyId, bodySha256: sha256Hex(body) });
    } catch {
      return fail("bad-request", keyId);
    }

    const key = deps.credentials.publicKeyFor(keyId);
    const signatureBytes = Buffer.from(signature, "base64url");
    let valid = false;
    try {
      // Always exactly one verification; the encoding check is applied to its result, not instead of it.
      valid = verify(null, message, key.ok ? key.publicKey : DUMMY_PUBLIC_KEY, signatureBytes) && isAcceptableEd25519Signature(signatureBytes);
    } catch {
      valid = false;
    }
    if (!key.ok) return fail(key.reason, keyId);
    if (!valid) return fail("bad-signature", keyId);

    const outcome = deps.nonces.checkAndInsert(keyId, nonce, ts + deps.skewMs);
    if (outcome === "replay") return fail("replay", keyId);
    if (outcome === "key-quota") return fail("nonce-key-quota", keyId, 429);
    if (outcome === "global-full") return fail("nonce-capacity", keyId, 503);
    return { ok: true, agentId: key.agentId, keyId };
  };
}

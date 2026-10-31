import { createHash } from "node:crypto";

/**
 * AgentShield signed agent requests, version 1 (M3-E E1).
 *
 * One implementation shared by the API (verification) and the agent SDK
 * (signing), so both build exactly the same bytes. It has no Express or browser
 * dependency; it needs only node:crypto (SHA-256). It does not sign, verify,
 * check timestamps against a clock or track nonces: those belong to the SDK
 * (E5) and the server (E3).
 *
 * Authorization header (one header, exactly this form; parameters in this order,
 * separated by a comma and one space, values in double quotes):
 *
 *   AGENTSHIELD-SIG-V1 keyId="<k>", ts="<t>", nonce="<n>", sig="<s>"
 *
 *   keyId  16 lower-case hex digits: the agent credential's public key id.
 *   ts     Unix time in milliseconds: 13 decimal digits, no sign, no leading zero.
 *   nonce  16 random bytes, base64url without padding (22 characters, canonical).
 *   sig    the Ed25519 signature (64 bytes), base64url without padding (86 characters, canonical).
 *
 * Only these four parameters exist. A private key never appears in the header:
 * any other parameter is refused, and `sig` must be exactly one 64-byte signature.
 *
 * Canonical request: these eight fields, each on its own line, joined with LF
 * (0x0A) and with no trailing LF. Every field is printable ASCII without CR or LF,
 * so the canonical bytes are the same in ASCII and UTF-8:
 *
 *   1. AGENTSHIELD-SIG-V1
 *   2. method        upper-case letters only, exactly as sent (GET, POST, ...).
 *   3. host          the Host header, ASCII lower-cased (see canonicalHost). No other change.
 *   4. target        the request target exactly as sent: origin-form path plus query,
 *                    RFC 3986 characters only (anything else must be percent-encoded by the
 *                    sender). Never decoded, re-encoded, case-folded or dot-segment-normalised.
 *   5. ts            as in the header.
 *   6. nonce         as in the header.
 *   7. keyId         as in the header.
 *   8. body-sha256   lower-case hex SHA-256 of the exact raw body bytes; a request with no
 *                    body hashes zero bytes (EMPTY_BODY_SHA256).
 *
 * The signature is computed over the UTF-8 bytes of that string (canonicalRequestBytes).
 * Validation errors carry a reason code and never echo the rejected value.
 */

export const AUTH_SCHEME = "AGENTSHIELD-SIG-V1";
export const MAX_AUTHORIZATION_LENGTH = 512;
export const MAX_TARGET_LENGTH = 2048;
export const MAX_HOST_LENGTH = 261;
export const NONCE_BYTES = 16;
export const SIGNATURE_BYTES = 64;
/** The default allowed difference between a request's ts and the server clock (enforced in E3). */
export const DEFAULT_TIMESTAMP_WINDOW_MS = 30_000;
/** SHA-256 of zero bytes: the body hash of a request without a body. */
export const EMPTY_BODY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

const KEY_ID = /^[0-9a-f]{16}$/;
const TIMESTAMP = /^[1-9][0-9]{12}$/;
const BASE64URL = /^[A-Za-z0-9_-]+$/;
const METHOD = /^[A-Z]{1,16}$/;
const SHA256_HEX = /^[0-9a-f]{64}$/;
const PRINTABLE_ASCII = /^[\x20-\x7E]*$/;
/** RFC 3986 origin-form: "/" then unreserved, sub-delims, ":", "@", "/", "?" or a %XX escape. */
const TARGET = /^\/(?:[A-Za-z0-9\-._~!$&'()*+,;=:@/?]|%[0-9A-Fa-f]{2})*$/;
const HOST_NAME = /^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$/;
const HOST_IPV6 = /^\[[0-9a-f:.]{2,45}\]$/;
const PARAMETERS = ["keyId", "ts", "nonce", "sig"] as const;

export type ProtocolRejection =
  | "not-a-string"
  | "too-long"
  | "invalid-characters"
  | "wrong-scheme"
  | "malformed"
  | "unknown-parameter"
  | "duplicate-parameter"
  | "missing-parameter"
  | "invalid-key-id"
  | "invalid-timestamp"
  | "invalid-nonce"
  | "invalid-signature"
  | "non-canonical"
  | "invalid-method"
  | "invalid-host"
  | "invalid-target"
  | "invalid-body-hash"
  | "invalid-body";

/** A rejected protocol value. The message names the field only; the value is never included. */
export class ProtocolError extends Error {
  constructor(readonly reason: ProtocolRejection) {
    super(`Invalid signed-request field (${reason}).`);
    this.name = "ProtocolError";
  }
}

/** Unpadded base64url that decodes to exactly `bytes` bytes and re-encodes to itself. */
function isCanonicalBase64url(value: unknown, bytes: number): value is string {
  if (typeof value !== "string" || value.length !== Math.ceil((bytes * 4) / 3) || !BASE64URL.test(value)) return false;
  const decoded = Buffer.from(value, "base64url");
  return decoded.length === bytes && decoded.toString("base64url") === value;
}

export const isKeyId = (value: unknown): value is string => typeof value === "string" && KEY_ID.test(value);
export const isTimestamp = (value: unknown): value is string => typeof value === "string" && TIMESTAMP.test(value);
export const isNonce = (value: unknown): value is string => isCanonicalBase64url(value, NONCE_BYTES);
export const isSignature = (value: unknown): value is string => isCanonicalBase64url(value, SIGNATURE_BYTES);
export const isMethod = (value: unknown): value is string => typeof value === "string" && METHOD.test(value);
export const isSha256Hex = (value: unknown): value is string => typeof value === "string" && SHA256_HEX.test(value);
export const isTarget = (value: unknown): value is string =>
  typeof value === "string" && value.length <= MAX_TARGET_LENGTH && TARGET.test(value);

/** A host already in canonical form: lower-case name, IPv4 or bracketed IPv6, optional port 1-65535. */
export function isCanonicalHost(value: unknown): value is string {
  if (typeof value !== "string" || value.length === 0 || value.length > MAX_HOST_LENGTH) return false;
  const ipv6 = value.startsWith("[");
  const portIndex = ipv6 ? value.indexOf("]:") + 1 : value.lastIndexOf(":");
  const name = portIndex > 0 ? value.slice(0, portIndex) : value;
  const port = portIndex > 0 ? value.slice(portIndex + 1) : null;
  if (port !== null && (!/^[1-9][0-9]{0,4}$/.test(port) || Number(port) > 65535)) return false;
  return ipv6 ? HOST_IPV6.test(name) : HOST_NAME.test(name);
}

/**
 * The host field from a Host header: ASCII lower-cased (host names are
 * case-insensitive), otherwise unchanged. Null when it is not a valid host.
 */
export function canonicalHost(hostHeader: unknown): string | null {
  if (typeof hostHeader !== "string" || !PRINTABLE_ASCII.test(hostHeader)) return null;
  const lowered = hostHeader.toLowerCase();
  return isCanonicalHost(lowered) ? lowered : null;
}

/** Lower-case hex SHA-256 of the exact raw body bytes. No body (undefined or null) means zero bytes. */
export function sha256Hex(body?: Uint8Array | null): string {
  if (body !== undefined && body !== null && !(body instanceof Uint8Array)) throw new ProtocolError("invalid-body");
  return createHash("sha256").update(body ?? new Uint8Array(0)).digest("hex");
}

export interface SignatureParameters {
  keyId: string;
  timestamp: string;
  nonce: string;
  signature: string;
}

function checkParameters(p: SignatureParameters): ProtocolRejection | null {
  if (!isKeyId(p.keyId)) return "invalid-key-id";
  if (!isTimestamp(p.timestamp)) return "invalid-timestamp";
  if (!isNonce(p.nonce)) return "invalid-nonce";
  if (!isSignature(p.signature)) return "invalid-signature";
  return null;
}

/** The Authorization header value. Throws ProtocolError for any invalid parameter. */
export function formatAuthorization(p: SignatureParameters): string {
  const problem = checkParameters(p);
  if (problem) throw new ProtocolError(problem);
  return `${AUTH_SCHEME} keyId="${p.keyId}", ts="${p.timestamp}", nonce="${p.nonce}", sig="${p.signature}"`;
}

export type AuthorizationParseResult = { ok: true; value: SignatureParameters } | { ok: false; reason: ProtocolRejection };

/**
 * Parses an Authorization header strictly. Anything other than exactly the
 * format above is refused: wrong scheme or case, unknown, duplicate or missing
 * parameters, invalid values, other spacing or order, control or non-ASCII
 * characters, or more than MAX_AUTHORIZATION_LENGTH characters.
 */
export function parseAuthorization(header: unknown): AuthorizationParseResult {
  const fail = (reason: ProtocolRejection): AuthorizationParseResult => ({ ok: false, reason });
  if (typeof header !== "string") return fail("not-a-string");
  if (header.length > MAX_AUTHORIZATION_LENGTH) return fail("too-long");
  if (!PRINTABLE_ASCII.test(header)) return fail("invalid-characters");
  const prefix = `${AUTH_SCHEME} `;
  if (!header.startsWith(prefix)) return fail("wrong-scheme");
  const values = new Map<string, string>();
  for (const part of header.slice(prefix.length).split(", ")) {
    const match = /^([A-Za-z]{1,16})="([^"]*)"$/.exec(part);
    if (!match) return fail("malformed");
    const name = match[1]!;
    if (!(PARAMETERS as readonly string[]).includes(name)) return fail("unknown-parameter");
    if (values.has(name)) return fail("duplicate-parameter");
    values.set(name, match[2]!);
  }
  for (const name of PARAMETERS) if (!values.has(name)) return fail("missing-parameter");
  const value: SignatureParameters = { keyId: values.get("keyId")!, timestamp: values.get("ts")!, nonce: values.get("nonce")!, signature: values.get("sig")! };
  const problem = checkParameters(value);
  if (problem) return fail(problem);
  // Exactly one accepted spelling: the formatter's (parameter order and separators).
  if (formatAuthorization(value) !== header) return fail("non-canonical");
  return { ok: true, value };
}

export interface CanonicalRequestInput {
  method: string;
  /** Canonical host (see canonicalHost). */
  host: string;
  /** The request target exactly as sent. */
  target: string;
  timestamp: string;
  nonce: string;
  keyId: string;
  /** sha256Hex of the raw body bytes. */
  bodySha256: string;
}

/** The canonical request string. Throws ProtocolError if any field is invalid; nothing is normalised here. */
export function buildCanonicalRequest(input: CanonicalRequestInput): string {
  if (!isMethod(input.method)) throw new ProtocolError("invalid-method");
  if (!isCanonicalHost(input.host)) throw new ProtocolError("invalid-host");
  if (!isTarget(input.target)) throw new ProtocolError("invalid-target");
  if (!isTimestamp(input.timestamp)) throw new ProtocolError("invalid-timestamp");
  if (!isNonce(input.nonce)) throw new ProtocolError("invalid-nonce");
  if (!isKeyId(input.keyId)) throw new ProtocolError("invalid-key-id");
  if (!isSha256Hex(input.bodySha256)) throw new ProtocolError("invalid-body-hash");
  return [AUTH_SCHEME, input.method, input.host, input.target, input.timestamp, input.nonce, input.keyId, input.bodySha256].join("\n");
}

/** The bytes that are signed: UTF-8 (identical to ASCII here) of the canonical request. */
export function canonicalRequestBytes(input: CanonicalRequestInput): Uint8Array {
  return Buffer.from(buildCanonicalRequest(input), "utf8");
}

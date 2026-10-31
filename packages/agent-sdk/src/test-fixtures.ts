import { createHash, createPrivateKey, createPublicKey, verify, type KeyObject } from "node:crypto";
import { canonicalHost, canonicalRequestBytes, parseAuthorization, sha256Hex } from "@agentshield/agent-protocol";

/**
 * Test fixtures only (M3-E E5): deterministic Ed25519 credentials derived at runtime from a
 * label, so no key material is stored in the repository. Never real credentials.
 */

const ED25519_PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");

export interface TestKey {
  credential: string;
  keyId: string;
  /** The base64url private-key part, to check it never leaks. */
  secretPart: string;
  publicKey: KeyObject;
}

export function testKey(label: string): TestKey {
  const seed = createHash("sha256").update(`agentshield-sdk-test-key\0${label}`).digest();
  const keyId = createHash("sha256").update(`agentshield-sdk-test-key-id\0${label}`).digest("hex").slice(0, 16);
  const der = Buffer.concat([ED25519_PKCS8_PREFIX, seed]);
  const publicKey = createPublicKey(createPrivateKey({ key: der, format: "der", type: "pkcs8" }));
  const secretPart = der.toString("base64url");
  return { credential: `asag2_${keyId}.${secretPart}`, keyId, secretPart, publicKey };
}

/** Verifies a signed request the way the server does: rebuild the canonical bytes from what was sent. */
export function verifySignedRequest(input: { method: string; url: string; authorization: string; body?: Uint8Array }, publicKey: KeyObject): boolean {
  const parsed = parseAuthorization(input.authorization);
  if (!parsed.ok) return false;
  const url = new URL(input.url);
  const message = canonicalRequestBytes({
    method: input.method,
    host: canonicalHost(url.host)!,
    target: `${url.pathname}${url.search}`,
    timestamp: parsed.value.timestamp,
    nonce: parsed.value.nonce,
    keyId: parsed.value.keyId,
    bodySha256: sha256Hex(input.body),
  });
  return verify(null, message, publicKey, Buffer.from(parsed.value.signature, "base64url"));
}

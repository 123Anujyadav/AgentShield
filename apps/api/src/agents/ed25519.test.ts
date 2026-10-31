import { createPublicKey, generateKeyPairSync, sign, verify } from "node:crypto";
import { describe, expect, it } from "vitest";
import { createCredentialStore, CredentialConfigError, ed25519PublicKey, issueEd25519Credential, parseCredentialDocument } from "./credentials.js";
import { isAcceptableEd25519PublicKey, isAcceptableEd25519Signature, isCanonicalPointEncoding, isSmallOrderEncoding } from "./ed25519.js";

/** M3-E audit M1: Ed25519 public-key and signature encodings that must never be trusted. */

const P = 2n ** 255n - 19n;
const D = 37095705934669439343138083508754565189542113879843219016388785533085940283555n;
const L = 2n ** 252n + 27742317777372353535851937790883648493n;
const Y8A = 2707385501144840649318225287225658788936804267575313519463743609750303402022n;
const Y8B = 55188659117513257062467267217118295137698188065244968500265048394206261417927n;

/** A 32-byte point encoding: y little-endian, with the x sign in the top bit. */
function encode(y: bigint, sign: 0 | 1 = 0): Buffer {
  const bytes = Buffer.alloc(32);
  let v = y;
  for (let i = 0; i < 32; i += 1) {
    bytes[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  bytes[31]! |= sign << 7;
  return bytes;
}
const b64 = (bytes: Buffer) => bytes.toString("base64url");
const modP = (a: bigint) => ((a % P) + P) % P;

/** The eight small-order points: y = 1 (identity), p-1 (order 2), 0 with either x (order 4), and the two order-8 y values with either x. */
const SMALL_ORDER: Array<[string, Buffer]> = [
  ["identity (01 then 31 zero bytes)", encode(1n)],
  ["order 2 (y = p - 1)", encode(P - 1n)],
  ["order 4, x positive (all-zero key)", encode(0n)],
  ["order 4, x negative", encode(0n, 1)],
  ["order 8 (first y), x positive", encode(Y8A)],
  ["order 8 (first y), x negative", encode(Y8A, 1)],
  ["order 8 (second y), x positive", encode(Y8B)],
  ["order 8 (second y), x negative", encode(Y8B, 1)],
];

const NON_CANONICAL: Array<[string, Buffer]> = [
  ["y = p (another encoding of y = 0)", encode(P)],
  ["y = p + 1 (another encoding of the identity)", encode(P + 1n)],
  ["y = 2^255 - 1", encode(2n ** 255n - 1n)],
  ["identity with the sign bit set (negative zero)", encode(1n, 1)],
  ["order-2 point with the sign bit set (negative zero)", encode(P - 1n, 1)],
];

describe("M3-E audit M1: point validation", () => {
  it("the small-order y constants really are small order (independent check)", () => {
    // A point of order 8 doubles to (+-sqrt(-1), 0), which requires d*y^4 + 2*y^2 - 1 = 0 (mod p).
    for (const y of [Y8A, Y8B]) expect(modP(D * y ** 4n + 2n * y * y - 1n)).toBe(0n);
  });

  it.each(SMALL_ORDER)("refuses the small-order point: %s", (_label, encoding) => {
    expect(isSmallOrderEncoding(encoding)).toBe(true);
    expect(isAcceptableEd25519PublicKey(encoding)).toBe(false);
    expect(ed25519PublicKey(b64(encoding))).toBeNull();
  });

  it.each(NON_CANONICAL)("refuses the non-canonical encoding: %s", (_label, encoding) => {
    expect(isCanonicalPointEncoding(encoding)).toBe(false);
    expect(isAcceptableEd25519PublicKey(encoding)).toBe(false);
    expect(ed25519PublicKey(b64(encoding))).toBeNull();
  });

  it("refuses a y that is not on the curve, and accepts one that is", () => {
    expect(isCanonicalPointEncoding(encode(2n))).toBe(false);
    expect(isCanonicalPointEncoding(encode(3n))).toBe(true);
    expect(isAcceptableEd25519PublicKey(encode(3n))).toBe(true);
  });

  it("accepts the RFC 8032 test-1 public key and every generated key", () => {
    expect(isAcceptableEd25519PublicKey(Buffer.from("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "hex"))).toBe(true);
    for (let i = 0; i < 200; i += 1) {
      const x = generateKeyPairSync("ed25519").publicKey.export({ format: "jwk" }).x!;
      expect(isAcceptableEd25519PublicKey(Buffer.from(x, "base64url"))).toBe(true);
      expect(ed25519PublicKey(x)?.asymmetricKeyType).toBe("ed25519");
    }
  });

  it("a credential store with a small-order or non-canonical public key is invalid; issued keys are fine", () => {
    const issued = issueEd25519Credential({ agentId: "writer", now: Date.now(), takenKeyIds: new Set() });
    expect(createCredentialStore([issued.record]).publicKeyFor(issued.record.keyId).ok).toBe(true);
    for (const [, encoding] of [...SMALL_ORDER, ...NON_CANONICAL]) {
      const doc = JSON.stringify({ schemaVersion: 2, credentials: [{ ...issued.record, publicKey: b64(encoding) }] });
      expect(() => parseCredentialDocument(doc, Date.now())).toThrowError(CredentialConfigError);
    }
  });
});

describe("M3-E audit M1: signature validation", () => {
  it("node:crypto alone accepts the universal forgery for the identity key (why the checks exist)", () => {
    const identity = createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: b64(encode(1n)) }, format: "jwk" });
    const forged = Buffer.concat([encode(1n), Buffer.alloc(32)]);
    expect(verify(null, Buffer.from("any message"), identity, forged)).toBe(true);
    expect(isAcceptableEd25519Signature(forged)).toBe(false);
  });

  it.each(SMALL_ORDER)("refuses a signature whose R is the small-order point: %s", (_label, encoding) => {
    expect(isAcceptableEd25519Signature(Buffer.concat([encoding, Buffer.alloc(32)]))).toBe(false);
  });

  it("refuses S >= L and accepts real signatures", () => {
    const { privateKey } = generateKeyPairSync("ed25519");
    const real = sign(null, Buffer.from("message"), privateKey);
    expect(isAcceptableEd25519Signature(real)).toBe(true);
    const withS = (s: bigint) => Buffer.concat([real.subarray(0, 32), encode(s)]);
    expect(isAcceptableEd25519Signature(withS(L - 1n))).toBe(true);
    expect(isAcceptableEd25519Signature(withS(L))).toBe(false);
    expect(isAcceptableEd25519Signature(withS(2n ** 255n - 1n))).toBe(false);
    expect(isAcceptableEd25519Signature(real.subarray(0, 63))).toBe(false);
  });
});

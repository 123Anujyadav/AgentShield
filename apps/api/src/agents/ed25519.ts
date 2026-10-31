/**
 * Ed25519 encoding checks that node:crypto does not make (M3-E audit M1).
 *
 * Node (OpenSSL) accepts any 32 bytes that decode as a point as an Ed25519 public
 * key, including small-order points. With the identity point as a public key, the
 * signature R = identity, S = 0 verifies for every message, so a stored key must be
 * checked before it is trusted. This module implements:
 *
 * - point decoding exactly as RFC 8032 section 5.1.3: the y coordinate must be
 *   canonical (y < p), the point must be on the curve, and x = 0 with the sign bit
 *   set ("negative zero") is refused;
 * - the small-order check libsodium uses (ge25519_has_small_order): a point whose y
 *   coordinate is 0, 1, p - 1 or one of the two order-8 values is refused. Those five
 *   y values, with either sign of x, cover all eight points of small order;
 * - for signatures: R must not be a small-order point and S must be below the group
 *   order L (libsodium's crypto_sign_verify_detached does the same).
 *
 * Plain BigInt arithmetic, no dependency. Nothing here is secret-dependent: public
 * keys and signatures are public values.
 */

const P = 2n ** 255n - 19n;
/** d = -121665 / 121666 mod p (RFC 8032). */
const D = 37095705934669439343138083508754565189542113879843219016388785533085940283555n;
/** sqrt(-1) mod p (RFC 8032). */
const SQRT_M1 = 19681161376707505956807079304988542015446066515923890162744021073123829784752n;
/** The prime order of the base point's subgroup. */
const L = 2n ** 252n + 27742317777372353535851937790883648493n;

/** y coordinates of the eight small-order points (libsodium's blocklist, decimal as in its comments). */
const SMALL_ORDER_Y = new Set<bigint>([
  0n, // order 4: (+-sqrt(-1), 0)
  1n, // order 1: the identity (0, 1)
  P - 1n, // order 2: (0, -1)
  2707385501144840649318225287225658788936804267575313519463743609750303402022n, // order 8 (two points)
  55188659117513257062467267217118295137698188065244968500265048394206261417927n, // order 8 (two points)
]);

function mod(a: bigint): bigint {
  const r = a % P;
  return r < 0n ? r + P : r;
}

function modPow(base: bigint, exponent: bigint): bigint {
  let result = 1n;
  let b = mod(base);
  let e = exponent;
  while (e > 0n) {
    if (e & 1n) result = (result * b) % P;
    b = (b * b) % P;
    e >>= 1n;
  }
  return result;
}

function littleEndian(bytes: Uint8Array): bigint {
  let value = 0n;
  for (let i = bytes.length - 1; i >= 0; i -= 1) value = (value << 8n) | BigInt(bytes[i]!);
  return value;
}

/** The y coordinate and x sign bit of a 32-byte point encoding. */
function splitEncoding(encoding: Uint8Array): { y: bigint; sign: number } {
  const bytes = Uint8Array.from(encoding);
  const sign = bytes[31]! >> 7;
  bytes[31]! &= 0x7f;
  return { y: littleEndian(bytes), sign };
}

/** RFC 8032 section 5.1.3: whether 32 bytes are the canonical encoding of a point on Ed25519. */
export function isCanonicalPointEncoding(encoding: Uint8Array): boolean {
  if (encoding.length !== 32) return false;
  const { y, sign } = splitEncoding(encoding);
  if (y >= P) return false;
  const y2 = (y * y) % P;
  const u = mod(y2 - 1n);
  const v = mod(D * y2 + 1n);
  const v3 = (v * v * v) % P;
  let x = (u * v3 * modPow(u * v3 * v3 * v, (P - 5n) / 8n)) % P;
  const vx2 = (v * x * x) % P;
  if (vx2 === u) {
    // x is a square root of u/v.
  } else if (vx2 === mod(-u)) {
    x = (x * SQRT_M1) % P;
  } else {
    return false;
  }
  return !(x === 0n && sign === 1);
}

/** Whether 32 bytes encode (canonically or not) one of the eight small-order points. */
export function isSmallOrderEncoding(encoding: Uint8Array): boolean {
  if (encoding.length !== 32) return false;
  const { y } = splitEncoding(encoding);
  return SMALL_ORDER_Y.has(y % P);
}

/** A public key that may be trusted: canonical, on the curve, and not of small order. */
export function isAcceptableEd25519PublicKey(encoding: Uint8Array): boolean {
  return encoding.length === 32 && isCanonicalPointEncoding(encoding) && !isSmallOrderEncoding(encoding);
}

/** A signature that may be passed to verification: R not of small order, S below L. */
export function isAcceptableEd25519Signature(signature: Uint8Array): boolean {
  if (signature.length !== 64) return false;
  if (isSmallOrderEncoding(signature.subarray(0, 32))) return false;
  return littleEndian(signature.subarray(32, 64)) < L;
}

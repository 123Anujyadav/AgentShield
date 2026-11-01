import { describe, expect, it } from "vitest";
import {
  AUTH_SCHEME,
  buildCanonicalRequest,
  canonicalHost,
  formatAuthorization,
  isTarget,
  MAX_AUTHORIZATION_LENGTH,
  parseAuthorization,
  ProtocolError,
  sha256Hex,
} from "./canonical.js";

/**
 * M3-E E13: deterministic fuzz / property tests for the signed-request format. A fixed-seed PRNG
 * (mulberry32) makes every run identical; no dependency is added.
 */

function prng(seed: number) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
const SEEDS = [1, 7, 42, 1337, 20261101];

/** Characters chosen to stress parsers: ASCII, quotes, separators, controls, bidi, emoji, surrogates. */
const ALPHABET = [..."abcXYZ019 ,=\"'\\/-_.:;~!?@#$%^&*()[]{}<>|`\t\r\n", "\u0000", "\u0007", "\u007f", "é", "\u200B", "\u202E", "\u2028", "😀", "\ud800"];

function randomString(random: () => number, max: number): string {
  const length = Math.floor(random() * max);
  let out = "";
  for (let i = 0; i < length; i += 1) out += ALPHABET[Math.floor(random() * ALPHABET.length)];
  return out;
}

const VALID = {
  keyId: "0123456789abcdef",
  timestamp: "1793523600000",
  nonce: "AAAAAAAAAAAAAAAAAAAAAA",
  signature: "A".repeat(85) + "A",
};

describe("M3-E E13: Authorization header fuzzing", () => {
  it("a valid header round-trips exactly", () => {
    expect(parseAuthorization(formatAuthorization(VALID))).toEqual({ ok: true, value: VALID });
  });

  it.each(SEEDS)("random input never throws and is never accepted (seed %i)", (seed) => {
    const random = prng(seed);
    for (let i = 0; i < 2000; i += 1) {
      const candidate = random() < 0.5 ? randomString(random, 120) : `${AUTH_SCHEME} ${randomString(random, 200)}`;
      const result = parseAuthorization(candidate);
      expect(result.ok).toBe(false);
    }
  });

  it.each(SEEDS)("every single-character mutation of a valid header is rejected or parses to the same values (seed %i)", (seed) => {
    const random = prng(seed);
    const header = formatAuthorization(VALID);
    for (let i = 0; i < 1000; i += 1) {
      const position = Math.floor(random() * header.length);
      const replacement = ALPHABET[Math.floor(random() * ALPHABET.length)]!;
      const mutated = header.slice(0, position) + replacement + header.slice(position + 1);
      const result = parseAuthorization(mutated);
      if (mutated === header) expect(result.ok).toBe(true);
      else if (result.ok) expect(result.value).not.toEqual(VALID); // a different but still canonical value
    }
  });

  it("non-string, oversized and duplicated-parameter headers are rejected", () => {
    for (const value of [undefined, null, 42, {}, [], Buffer.from("x")]) expect(parseAuthorization(value).ok).toBe(false);
    expect(parseAuthorization(`${formatAuthorization(VALID)}${" ".repeat(MAX_AUTHORIZATION_LENGTH)}`).ok).toBe(false);
    expect(parseAuthorization(`${formatAuthorization(VALID)}, keyId="0123456789abcdef"`).ok).toBe(false);
  });
});

describe("M3-E E13: canonical request fuzzing", () => {
  const base = { method: "POST", host: "127.0.0.1:4000", target: "/api/evaluate", timestamp: VALID.timestamp, nonce: VALID.nonce, keyId: VALID.keyId, bodySha256: sha256Hex(Buffer.from("{}")) };

  it.each(SEEDS)("random hosts and targets either build a canonical request or throw ProtocolError, nothing else (seed %i)", (seed) => {
    const random = prng(seed);
    for (let i = 0; i < 1500; i += 1) {
      const target = random() < 0.5 ? `/${randomString(random, 40)}` : randomString(random, 40);
      const host = randomString(random, 30);
      try {
        const text = buildCanonicalRequest({ ...base, target, host });
        // Whatever was accepted is printable ASCII, one field per line, eight lines.
        expect(/^[\x20-\x7e\n]*$/.test(text)).toBe(true);
        expect(text.split("\n")).toHaveLength(8);
        expect(isTarget(target)).toBe(true);
      } catch (error) {
        expect(error).toBeInstanceOf(ProtocolError);
      }
    }
  });

  it.each(SEEDS)("canonicalHost never returns a value containing control, space or non-ASCII characters (seed %i)", (seed) => {
    const random = prng(seed);
    for (let i = 0; i < 2000; i += 1) {
      const host = canonicalHost(randomString(random, 30));
      if (host !== null) expect(/^[a-z0-9.:\[\]-]+$/.test(host)).toBe(true);
    }
  });
});

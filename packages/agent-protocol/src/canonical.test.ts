import { generateKeyPairSync, randomBytes, sign, verify } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  AUTH_SCHEME,
  buildCanonicalRequest,
  canonicalHost,
  canonicalRequestBytes,
  EMPTY_BODY_SHA256,
  formatAuthorization,
  isCanonicalHost,
  isNonce,
  isSignature,
  isTarget,
  MAX_AUTHORIZATION_LENGTH,
  MAX_TARGET_LENGTH,
  parseAuthorization,
  ProtocolError,
  sha256Hex,
  type CanonicalRequestInput,
  type SignatureParameters,
} from "./canonical.js";

/** M3-E E1: the shared signed-request protocol. Fixed vectors only; keys are generated at runtime and never stored. */

const KEY_ID = "0123456789abcdef";
const TS = "1793523600123";
const NONCE = "AAECAwQFBgcICQoLDA0ODw"; // bytes 0x00..0x0f
const SIG = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0-Pw"; // bytes 0x00..0x3f
const BODY = '{"intent":{"task":"Summarize"},"action":{"type":"create_summary","tool":"simulated.workspace.createSummary","destination":"simulated-workspace","summary":"Create a summary"}}';
const BODY_SHA256 = "dff6be8da49e8968897a2ea6b144bc9bb6724d0288ed6b58d6bda0cd61d8e296";
const params: SignatureParameters = { keyId: KEY_ID, timestamp: TS, nonce: NONCE, signature: SIG };
const HEADER = `AGENTSHIELD-SIG-V1 keyId="${KEY_ID}", ts="${TS}", nonce="${NONCE}", sig="${SIG}"`;

const evaluateRequest: CanonicalRequestInput = {
  method: "POST",
  host: "127.0.0.1:4000",
  target: "/api/evaluate",
  timestamp: TS,
  nonce: NONCE,
  keyId: KEY_ID,
  bodySha256: BODY_SHA256,
};

const reasonOf = (fn: () => unknown): string | null => {
  try {
    fn();
    return null;
  } catch (error) {
    return error instanceof ProtocolError ? error.reason : `unexpected: ${String(error)}`;
  }
};

describe("M3-E E1: fixed canonical request vectors", () => {
  it("POST with a JSON body", () => {
    expect(sha256Hex(Buffer.from(BODY, "utf8"))).toBe(BODY_SHA256);
    expect(buildCanonicalRequest(evaluateRequest)).toBe(
      [
        "AGENTSHIELD-SIG-V1",
        "POST",
        "127.0.0.1:4000",
        "/api/evaluate",
        "1793523600123",
        "AAECAwQFBgcICQoLDA0ODw",
        "0123456789abcdef",
        "dff6be8da49e8968897a2ea6b144bc9bb6724d0288ed6b58d6bda0cd61d8e296",
      ].join("\n"),
    );
  });

  it("GET with a query string and no body", () => {
    const canonical = buildCanonicalRequest({ ...evaluateRequest, method: "GET", host: "localhost:4000", target: "/api/agent/approvals?status=PENDING&limit=10", bodySha256: sha256Hex() });
    expect(canonical).toBe(
      "AGENTSHIELD-SIG-V1\nGET\nlocalhost:4000\n/api/agent/approvals?status=PENDING&limit=10\n1793523600123\nAAECAwQFBgcICQoLDA0ODw\n0123456789abcdef\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    );
  });

  it("the signed bytes are the UTF-8 (= ASCII) bytes of the canonical string: LF only, no trailing newline", () => {
    const bytes = Buffer.from(canonicalRequestBytes(evaluateRequest));
    expect(bytes.toString("utf8")).toBe(buildCanonicalRequest(evaluateRequest));
    expect(bytes.includes(0x0d)).toBe(false);
    expect(bytes.filter((b) => b === 0x0a)).toHaveLength(7);
    expect(bytes.at(-1)).not.toBe(0x0a);
    expect([...bytes].every((b) => b >= 0x0a && b <= 0x7e)).toBe(true);
    // Fixed vector for other implementations: 171 bytes with this SHA-256.
    expect([bytes.length, sha256Hex(bytes)]).toEqual([171, "c03be3f3545dc896d23020ff47d487f7564ef532a09835534c9a3190b9ae6155"]);
  });

  it("an IPv6 host and an encoded target are carried exactly", () => {
    expect(buildCanonicalRequest({ ...evaluateRequest, host: "[::1]:4000", target: "/api/a%2Fb?x=%7E" }).split("\n").slice(2, 4)).toEqual(["[::1]:4000", "/api/a%2Fb?x=%7E"]);
  });
});

describe("M3-E E1: the Authorization header", () => {
  it("formats the fixed vector and round-trips", () => {
    expect(formatAuthorization(params)).toBe(HEADER);
    expect(parseAuthorization(HEADER)).toEqual({ ok: true, value: params });
    const random: SignatureParameters = { keyId: "fedcba9876543210", timestamp: "1700000000000", nonce: randomBytes(16).toString("base64url"), signature: randomBytes(64).toString("base64url") };
    expect(parseAuthorization(formatAuthorization(random))).toEqual({ ok: true, value: random });
    expect(HEADER.length).toBeLessThan(MAX_AUTHORIZATION_LENGTH);
  });

  it.each([
    ["not a string", 42, "not-a-string"],
    ["missing scheme", HEADER.slice(AUTH_SCHEME.length + 1), "wrong-scheme"],
    ["lower-case scheme", HEADER.replace(AUTH_SCHEME, AUTH_SCHEME.toLowerCase()), "wrong-scheme"],
    ["Bearer scheme", `Bearer ${KEY_ID}`, "wrong-scheme"],
    ["scheme without the space", HEADER.replace(`${AUTH_SCHEME} `, AUTH_SCHEME), "wrong-scheme"],
    ["missing keyId", HEADER.replace(`keyId="${KEY_ID}", `, ""), "missing-parameter"],
    ["missing ts", HEADER.replace(`ts="${TS}", `, ""), "missing-parameter"],
    ["missing nonce", HEADER.replace(`nonce="${NONCE}", `, ""), "missing-parameter"],
    ["missing sig", HEADER.replace(`, sig="${SIG}"`, ""), "missing-parameter"],
    ["duplicate keyId", `${HEADER}, keyId="${KEY_ID}"`, "duplicate-parameter"],
    ["duplicate sig", `${HEADER}, sig="${SIG}"`, "duplicate-parameter"],
    ["unknown parameter", `${HEADER}, alg="ed25519"`, "unknown-parameter"],
    ["a private key parameter", `${HEADER}, privateKey="${randomBytes(32).toString("base64url")}"`, "unknown-parameter"],
    ["parameter name in another case", HEADER.replace("keyId=", "KeyId="), "unknown-parameter"],
    ["unquoted value", HEADER.replace(`ts="${TS}"`, `ts=${TS}`), "malformed"],
    ["single quotes", HEADER.replace(`ts="${TS}"`, `ts='${TS}'`), "malformed"],
    ["extra space after a comma", HEADER.replace(", ts=", ",  ts="), "malformed"],
    ["comma without space", HEADER.replace(", ts=", ",ts="), "malformed"],
    ["trailing comma", `${HEADER}, `, "malformed"],
    ["space around =", HEADER.replace('ts="', 'ts = "'), "malformed"],
    ["parameters in another order", `${AUTH_SCHEME} ts="${TS}", keyId="${KEY_ID}", nonce="${NONCE}", sig="${SIG}"`, "non-canonical"],
    ["trailing space", `${HEADER} `, "malformed"],
  ])("refuses %s", (_label, header, reason) => {
    expect(parseAuthorization(header)).toEqual({ ok: false, reason });
  });

  it.each([
    ["upper-case hex", "0123456789ABCDEF"],
    ["15 digits", "0123456789abcde"],
    ["17 digits", "0123456789abcdef0"],
    ["non-hex", "0123456789abcdeg"],
    ["empty", ""],
  ])("refuses a key id that is %s", (_label, keyId) => {
    expect(parseAuthorization(HEADER.replace(KEY_ID, keyId))).toEqual({ ok: false, reason: "invalid-key-id" });
    expect(reasonOf(() => formatAuthorization({ ...params, keyId }))).toBe("invalid-key-id");
    expect(reasonOf(() => buildCanonicalRequest({ ...evaluateRequest, keyId }))).toBe("invalid-key-id");
  });

  it.each([
    ["12 digits", "179352360012"],
    ["14 digits", "17935236001230"],
    ["a leading zero", "0793523600123"],
    ["a sign", "+793523600123"],
    ["a decimal point", "1793523600.12"],
    ["an exponent", "1.79352360e12"],
    ["seconds instead of milliseconds", "1793523600"],
    ["letters", "17935236001a3"],
    ["empty", ""],
  ])("refuses a timestamp with %s", (_label, ts) => {
    expect(parseAuthorization(HEADER.replace(`ts="${TS}"`, `ts="${ts}"`))).toEqual({ ok: false, reason: "invalid-timestamp" });
    expect(reasonOf(() => buildCanonicalRequest({ ...evaluateRequest, timestamp: ts }))).toBe("invalid-timestamp");
  });

  it.each([
    ["21 characters", NONCE.slice(0, -1)],
    ["23 characters", `${NONCE}A`],
    ["standard base64 characters", "AAECAwQFBgcICQoLDA0O+/"],
    ["padding", "AAECAwQFBgcICQoLDA0ODw=="],
    ["non-canonical trailing bits", "AAECAwQFBgcICQoLDA0ODx"],
    ["a space", "AAECAwQFBgcICQoLD A0Ow"],
    ["empty", ""],
  ])("refuses a nonce with %s", (_label, nonce) => {
    expect(isNonce(nonce)).toBe(false);
    expect(parseAuthorization(HEADER.replace(NONCE, nonce)).ok).toBe(false);
    expect(reasonOf(() => buildCanonicalRequest({ ...evaluateRequest, nonce }))).toBe("invalid-nonce");
  });

  it.each([
    ["85 characters", SIG.slice(0, -1)],
    ["87 characters", `${SIG}A`],
    ["standard base64", Buffer.from([...Array(64).keys()]).toString("base64")],
    ["padding", `${SIG}==`],
    ["non-canonical trailing bits", `${SIG.slice(0, -1)}x`],
    ["a 32-byte private seed", randomBytes(32).toString("base64url")],
    ["a 48-byte PKCS#8 key", randomBytes(48).toString("base64url")],
    ["empty", ""],
  ])("refuses a signature with %s", (_label, sig) => {
    expect(isSignature(sig)).toBe(false);
    expect(parseAuthorization(HEADER.replace(SIG, sig)).ok).toBe(false);
    expect(reasonOf(() => formatAuthorization({ ...params, signature: sig }))).toBe("invalid-signature");
  });

  it("refuses CR, LF, other control and non-ASCII characters anywhere in the header", () => {
    for (const injected of ["\r\n", "\n", "\r", "\t", "\u0000", "é", " "]) {
      expect(parseAuthorization(HEADER.replace(", ts=", `,${injected}ts=`))).toEqual({ ok: false, reason: "invalid-characters" });
      expect(parseAuthorization(`${HEADER}${injected}X-Injected: 1`)).toEqual({ ok: false, reason: "invalid-characters" });
    }
  });

  it(`refuses a header longer than ${MAX_AUTHORIZATION_LENGTH} characters before parsing it`, () => {
    expect(parseAuthorization(`${HEADER}, ${"x".repeat(MAX_AUTHORIZATION_LENGTH)}`)).toEqual({ ok: false, reason: "too-long" });
    expect(parseAuthorization(HEADER.padEnd(MAX_AUTHORIZATION_LENGTH + 1, " "))).toEqual({ ok: false, reason: "too-long" });
  });

  it("errors name the field but never echo the rejected value", () => {
    const secretish = "privateKeyMaterialShouldNeverAppear";
    try {
      formatAuthorization({ ...params, signature: secretish });
    } catch (error) {
      expect((error as Error).message).toBe("Invalid signed-request field (invalid-signature).");
      expect((error as Error).message).not.toContain(secretish);
    }
  });
});

describe("M3-E E1: raw body hashing", () => {
  it("no body, null and zero bytes all hash zero bytes", () => {
    expect([sha256Hex(), sha256Hex(null), sha256Hex(new Uint8Array(0)), sha256Hex(Buffer.alloc(0))]).toEqual(Array(4).fill(EMPTY_BODY_SHA256));
  });

  it("hashes the exact bytes: one byte, whitespace or encoding difference changes the hash", () => {
    const bytes = Buffer.from(BODY, "utf8");
    expect(sha256Hex(new Uint8Array(bytes))).toBe(BODY_SHA256);
    const changed = Buffer.from(bytes);
    changed[changed.length - 2] ^= 1;
    expect(sha256Hex(changed)).not.toBe(BODY_SHA256);
    expect(sha256Hex(Buffer.from(`${BODY}\n`, "utf8"))).not.toBe(BODY_SHA256);
    expect(sha256Hex(Buffer.from(JSON.stringify(JSON.parse(BODY), null, 2), "utf8"))).not.toBe(BODY_SHA256);
    expect(sha256Hex(Buffer.from("café", "utf8"))).not.toBe(sha256Hex(Buffer.from("café", "latin1")));
  });

  it("refuses a string body, so the caller must supply the raw bytes", () => {
    expect(reasonOf(() => sha256Hex(BODY as unknown as Uint8Array))).toBe("invalid-body");
    expect(reasonOf(() => sha256Hex({} as unknown as Uint8Array))).toBe("invalid-body");
  });
});

describe("M3-E E1: canonical fields", () => {
  it.each([
    ["method", { method: "PUT" }],
    ["host", { host: "127.0.0.1:4001" }],
    ["target path", { target: "/api/evaluatE" }],
    ["target query", { target: "/api/evaluate?x=1" }],
    ["timestamp", { timestamp: "1793523600124" }],
    ["nonce", { nonce: "AAECAwQFBgcICQoLDA0OEA" }],
    ["key id", { keyId: "0123456789abcdee" }],
    ["body hash", { bodySha256: EMPTY_BODY_SHA256 }],
  ])("changing the %s changes the canonical request", (_label, change) => {
    expect(buildCanonicalRequest({ ...evaluateRequest, ...change })).not.toBe(buildCanonicalRequest(evaluateRequest));
  });

  it("the target is never normalised: case, trailing slash, percent-encoding and dot segments are signed as sent", () => {
    const targets = ["/api/evaluate", "/api/Evaluate", "/api/evaluate/", "/api/%65valuate", "/api/%2e%2e/api/evaluate", "/api/../api/evaluate", "/api//evaluate", "/api/a%2fb", "/api/a%2Fb"];
    const canonical = targets.map((target) => buildCanonicalRequest({ ...evaluateRequest, target }).split("\n")[3]);
    expect(canonical).toEqual(targets);
  });

  it.each([
    ["LF in the target", { target: "/api/evaluate\nX-Injected: 1" }, "invalid-target"],
    ["CRLF in the target", { target: "/api/evaluate\r\nGET" }, "invalid-target"],
    ["LF in the host", { host: "127.0.0.1\nevil" }, "invalid-host"],
    ["CR in the method", { method: "POST\r" }, "invalid-method"],
    ["LF in the nonce", { nonce: "AAECAwQFBgcICQoLDA0O\nA" }, "invalid-nonce"],
    ["LF in the key id", { keyId: "0123456789abcde\n" }, "invalid-key-id"],
    ["LF in the body hash", { bodySha256: `${BODY_SHA256.slice(0, 63)}\n` }, "invalid-body-hash"],
  ])("refuses %s (no line can be added to the canonical request)", (_label, change, reason) => {
    expect(reasonOf(() => buildCanonicalRequest({ ...evaluateRequest, ...change }))).toBe(reason);
  });

  it.each([
    ["lower-case method", { method: "post" }, "invalid-method"],
    ["method with a digit", { method: "P0ST" }, "invalid-method"],
    ["empty method", { method: "" }, "invalid-method"],
    ["upper-case host (not canonicalised)", { host: "LOCALHOST:4000" }, "invalid-host"],
    ["host with a path", { host: "localhost/api" }, "invalid-host"],
    ["host with user info", { host: "user@localhost" }, "invalid-host"],
    ["host with port 0", { host: "localhost:0" }, "invalid-host"],
    ["host with port 65536", { host: "localhost:65536" }, "invalid-host"],
    ["absolute-form target", { target: "http://127.0.0.1:4000/api/evaluate" }, "invalid-target"],
    ["target with a space", { target: "/api/eval uate" }, "invalid-target"],
    ["target with a fragment", { target: "/api/evaluate#x" }, "invalid-target"],
    ["target with a backslash", { target: "/api\\evaluate" }, "invalid-target"],
    ["target with raw non-ASCII", { target: "/api/café" }, "invalid-target"],
    ["target with a bad escape", { target: "/api/%zz" }, "invalid-target"],
    ["target that is too long", { target: `/${"a".repeat(MAX_TARGET_LENGTH)}` }, "invalid-target"],
    ["upper-case body hash", { bodySha256: BODY_SHA256.toUpperCase() }, "invalid-body-hash"],
    ["short body hash", { bodySha256: BODY_SHA256.slice(1) }, "invalid-body-hash"],
  ])("refuses a %s", (_label, change, reason) => {
    expect(reasonOf(() => buildCanonicalRequest({ ...evaluateRequest, ...change }))).toBe(reason);
  });

  it("accepts the longest allowed target and percent-encoded text", () => {
    expect(isTarget(`/${"a".repeat(MAX_TARGET_LENGTH - 1)}`)).toBe(true);
    expect(isTarget("/api/caf%C3%A9?q=a%20b&r=%0D%0A")).toBe(true); // escaped CRLF is ordinary text, still one line
  });

  it("canonicalHost lower-cases a Host header and refuses anything that is not a host", () => {
    expect(canonicalHost("LOCALHOST:4000")).toBe("localhost:4000");
    expect(canonicalHost("127.0.0.1:4000")).toBe("127.0.0.1:4000");
    expect(canonicalHost("[::1]:4000")).toBe("[::1]:4000");
    expect(canonicalHost("[::1]")).toBe("[::1]");
    for (const bad of [undefined, "", " localhost", "localhost ", "local host", "localhost:", "localhost:99999", "-bad.example", "a@b", "localhost\r\n", "lócalhost", "[::1", 7]) {
      expect(canonicalHost(bad), String(bad)).toBeNull();
    }
    expect(isCanonicalHost("localhost:04000")).toBe(false);
  });
});

describe("M3-E E1: Ed25519 over the canonical bytes (runtime keys, never stored)", () => {
  it("a signature made with the canonical bytes verifies after a header round-trip, and any tampering fails", () => {
    const { privateKey, publicKey } = generateKeyPairSync("ed25519");
    const request: CanonicalRequestInput = { ...evaluateRequest, nonce: randomBytes(16).toString("base64url") };
    const signature = sign(null, canonicalRequestBytes(request), privateKey).toString("base64url");
    const header = formatAuthorization({ keyId: request.keyId, timestamp: request.timestamp, nonce: request.nonce, signature });
    const parsed = parseAuthorization(header);
    expect(parsed.ok).toBe(true);
    if (!parsed.ok) return;
    const rebuilt = { ...request, keyId: parsed.value.keyId, timestamp: parsed.value.timestamp, nonce: parsed.value.nonce };
    const sig = Buffer.from(parsed.value.signature, "base64url");
    expect(sig).toHaveLength(64);
    expect(verify(null, canonicalRequestBytes(rebuilt), publicKey, sig)).toBe(true);
    for (const change of [{ method: "PUT" }, { host: "localhost:4000" }, { target: "/api/evaluate?" }, { timestamp: "1793523600124" }, { keyId: "0123456789abcdee" }, { bodySha256: EMPTY_BODY_SHA256 }]) {
      expect(verify(null, canonicalRequestBytes({ ...rebuilt, ...change }), publicKey, sig), JSON.stringify(change)).toBe(false);
    }
    expect(verify(null, canonicalRequestBytes(rebuilt), generateKeyPairSync("ed25519").publicKey, sig)).toBe(false);
  });
});

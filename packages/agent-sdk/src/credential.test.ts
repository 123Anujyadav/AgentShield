import { generateKeyPairSync, randomBytes, verify } from "node:crypto";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { inspect } from "node:util";
import { afterEach, describe, expect, it } from "vitest";
import { AgentCredential, MAX_CREDENTIAL_FILE_BYTES } from "./credential.js";
import { CredentialError } from "./errors.js";
import { testKey } from "./test-fixtures.js";

/** M3-E E5: loading and holding an agent credential. Deterministic test keys; temporary files only. */

const key = testKey("credential-tests");
const INVALID = "The agent credential is not a valid AgentShield Ed25519 credential (expected asag2_<keyId>.<key>).";

let dir: string | null = null;
afterEach(() => {
  if (dir) rmSync(dir, { recursive: true, force: true });
  dir = null;
});
const tempFile = (content: string | Buffer) => {
  dir = mkdtempSync(join(tmpdir(), "agentshield-sdk-test-"));
  const path = join(dir, "agent.key");
  writeFileSync(path, content);
  return path;
};

describe("M3-E E5: parsing credentials", () => {
  it("accepts an asag2_ Ed25519 credential and signs with it", () => {
    const credential = AgentCredential.fromString(key.credential);
    expect(credential.keyId).toBe(key.keyId);
    const message = Buffer.from("canonical request");
    expect(verify(null, message, key.publicKey, credential.sign(message))).toBe(true);
  });

  it.each([
    ["empty", ""],
    ["not a string", 42],
    ["undefined", undefined],
    ["a bearer credential", `asag_${key.keyId}.${"A".repeat(43)}`],
    ["the wrong prefix", key.credential.replace("asag2_", "asag3_")],
    ["an upper-case key id", key.credential.replace(key.keyId, key.keyId.toUpperCase())],
    ["a short key id", key.credential.replace(key.keyId, key.keyId.slice(1))],
    ["a missing separator", key.credential.replace(".", "")],
    ["a truncated key", key.credential.slice(0, -1)],
    ["an extra character", `${key.credential}A`],
    ["leading whitespace", ` ${key.credential.slice(1)}`],
    ["a trailing newline", `${key.credential}\n`],
    ["standard base64 characters", key.credential.slice(0, -2) + "+/"],
    ["an X25519 key", `asag2_${key.keyId}.${(generateKeyPairSync("x25519").privateKey.export({ format: "der", type: "pkcs8" }) as Buffer).toString("base64url")}`],
    ["48 random bytes", `asag2_${key.keyId}.${randomBytes(48).toString("base64url")}`],
  ])("refuses %s with a fixed message that never echoes the input", (_label, value) => {
    let error: unknown;
    try {
      AgentCredential.fromString(value);
    } catch (e) {
      error = e;
    }
    expect(error).toBeInstanceOf(CredentialError);
    expect((error as Error).message).toBe(INVALID);
    expect((error as Error).message).not.toContain(key.secretPart);
    expect((error as CredentialError).code).toBe("credential");
  });
});

describe("M3-E E5: credential sources", () => {
  it("reads a credential file with at most one trailing newline (as agent-credential create --out writes it)", () => {
    expect(AgentCredential.fromFile(tempFile(`${key.credential}\n`)).keyId).toBe(key.keyId);
    expect(AgentCredential.fromFile(tempFile(`${key.credential}\r\n`)).keyId).toBe(key.keyId);
    expect(AgentCredential.fromFile(tempFile(key.credential)).keyId).toBe(key.keyId);
    expect(() => AgentCredential.fromFile(tempFile(`${key.credential}\n\n`))).toThrowError(INVALID);
    expect(() => AgentCredential.fromFile(tempFile(` ${key.credential}`))).toThrowError(CredentialError);
  });

  it("refuses a missing, unreadable or oversized file without echoing its content", () => {
    expect(() => AgentCredential.fromFile(join(tmpdir(), "agentshield-sdk-no-such-file.key"))).toThrowError("The agent credential file cannot be read.");
    expect(() => AgentCredential.fromFile(tempFile(`${key.credential}\n`.repeat(20)))).toThrowError("The agent credential file is too large to be a credential.");
    expect(MAX_CREDENTIAL_FILE_BYTES).toBe(1024);
    expect(() => AgentCredential.fromFile(dir!)).toThrowError(CredentialError);
  });

  it("reads an explicitly named environment variable, and only that", () => {
    expect(AgentCredential.fromEnv("MY_AGENT_KEY", { MY_AGENT_KEY: key.credential }).keyId).toBe(key.keyId);
    expect(() => AgentCredential.fromEnv("MY_AGENT_KEY", {})).toThrowError("The agent credential environment variable is not set.");
    expect(() => AgentCredential.fromEnv("MY_AGENT_KEY", { MY_AGENT_KEY: "" })).toThrowError(CredentialError);
    expect(() => AgentCredential.fromEnv("", { "": key.credential })).toThrowError("An environment variable name is required.");
    expect(() => AgentCredential.fromEnv("MY_AGENT_KEY", { MY_AGENT_KEY: "garbage" })).toThrowError(INVALID);
  });
});

describe("M3-E E5: the private key never leaves the credential object", () => {
  it("is absent from JSON, string conversion, inspect, keys, spreading and structured cloning", () => {
    const credential = AgentCredential.fromString(key.credential);
    const views = [
      JSON.stringify(credential),
      String(credential),
      `${credential}`,
      inspect(credential),
      inspect(credential, { showHidden: true, depth: 10 }),
      JSON.stringify(Object.keys(credential)),
      JSON.stringify(Object.getOwnPropertyNames(credential)),
      JSON.stringify({ ...credential }),
      JSON.stringify(structuredClone(credential)),
    ];
    for (const view of views) {
      expect(view).not.toContain(key.secretPart);
      expect(view).not.toContain(key.secretPart.slice(-43));
    }
    expect(JSON.parse(JSON.stringify(credential))).toEqual({ keyId: key.keyId });
    expect(inspect(credential)).toBe(`AgentCredential { keyId: '${key.keyId}' }`);
  });
});

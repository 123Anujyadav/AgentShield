import { createPrivateKey, sign as ed25519Sign, type KeyObject } from "node:crypto";
import { readFileSync, statSync } from "node:fs";
import { inspect } from "node:util";
import { isKeyId } from "@agentshield/agent-protocol";
import { CredentialError } from "./errors.js";

/**
 * An agent's Ed25519 signing credential (M3-E E5), as issued by
 * `npm run agent-credential -- create`:
 *
 *   asag2_<keyId>.<key>
 *
 * `<keyId>` is the public 16-hex-digit key id; `<key>` is the PKCS#8 DER encoding of the
 * Ed25519 private key (48 bytes, RFC 8410) in unpadded base64url. The private key stays
 * inside this object: it is only used to sign, is never sent to AgentShield, and does not
 * appear in JSON, string conversion, `util.inspect` or error messages.
 */

const CREDENTIAL = /^asag2_([0-9a-f]{16})\.([A-Za-z0-9_-]{64})$/;
const ED25519_PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");
/** A credential file holds one 87-character line; anything much larger is not one. */
export const MAX_CREDENTIAL_FILE_BYTES = 1024;

const INVALID = "The agent credential is not a valid AgentShield Ed25519 credential (expected asag2_<keyId>.<key>).";

export class AgentCredential {
  /** The credential's public key id (safe to log). */
  readonly keyId: string;
  readonly #privateKey: KeyObject;

  private constructor(keyId: string, privateKey: KeyObject) {
    this.keyId = keyId;
    this.#privateKey = privateKey;
  }

  /** Parses a credential given as text. The text must be exactly the credential. */
  static fromString(value: unknown): AgentCredential {
    if (typeof value !== "string" || value.length !== 87) throw new CredentialError(INVALID);
    const match = CREDENTIAL.exec(value);
    if (!match || !isKeyId(match[1])) throw new CredentialError(INVALID);
    const der = Buffer.from(match[2]!, "base64url");
    if (der.length !== 48 || der.toString("base64url") !== match[2] || !der.subarray(0, ED25519_PKCS8_PREFIX.length).equals(ED25519_PKCS8_PREFIX)) {
      throw new CredentialError(INVALID);
    }
    let privateKey: KeyObject;
    try {
      privateKey = createPrivateKey({ key: der, format: "der", type: "pkcs8" });
    } catch {
      throw new CredentialError(INVALID);
    }
    if (privateKey.asymmetricKeyType !== "ed25519") throw new CredentialError(INVALID);
    return new AgentCredential(match[1]!, privateKey);
  }

  /**
   * Reads a credential file, such as one written by `agent-credential create --out`. The
   * file holds the credential and at most one trailing newline. Keep it readable only by
   * the agent's account.
   */
  static fromFile(path: string): AgentCredential {
    let text: string;
    try {
      if (statSync(path).size > MAX_CREDENTIAL_FILE_BYTES) throw new CredentialError("The agent credential file is too large to be a credential.");
      text = readFileSync(path, "utf8");
    } catch (error) {
      if (error instanceof CredentialError) throw error;
      throw new CredentialError("The agent credential file cannot be read.");
    }
    return AgentCredential.fromString(text.replace(/\r?\n$/, ""));
  }

  /** Reads a credential from the named environment variable (no default name: the source is always explicit). */
  static fromEnv(name: string, env: NodeJS.ProcessEnv = process.env): AgentCredential {
    if (typeof name !== "string" || name.length === 0) throw new CredentialError("An environment variable name is required.");
    const value = env[name];
    if (value === undefined || value === "") throw new CredentialError("The agent credential environment variable is not set.");
    return AgentCredential.fromString(value);
  }

  /** Signs bytes (a canonical request) with the private key. The key itself never leaves this object. */
  sign(message: Uint8Array): Buffer {
    return ed25519Sign(null, message, this.#privateKey);
  }

  toJSON(): { keyId: string } {
    return { keyId: this.keyId };
  }

  toString(): string {
    return `AgentCredential(${this.keyId})`;
  }

  [inspect.custom](): string {
    return `AgentCredential { keyId: '${this.keyId}' }`;
  }
}

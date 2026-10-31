import { createHash } from "node:crypto";
import { existsSync, mkdtempSync, readdirSync, readFileSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  createCredentialStore,
  createReloadingCredentialStore,
  credentialFilePath,
  credentialHash,
  CredentialConfigError,
  generateCredential,
  issueCredential,
  MAX_ACTIVE_PER_AGENT,
  MAX_CREDENTIAL_FILE_BYTES,
  parseCredential,
  parseCredentialDocument,
  readCredentialFile,
  serializeCredentialDocument,
  type CredentialRecord,
  type CredentialReloadEvent,
} from "./credentials.js";
import { isRestrictedToCurrentUser, writeRestrictedFileAtomically } from "./file-security.js";

/** M3-D D1: agent credentials. Temporary files only; no real credential store is read or written. */

const NOW = Date.parse("2026-11-01T09:00:00.000Z");
const DAY = 24 * 60 * 60 * 1000;
const issue = (agentId: string, extra: { days?: number; now?: number; taken?: Set<string> } = {}) =>
  issueCredential({ agentId, now: extra.now ?? NOW, takenKeyIds: extra.taken ?? new Set(), days: extra.days });
const doc = (credentials: unknown[], extra: Record<string, unknown> = {}) => JSON.stringify({ schemaVersion: 1, credentials, ...extra });

describe("M3-D: credential format and generation", () => {
  it("a generated credential is asag_<16 hex>.<43 base64url> with a 256-bit secret, and key ids are unique", () => {
    const seen = new Set<string>();
    for (let i = 0; i < 300; i += 1) {
      const { credential, keyId, sha256 } = generateCredential(seen);
      expect(credential).toMatch(/^asag_[0-9a-f]{16}\.[A-Za-z0-9_-]{43}$/);
      expect(Buffer.from(parseCredential(credential)!.secret, "base64url")).toHaveLength(32);
      expect(seen.has(keyId)).toBe(false);
      seen.add(keyId);
      expect(sha256).not.toContain(parseCredential(credential)!.secret);
    }
  });

  it("a taken key id is never reused", () => {
    const taken = new Set<string>();
    for (let i = 0; i < 50; i += 1) taken.add(generateCredential(taken).keyId);
    expect(taken.size).toBe(50);
  });

  it("only the exact format parses", () => {
    const { credential } = generateCredential(new Set());
    expect(parseCredential(credential)).not.toBeNull();
    for (const bad of [
      credential.slice(0, -1),
      `${credential}A`,
      credential.replace("asag_", "ASAG_"),
      credential.replace("asag_", "asak_"),
      credential.replace(".", "_"),
      credential.replace(/^asag_([0-9a-f])/, "asag_G"),
      credential.replace(/^asag_[0-9a-f]{16}/, (m) => m.toUpperCase().replace("ASAG_", "asag_")) === credential ? "asag_x" : credential.replace(/^asag_[0-9a-f]{16}/, (m) => m.toUpperCase().replace("ASAG_", "asag_")),
      ` ${credential}`,
      credential.replace(/.$/, "="),
      "",
    ]) {
      expect(parseCredential(bad), bad.slice(0, 12)).toBeNull();
    }
  });
});

describe("M3-D: hashing", () => {
  it("is a stable domain-separated SHA-256 bound to the key id", () => {
    const keyId = "0123456789abcdef";
    const secret = "A".repeat(43);
    expect(credentialHash(keyId, secret)).toBe(credentialHash(keyId, secret));
    expect(credentialHash(keyId, secret)).toMatch(/^[0-9a-f]{64}$/);
    expect(credentialHash(keyId, secret)).not.toBe(createHash("sha256").update(secret).digest("hex"));
    expect(credentialHash(keyId, secret)).not.toBe(credentialHash("fedcba9876543210", secret));
  });

  it("swapping two records' hashes makes both credentials fail", () => {
    const a = issue("writer");
    const b = issue("reader", { taken: new Set([a.record.keyId]) });
    const swapped = createCredentialStore([{ ...a.record, sha256: b.record.sha256 }, { ...b.record, sha256: a.record.sha256 }], () => NOW);
    expect(swapped.verify(a.credential)).toEqual({ ok: false, reason: "wrong-secret" });
    expect(swapped.verify(b.credential)).toEqual({ ok: false, reason: "wrong-secret" });
  });
});

describe("M3-D: verification", () => {
  it("returns the record's agent for a valid credential and a reason for each failure", () => {
    const a = issue("writer");
    const store = createCredentialStore([a.record], () => NOW);
    expect(store.verify(a.credential)).toEqual({ ok: true, agentId: "writer", keyId: a.record.keyId });
    const { secret } = parseCredential(a.credential)!;
    const otherSecret = secret.startsWith("A") ? `B${secret.slice(1)}` : `A${secret.slice(1)}`;
    expect(store.verify(`asag_${a.record.keyId}.${otherSecret}`)).toEqual({ ok: false, reason: "wrong-secret" });
    expect(store.verify(generateCredential(new Set()).credential)).toEqual({ ok: false, reason: "unknown-key" });
    expect(store.verify("asag_nope")).toEqual({ ok: false, reason: "malformed" });
    expect(store.verify(undefined as unknown as string)).toEqual({ ok: false, reason: "malformed" });
  });

  it("revoked and expired credentials fail, and expiry is evaluated at the time of use", () => {
    let now = NOW;
    const a = issue("writer", { days: 1 });
    const r = issue("writer", { taken: new Set([a.record.keyId]) });
    const store = createCredentialStore([a.record, { ...r.record, revokedAt: new Date(NOW).toISOString() }], () => now);
    expect(store.verify(a.credential).ok).toBe(true);
    expect(store.verify(r.credential)).toEqual({ ok: false, reason: "revoked" });
    now = NOW + DAY;
    expect(store.verify(a.credential)).toEqual({ ok: false, reason: "expired" });
    expect([store.status(a.record.keyId), store.status(r.record.keyId), store.status("ffffffffffffffff")]).toEqual(["expired", "revoked", "unknown"]);
  });

  it("issues credentials for 90 days by default and refuses more than 365", () => {
    const { record } = issue("writer");
    expect(Date.parse(record.expiresAt) - Date.parse(record.createdAt)).toBe(90 * DAY);
    expect(Date.parse(issue("writer", { days: 365 }).record.expiresAt) - NOW).toBe(365 * DAY);
    for (const days of [0, 366, 1.5, -1]) expect(() => issue("writer", { days })).toThrowError(CredentialConfigError);
    expect(() => issue("Writer")).toThrowError(/agentId/);
  });
});

describe("M3-D: credential stores are validated strictly", () => {
  const valid = issue("writer").record;

  it("round-trips through the document format, which holds hashes only", () => {
    const text = serializeCredentialDocument([valid]);
    expect(parseCredentialDocument(text, NOW)).toEqual([valid]);
    expect(Object.keys(JSON.parse(text).credentials[0]).sort()).toEqual(["agentId", "createdAt", "expiresAt", "keyId", "label", "revokedAt", "sha256"]);
  });

  it.each([
    ["not JSON", "{", /not valid JSON/],
    ["an array", "[]", /must be a JSON object/],
    ["an unknown top-level field", doc([valid], { extra: 1 }), /^The credential store has an unknown top-level field\.$/],
    ["another schema version", JSON.stringify({ schemaVersion: 2, credentials: [] }), /schemaVersion must be 1/],
    ["credentials not an array", JSON.stringify({ schemaVersion: 1, credentials: {} }), /must be an array/],
    ["an unknown record field", doc([{ ...valid, secret: "x" }]), /^credentials\[0\] has an unknown field\.$/],
    ["a missing field", doc([{ ...valid, revokedAt: undefined }]), /revokedAt is required/],
    ["a bad key id", doc([{ ...valid, keyId: "0123456789ABCDEF" }]), /keyId/],
    ["a short key id", doc([{ ...valid, keyId: "0123" }]), /keyId/],
    ["a bad agent id", doc([{ ...valid, agentId: "../x" }]), /agentId/],
    ["a bad hash", doc([{ ...valid, sha256: "abc" }]), /sha256/],
    ["an upper-case hash", doc([{ ...valid, sha256: valid.sha256.toUpperCase() }]), /sha256/],
    ["an empty label", doc([{ ...valid, label: "" }]), /label/],
    ["a long label", doc([{ ...valid, label: "l".repeat(101) }]), /label/],
    ["a label with a control character", doc([{ ...valid, label: "a\nb" }]), /label/],
    ["a non-ISO date", doc([{ ...valid, createdAt: "2026-11-01" }]), /createdAt/],
    ["an impossible date", doc([{ ...valid, expiresAt: "2026-02-30T00:00:00.000Z" }]), /expiresAt/],
    ["expiry before creation", doc([{ ...valid, expiresAt: valid.createdAt }]), /after createdAt/],
    ["expiry beyond 365 days", doc([{ ...valid, expiresAt: new Date(NOW + 366 * DAY).toISOString() }]), /at most 365 days/],
    ["a bad revocation date", doc([{ ...valid, revokedAt: "yesterday" }]), /revokedAt/],
    ["a duplicate key id", doc([valid, { ...valid, sha256: "0".repeat(64) }]), /keyId duplicates/],
    ["a duplicate hash", doc([valid, { ...valid, keyId: "ffffffffffffffff" }]), /sha256 duplicates/],
  ])("refuses %s", (_label, text, message) => {
    expect(() => parseCredentialDocument(text, NOW)).toThrowError(message);
  });

  it(`allows at most ${MAX_ACTIVE_PER_AGENT} active credentials per agent; revoked and expired ones do not count`, () => {
    const taken = new Set<string>();
    const make = (agentId: string, change: Partial<CredentialRecord> = {}) => {
      const { record } = issue(agentId, { taken });
      taken.add(record.keyId);
      return { ...record, ...change };
    };
    const four = [make("writer"), make("writer"), make("writer"), make("writer")];
    const revoked = make("writer", { revokedAt: new Date(NOW).toISOString() });
    const expired = make("writer", { createdAt: new Date(NOW - 10 * DAY).toISOString(), expiresAt: new Date(NOW - DAY).toISOString() });
    expect(parseCredentialDocument(doc([...four, revoked, expired, make("reader")]), NOW)).toHaveLength(7);
    expect(() => parseCredentialDocument(doc([...four, make("writer")]), NOW)).toThrowError(/more than 4 active/);
  });

  it("M3-D audit L4: an unknown field's name is never echoed, at the top level or in a record", () => {
    const name = "fakeSecretFieldName_0123456789";
    for (const text of [doc([valid], { [name]: 1 }), doc([{ ...valid, [name]: 1 }])]) {
      let message = "";
      try {
        parseCredentialDocument(text, NOW);
      } catch (error) {
        expect(error).toBeInstanceOf(CredentialConfigError);
        message = (error as Error).message;
      }
      expect(message).toMatch(/unknown (top-level )?field\.$/);
      expect(message).not.toContain("fakeSecretFieldName");
    }
  });

  it("refuses an oversized document and never echoes file content in errors", () => {
    expect(() => parseCredentialDocument(doc([]).padEnd(MAX_CREDENTIAL_FILE_BYTES + 1, " "), NOW)).toThrowError(/larger than/);
    try {
      parseCredentialDocument(doc([{ ...valid, label: "fakeSecretLabelValue\u0001" }]), NOW);
    } catch (error) {
      expect((error as Error).message).not.toContain("fakeSecretLabelValue");
    }
  });

  it("uses AGENT_CREDENTIAL_FILE, or the per-user AgentShield folder", () => {
    expect(credentialFilePath({ AGENT_CREDENTIAL_FILE: "  C:\\x\\creds.json " })).toBe("C:\\x\\creds.json");
    expect(credentialFilePath({ LOCALAPPDATA: "C:\\Users\\u\\AppData\\Local" })).toBe(join("C:\\Users\\u\\AppData\\Local", "AgentShield", "agent-credentials.json"));
  });
});

describe("M3-D: credential files (temporary directory)", () => {
  let dir: string | null = null;
  afterEach(() => {
    if (dir) rmSync(dir, { recursive: true, force: true });
    dir = null;
  });
  const tempPath = () => {
    dir = mkdtempSync(join(tmpdir(), "agentshield-credential-test-"));
    return join(dir, "agent-credentials.json");
  };

  it("a missing file is an empty store; an unreadable, oversized or invalid one is refused", () => {
    const path = tempPath();
    expect(readCredentialFile(path, NOW)).toEqual([]);
    writeFileSync(path, "x".repeat(MAX_CREDENTIAL_FILE_BYTES + 1));
    expect(() => readCredentialFile(path, NOW)).toThrowError(/larger than/);
    writeFileSync(path, "{");
    expect(() => readCredentialFile(path, NOW)).toThrowError(/not valid JSON/);
    expect(() => readCredentialFile(dir!, NOW)).toThrowError(CredentialConfigError);
  });

  it("atomic writes leave no temporary file and restrict the file to the current user", () => {
    const path = tempPath();
    writeRestrictedFileAtomically(path, serializeCredentialDocument([issue("writer").record]), { overwrite: true });
    writeRestrictedFileAtomically(path, serializeCredentialDocument([]), { overwrite: true });
    expect(readFileSync(path, "utf8")).toBe(serializeCredentialDocument([]));
    expect(readdirSync(dir!)).toEqual(["agent-credentials.json"]);
    expect(isRestrictedToCurrentUser(path)).toBe(true);
  });

  it("a no-overwrite write never replaces an existing file", () => {
    const path = tempPath();
    writeFileSync(path, "original");
    expect(() => writeRestrictedFileAtomically(path, "replacement", { overwrite: false })).toThrowError(/already exists/);
    expect(readFileSync(path, "utf8")).toBe("original");
    expect(readdirSync(dir!)).toEqual(["agent-credentials.json"]);
  });

  describe("hot reload (U1)", () => {
    function setup(initial: CredentialRecord[]) {
      const path = tempPath();
      writeRestrictedFileAtomically(path, serializeCredentialDocument(initial), { overwrite: true });
      let now = NOW;
      const events: CredentialReloadEvent[] = [];
      const store = createReloadingCredentialStore(path, { now: () => now, onEvent: (e) => events.push(e), hasPolicy: (id) => id !== "orphan" });
      return { path, store, events, advance: (ms: number) => (now += ms), write: (records: CredentialRecord[]) => writeRestrictedFileAtomically(path, serializeCredentialDocument(records), { overwrite: true }) };
    }

    it("an invalid initial file fails start-up", () => {
      const path = tempPath();
      writeFileSync(path, doc([{ keyId: "bad" }]));
      expect(() => createReloadingCredentialStore(path)).toThrowError(CredentialConfigError);
    });

    it("a revocation written to the file takes effect within the 2-second interval", () => {
      const a = issue("writer");
      const t = setup([a.record]);
      expect(t.store.verify(a.credential).ok).toBe(true);
      t.write([{ ...a.record, revokedAt: new Date(NOW).toISOString() }]);
      t.advance(1999);
      expect(t.store.verify(a.credential).ok).toBe(true); // still inside the interval
      t.advance(1);
      expect(t.store.verify(a.credential)).toEqual({ ok: false, reason: "revoked" });
      expect(t.events).toContainEqual({ kind: "reloaded", count: 1 });
    });

    it("an atomically replaced file (rename over the old one) is detected", () => {
      const a = issue("writer");
      const t = setup([a.record]);
      const b = issue("writer", { taken: new Set([a.record.keyId]) });
      const staged = `${t.path}.staged`;
      writeFileSync(staged, serializeCredentialDocument([b.record]));
      renameSync(staged, t.path);
      t.advance(2000);
      expect([t.store.verify(a.credential).ok, t.store.verify(b.credential).ok]).toEqual([false, true]);
    });

    it("an invalid changed file rejects every agent credential, without falling back, until it is fixed", () => {
      const a = issue("writer");
      const t = setup([a.record]);
      writeFileSync(t.path, "{ not json");
      t.advance(2000);
      expect(t.store.verify(a.credential)).toEqual({ ok: false, reason: "store-unavailable" });
      expect([t.store.state, t.store.status(a.record.keyId)]).toEqual(["invalid", "unavailable"]);
      expect(t.events.at(-1)).toEqual({ kind: "invalid", reason: "The credential store is not valid JSON." });
      t.advance(2000);
      expect(t.store.verify(a.credential).ok).toBe(false); // still invalid: re-read, still refused
      t.write([a.record]);
      t.advance(2000);
      expect([t.store.verify(a.credential).ok, t.store.state]).toEqual([true, "ok"]);
    });

    it("a deleted file means no credentials; a file created later is picked up", () => {
      const a = issue("writer");
      const t = setup([a.record]);
      rmSync(t.path);
      t.advance(2000);
      expect(t.store.verify(a.credential)).toEqual({ ok: false, reason: "unknown-key" });
      t.write([a.record]);
      t.advance(2000);
      expect(t.store.verify(a.credential).ok).toBe(true);
    });

    it("U8: a credential for an agent without a policy loads, with a warning", () => {
      const orphan = issue("orphan");
      const t = setup([orphan.record]);
      expect(t.store.verify(orphan.credential)).toEqual({ ok: true, agentId: "orphan", keyId: orphan.record.keyId });
      expect(t.events).toEqual([{ kind: "no-policy", agentId: "orphan", keyId: orphan.record.keyId }]);
      expect(existsSync(t.path)).toBe(true);
    });
  });
});

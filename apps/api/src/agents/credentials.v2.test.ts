import { generateKeyPairSync, randomBytes, sign, verify } from "node:crypto";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  bearerAllowedFromEnv,
  createCredentialStore,
  createReloadingCredentialStore,
  CredentialConfigError,
  ed25519PublicKey,
  emptyCredentialStore,
  issueCredential,
  issueEd25519Credential,
  parseCredentialDocument,
  parseSigningCredential,
  serializeCredentialDocument,
  type CredentialRecord,
  type CredentialReloadEvent,
} from "./credentials.js";
import { writeRestrictedFileAtomically } from "./file-security.js";

/** M3-E E2: credential store schema v2, Ed25519 credentials and the bearer switch. Runtime keys only; temporary files only. */

const NOW = Date.parse("2026-11-01T09:00:00.000Z");
const DAY = 24 * 60 * 60 * 1000;
const taken = new Set<string>();
const ed = (agentId = "writer", extra: { days?: number; now?: number } = {}) => {
  const issued = issueEd25519Credential({ agentId, now: extra.now ?? NOW, days: extra.days, takenKeyIds: taken });
  taken.add(issued.record.keyId);
  return issued;
};
const bearer = (agentId = "writer") => {
  const issued = issueCredential({ agentId, now: NOW, takenKeyIds: taken });
  taken.add(issued.record.keyId);
  return issued;
};
const doc = (version: number, credentials: unknown[]) => JSON.stringify({ schemaVersion: version, credentials });
const message = Buffer.from("AGENTSHIELD-SIG-V1\nPOST\n127.0.0.1:4000\n/api/evaluate");

describe("M3-E E2: schema v1 stores keep their meaning", () => {
  it("a v1 record (no scheme field) is read as bearer with every field unchanged, never as Ed25519", () => {
    const issued = bearer();
    const { scheme: _scheme, ...v1 } = issued.record;
    const [record] = parseCredentialDocument(doc(1, [v1]), NOW);
    expect(record).toEqual({ ...v1, scheme: "bearer" });
    expect(createCredentialStore([record!], { now: () => NOW, bearerAllowed: true }).verify(issued.credential).ok).toBe(true);
    expect(createCredentialStore([record!], { now: () => NOW }).publicKeyFor(issued.record.keyId)).toEqual({ ok: false, reason: "scheme-mismatch" });
  });

  it("rewriting a v1 store produces schema 2 with the same bearer records (hash unchanged)", () => {
    const { scheme: _scheme, ...v1 } = bearer().record;
    const written = JSON.parse(serializeCredentialDocument(parseCredentialDocument(doc(1, [v1]), NOW)));
    expect(written.schemaVersion).toBe(2);
    expect(written.credentials[0]).toEqual({ scheme: "bearer", ...v1 });
  });

  it.each([
    ["a scheme field", (v1: Record<string, unknown>) => ({ ...v1, scheme: "bearer" })],
    ["a public key", (v1: Record<string, unknown>) => ({ ...v1, publicKey: ed().record.publicKey })],
    ["no hash", ({ sha256: _h, ...rest }: Record<string, unknown>) => rest],
  ])("a v1 record with %s is refused", (_label, change) => {
    const { scheme: _scheme, ...v1 } = bearer().record;
    expect(() => parseCredentialDocument(doc(1, [change(v1)]), NOW)).toThrowError(CredentialConfigError);
  });
});

describe("M3-E E2: schema v2 validation", () => {
  it("accepts a mixed store of both schemes and round-trips it", () => {
    const records = [ed().record, bearer("reader").record];
    expect(parseCredentialDocument(serializeCredentialDocument(records), NOW)).toEqual(records);
  });

  it.each([
    ["no scheme", (r: Record<string, unknown>) => ({ ...r, scheme: undefined }), /scheme must be "bearer" or "ed25519"/],
    ["an unknown scheme", (r: Record<string, unknown>) => ({ ...r, scheme: "rsa" }), /scheme must be/],
    ["a scheme in another case", (r: Record<string, unknown>) => ({ ...r, scheme: "Ed25519" }), /scheme must be/],
    ["a hash on an Ed25519 record", (r: Record<string, unknown>) => ({ ...r, sha256: "0".repeat(64) }), /^credentials\[0\] has an unknown field\.$/],
    ["a private key field", (r: Record<string, unknown>) => ({ ...r, privateKey: "x" }), /^credentials\[0\] has an unknown field\.$/],
    ["no public key", ({ publicKey: _p, ...rest }: Record<string, unknown>) => rest, /publicKey is required/],
    ["a public key that is too short", (r: Record<string, unknown>) => ({ ...r, publicKey: randomBytes(31).toString("base64url") }), /publicKey must be/],
    ["a public key that is too long", (r: Record<string, unknown>) => ({ ...r, publicKey: randomBytes(33).toString("base64url") }), /publicKey must be/],
    ["a padded public key", (r: Record<string, unknown>) => ({ ...r, publicKey: `${String(r.publicKey)}=` }), /publicKey must be/],
    ["a standard-base64 public key", (r: Record<string, unknown>) => ({ ...r, publicKey: Buffer.from(String(r.publicKey), "base64url").toString("base64").replace(/=+$/, "") + "+" }), /publicKey must be/],
    ["a non-canonical public key", (r: Record<string, unknown>) => ({ ...r, publicKey: `${String(r.publicKey).slice(0, 42)}${String(r.publicKey).endsWith("B") ? "C" : "B"}` }), /publicKey must be|duplicates/],
    ["a hex public key", (r: Record<string, unknown>) => ({ ...r, publicKey: randomBytes(32).toString("hex") }), /publicKey must be/],
    ["a PKCS#8 private key as the public key", (r: Record<string, unknown>) => ({ ...r, publicKey: (generateKeyPairSync("ed25519").privateKey.export({ format: "der", type: "pkcs8" }) as Buffer).toString("base64url") }), /publicKey must be/],
    ["a non-string public key", (r: Record<string, unknown>) => ({ ...r, publicKey: 42 }), /publicKey must be/],
  ])("refuses an Ed25519 record with %s", (_label, change, message) => {
    expect(() => parseCredentialDocument(doc(2, [change({ ...ed().record })]), NOW)).toThrowError(message);
  });

  it("refuses a bearer record with a public key, and duplicate key ids or public keys across the store", () => {
    const e = ed().record;
    const b = bearer().record;
    expect(() => parseCredentialDocument(doc(2, [{ ...b, publicKey: e.publicKey }]), NOW)).toThrowError(/unknown field/);
    expect(() => parseCredentialDocument(doc(2, [e, { ...b, keyId: e.keyId }]), NOW)).toThrowError(/keyId duplicates/);
    expect(() => parseCredentialDocument(doc(2, [e, { ...ed().record, publicKey: e.publicKey }]), NOW)).toThrowError(/publicKey duplicates/);
  });

  it("schema 3 and a missing schema version are refused", () => {
    expect(() => parseCredentialDocument(doc(3, []), NOW)).toThrowError(/schemaVersion must be 1 or 2/);
    expect(() => parseCredentialDocument(JSON.stringify({ credentials: [] }), NOW)).toThrowError(/schemaVersion must be 1 or 2/);
  });

  it("the four-active limit, expiry and revocation apply to Ed25519 credentials and count across schemes", () => {
    const three = [ed().record, ed().record, ed().record];
    expect(parseCredentialDocument(doc(2, [...three, bearer().record]), NOW)).toHaveLength(4);
    expect(() => parseCredentialDocument(doc(2, [...three, bearer().record, ed().record]), NOW)).toThrowError(/more than 4 active/);
    const revoked = { ...ed().record, revokedAt: new Date(NOW).toISOString() };
    expect(parseCredentialDocument(doc(2, [...three, bearer().record, revoked]), NOW)).toHaveLength(5);
    expect(() => parseCredentialDocument(doc(2, [{ ...ed().record, expiresAt: new Date(NOW + 366 * DAY).toISOString() }]), NOW)).toThrowError(/at most 365 days/);
  });
});

describe("M3-E E2: Ed25519 issuance", () => {
  it("generates a key pair, returns the PKCS#8 private key once as asag2_<keyId>.<base64url DER>, and records only the public key", () => {
    const { credential, record } = ed("writer");
    expect(credential).toMatch(/^asag2_[0-9a-f]{16}\.[A-Za-z0-9_-]{64}$/);
    expect(record).toEqual({ scheme: "ed25519", keyId: record.keyId, agentId: "writer", publicKey: record.publicKey, label: null, createdAt: new Date(NOW).toISOString(), expiresAt: new Date(NOW + 90 * DAY).toISOString(), revokedAt: null });
    const parsed = parseSigningCredential(credential)!;
    expect(parsed.keyId).toBe(record.keyId);
    expect(parsed.privateKey.export({ format: "jwk" }).x).toBe(record.publicKey);
    expect(JSON.stringify(record)).not.toContain(credential.slice(23));
    const stored = serializeCredentialDocument([record]);
    expect(stored).not.toContain(credential.slice(23));
    expect(stored).not.toContain(parsed.privateKey.export({ format: "jwk" }).d!);
  });

  it("key ids are unique and every key pair is different", () => {
    const issued = Array.from({ length: 100 }, () => ed());
    expect(new Set(issued.map((i) => i.record.keyId)).size).toBe(100);
    expect(new Set(issued.map((i) => i.record.publicKey)).size).toBe(100);
  });

  it("uses the same expiry rules: 90 days by default, 365 at most", () => {
    expect(Date.parse(ed("writer", { days: 365 }).record.expiresAt) - NOW).toBe(365 * DAY);
    for (const days of [0, 366, 2.5]) expect(() => ed("writer", { days })).toThrowError(CredentialConfigError);
    expect(() => ed("Bad")).toThrowError(/agentId/);
  });

  it("parseSigningCredential accepts only an Ed25519 PKCS#8 key in the exact format", () => {
    const { credential } = ed();
    expect(parseSigningCredential(credential)).not.toBeNull();
    const x25519 = (generateKeyPairSync("x25519").privateKey.export({ format: "der", type: "pkcs8" }) as Buffer).toString("base64url");
    for (const bad of [
      bearer().credential,
      credential.slice(0, -1),
      `${credential}A`,
      credential.replace("asag2_", "asag3_"),
      `asag2_${"0".repeat(16)}.${x25519}`,
      `asag2_${"0".repeat(16)}.${randomBytes(48).toString("base64url")}`,
      `asag2_${"0".repeat(16)}.${"A".repeat(64)}`, // 48 bytes, but not an Ed25519 PKCS#8 key
      undefined,
      42,
    ]) {
      expect(parseSigningCredential(bad), String(bad).slice(0, 12)).toBeNull();
    }
  });
});

describe("M3-E E2: the bearer switch and scheme separation", () => {
  it("AGENT_BEARER_ALLOWED enables bearer only when it is exactly \"true\"", () => {
    expect(bearerAllowedFromEnv({})).toBe(false);
    expect(bearerAllowedFromEnv({ AGENT_BEARER_ALLOWED: "true" })).toBe(true);
    for (const value of ["TRUE", "True", "1", "yes", " true", "true ", "false", ""]) expect(bearerAllowedFromEnv({ AGENT_BEARER_ALLOWED: value }), value).toBe(false);
  });

  it("bearer credentials are disabled by default: a correct secret is refused unless bearer is allowed", () => {
    const b = bearer();
    expect(createCredentialStore([b.record], { now: () => NOW }).verify(b.credential)).toEqual({ ok: false, reason: "bearer-disabled" });
    expect(createCredentialStore([b.record], { now: () => NOW, bearerAllowed: false }).verify(b.credential)).toEqual({ ok: false, reason: "bearer-disabled" });
    expect(createCredentialStore([b.record], { now: () => NOW, bearerAllowed: true }).verify(b.credential)).toEqual({ ok: true, agentId: "writer", keyId: b.record.keyId });
    expect(emptyCredentialStore().verify(b.credential)).toEqual({ ok: false, reason: "unknown-key" });
  });

  it("an Ed25519 key id never authenticates as a bearer credential, whatever the bearer setting", () => {
    const e = ed();
    const forged = `asag_${e.record.keyId}.${randomBytes(32).toString("base64url")}`;
    for (const bearerAllowed of [true, false]) {
      expect(createCredentialStore([e.record], { now: () => NOW, bearerAllowed }).verify(forged)).toEqual({ ok: false, reason: "scheme-mismatch" });
      expect(createCredentialStore([e.record], { now: () => NOW, bearerAllowed }).verify(e.credential)).toEqual({ ok: false, reason: "malformed" });
    }
  });

  it("a bearer key id never yields a public key, and Ed25519 public keys are independent of the bearer setting", () => {
    const e = ed();
    const b = bearer("reader");
    const signature = sign(null, message, parseSigningCredential(e.credential)!.privateKey);
    for (const bearerAllowed of [true, false]) {
      const store = createCredentialStore([e.record, b.record], { now: () => NOW, bearerAllowed });
      const lookup = store.publicKeyFor(e.record.keyId);
      expect(lookup.ok && lookup.agentId).toBe("writer");
      expect(lookup.ok && verify(null, message, lookup.publicKey, signature)).toBe(true);
      expect(store.publicKeyFor(b.record.keyId)).toEqual({ ok: false, reason: "scheme-mismatch" });
      expect(store.publicKeyFor("ffffffffffffffff")).toEqual({ ok: false, reason: "unknown-key" });
      expect([store.status(e.record.keyId), store.status(b.record.keyId)]).toEqual(["active", "active"]);
    }
  });

  it("revoked and expired Ed25519 keys are not returned", () => {
    let now = NOW;
    const short = ed("writer", { days: 1 });
    const revoked = { ...ed().record, revokedAt: new Date(NOW).toISOString() };
    const store = createCredentialStore([short.record, revoked], { now: () => now });
    expect(store.publicKeyFor(revoked.keyId)).toEqual({ ok: false, reason: "revoked" });
    expect(store.publicKeyFor(short.record.keyId).ok).toBe(true);
    now += DAY;
    expect(store.publicKeyFor(short.record.keyId)).toEqual({ ok: false, reason: "expired" });
    expect(store.status(short.record.keyId)).toBe("expired");
  });

  it("ed25519PublicKey accepts only a raw 32-byte Ed25519 key", () => {
    expect(ed25519PublicKey(ed().record.publicKey)?.asymmetricKeyType).toBe("ed25519");
    for (const bad of ["", "x".repeat(43), randomBytes(32).toString("base64"), randomBytes(32).toString("hex"), null, 7]) expect(ed25519PublicKey(bad)).toBeNull();
  });
});

describe("M3-E E2: hot reload with Ed25519 keys (temporary file)", () => {
  let dir: string | null = null;
  afterEach(() => {
    if (dir) rmSync(dir, { recursive: true, force: true });
    dir = null;
  });

  function setup(initial: CredentialRecord[], bearerAllowed?: boolean) {
    dir = mkdtempSync(join(tmpdir(), "agentshield-credential-v2-test-"));
    const path = join(dir, "agent-credentials.json");
    writeRestrictedFileAtomically(path, serializeCredentialDocument(initial), { overwrite: true });
    let now = NOW;
    const events: CredentialReloadEvent[] = [];
    const store = createReloadingCredentialStore(path, { now: () => now, bearerAllowed, onEvent: (e) => events.push(e) });
    const write = (records: CredentialRecord[]) => writeRestrictedFileAtomically(path, serializeCredentialDocument(records), { overwrite: true });
    return { path, store, events, write, advance: (ms: number) => (now += ms) };
  }

  it("a revoked Ed25519 key stops being returned within 2 seconds; an invalid file returns none, without fallback", () => {
    const e = ed();
    const t = setup([e.record]);
    expect(t.store.publicKeyFor(e.record.keyId).ok).toBe(true);
    t.write([{ ...e.record, revokedAt: new Date(NOW).toISOString() }]);
    t.advance(2000);
    expect(t.store.publicKeyFor(e.record.keyId)).toEqual({ ok: false, reason: "revoked" });
    t.write([e.record]);
    t.advance(2000);
    expect(t.store.publicKeyFor(e.record.keyId).ok).toBe(true);
    writeFileSync(t.path, "{ broken");
    t.advance(2000);
    expect(t.store.publicKeyFor(e.record.keyId)).toEqual({ ok: false, reason: "store-unavailable" });
  });

  it("warns about active bearer credentials while bearer is disabled (the default), and not otherwise", () => {
    const b = bearer();
    expect(setup([b.record, ed().record]).events).toEqual([{ kind: "bearer-disabled", count: 1 }]);
    expect(setup([b.record], true).events).toEqual([]);
    expect(setup([ed().record]).events).toEqual([]);
    expect(setup([{ ...b.record, revokedAt: new Date(NOW).toISOString() }]).events).toEqual([]);
  });

  it("a v1 store file loads as bearer and is refused for authentication by default", () => {
    const b = bearer();
    const { scheme: _scheme, ...v1 } = b.record;
    dir = mkdtempSync(join(tmpdir(), "agentshield-credential-v2-test-"));
    const path = join(dir, "agent-credentials.json");
    writeFileSync(path, doc(1, [v1]));
    const store = createReloadingCredentialStore(path, { now: () => NOW });
    expect(store.list()[0]?.scheme).toBe("bearer");
    expect(store.verify(b.credential)).toEqual({ ok: false, reason: "bearer-disabled" });
    expect(createReloadingCredentialStore(path, { now: () => NOW, bearerAllowed: true }).verify(b.credential).ok).toBe(true);
  });
});

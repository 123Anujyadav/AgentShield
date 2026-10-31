import { sign, verify } from "node:crypto";
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { runCli } from "./cli.js";
import { createCredentialStore, parseCredentialDocument, parseSigningCredential, type CredentialRecord } from "./credentials.js";
import { isRestrictedToCurrentUser } from "./file-security.js";

/** M3-D D2 / M3-E E2: the credential CLI, against temporary stores only (never the real default store). */

const NOW = Date.parse("2026-11-01T09:00:00.000Z");
const SIGNING = /asag2_[0-9a-f]{16}\.[A-Za-z0-9_-]{64}/g;
const BEARER = /asag_[0-9a-f]{16}\.[A-Za-z0-9_-]{43}/g;
const ANY_CREDENTIAL = /asag2?_[0-9a-f]{16}\./;

let dir: string;
let store: string;
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "agentshield-cli-test-"));
  store = join(dir, "agent-credentials.json");
});
afterEach(() => rmSync(dir, { recursive: true, force: true }));

function runWith(env: NodeJS.ProcessEnv, ...argv: string[]) {
  const out: string[] = [];
  const err: string[] = [];
  const code = runCli([...argv], { env: { AGENT_CREDENTIAL_FILE: store, ...env }, now: () => NOW, out: (l) => out.push(l), err: (l) => err.push(l) });
  const all = [...out, ...err].join("\n");
  return { code, out, err, all, signing: all.match(SIGNING) ?? [], bearer: all.match(BEARER) ?? [] };
}
const run = (...argv: string[]) => runWith({}, ...argv);
const legacy = (...argv: string[]) => runWith({ AGENT_BEARER_ALLOWED: "true" }, ...argv);
const records = (): CredentialRecord[] => parseCredentialDocument(readFileSync(store, "utf8"), NOW);
const keyIdOf = (credential: string) => /^asag2?_([0-9a-f]{16})\./.exec(credential)![1]!;
const verifier = () => createCredentialStore(records(), { now: () => NOW });

/** The private key in a printed credential signs, and the stored public key verifies. */
function signsAndVerifies(credential: string): boolean {
  const parsed = parseSigningCredential(credential);
  const lookup = verifier().publicKeyFor(parsed!.keyId);
  if (!lookup.ok) return false;
  const message = Buffer.from("canonical request bytes");
  return verify(null, message, lookup.publicKey, sign(null, message, parsed!.privateKey));
}

describe("M3-E E2: agent-credential create (Ed25519 by default)", () => {
  it("prints the private key exactly once, stores only the public key, and restricts the store to the current user", () => {
    const r = run("create", "--agent", "writer", "--label", "nightly job");
    expect(r.code).toBe(0);
    expect([r.signing.length, r.bearer.length]).toEqual([1, 0]);
    const [credential] = r.signing as [string];
    expect(r.all.split(credential)).toHaveLength(2); // shown once
    const [record] = records();
    expect(record).toMatchObject({ scheme: "ed25519", keyId: keyIdOf(credential), agentId: "writer", label: "nightly job", revokedAt: null });
    expect(Date.parse(record!.expiresAt) - NOW).toBe(90 * 24 * 60 * 60 * 1000);
    const text = readFileSync(store, "utf8");
    expect(text).not.toContain(credential.slice(23));
    expect(text).not.toMatch(/PRIVATE|pkcs8|asag2_/i);
    expect(JSON.parse(text).schemaVersion).toBe(2);
    expect(signsAndVerifies(credential)).toBe(true);
    expect(isRestrictedToCurrentUser(store)).toBe(true);
    expect(readdirSync(dir)).toEqual(["agent-credentials.json"]);
  });

  it("the printed private key is PKCS#8 for exactly the stored public key", () => {
    const credential = run("create", "--agent", "writer").signing[0]!;
    const parsed = parseSigningCredential(credential)!;
    expect(parsed.privateKey.asymmetricKeyType).toBe("ed25519");
    const [record] = records();
    expect(record?.scheme === "ed25519" && record.publicKey).toBe(parsed.privateKey.export({ format: "jwk" }).x);
  });

  it("--out writes the private key to a new current-user-only file and does not print it", () => {
    const out = join(dir, "writer.credential");
    const r = run("create", "--agent", "writer", "--out", out, "--days", "30");
    expect([r.code, r.signing, r.bearer]).toEqual([0, [], []]);
    const credential = readFileSync(out, "utf8").trim();
    expect(credential).toMatch(/^asag2_[0-9a-f]{16}\.[A-Za-z0-9_-]{64}$/);
    expect(isRestrictedToCurrentUser(out)).toBe(true);
    expect(records()[0]!.keyId).toBe(keyIdOf(credential));
    expect(signsAndVerifies(credential)).toBe(true);
  });

  it("--out never replaces an existing file, and then nothing is stored", () => {
    const out = join(dir, "existing.txt");
    writeFileSync(out, "keep me");
    const r = run("create", "--agent", "writer", "--out", out);
    expect([r.code, r.signing]).toEqual([1, []]);
    expect(readFileSync(out, "utf8")).toBe("keep me");
    expect(existsSync(store)).toBe(false);
  });

  it("refuses a fifth active credential for one agent (both schemes count); key ids are unique", () => {
    const created = [1, 2, 3].map(() => run("create", "--agent", "writer").signing[0]!);
    created.push(legacy("create", "--agent", "writer", "--scheme", "bearer").bearer[0]!);
    expect(new Set(created.map(keyIdOf)).size).toBe(4);
    const r = run("create", "--agent", "writer");
    expect([r.code, r.signing]).toEqual([1, []]);
    expect(r.err.join(" ")).toMatch(/already has 4 active credentials/);
    expect(records()).toHaveLength(4);
    expect(run("create", "--agent", "reader").code).toBe(0);
  });

  it("refuses bad input with a usage error and writes nothing", () => {
    expect(run("create").code).toBe(2);
    expect(run("create", "--agent", "Writer").code).toBe(1);
    expect(run("create", "--agent", "writer", "--days", "366").code).toBe(1);
    expect(run("create", "--agent", "writer", "--days", "ten").code).toBe(2);
    expect(run("create", "--agent", "writer", "--label", "a\u0007b").code).toBe(1);
    expect(run("create", "--agent", "writer", "--scheme", "rsa").code).toBe(2);
    expect(run("create", "--agent", "writer", "--scheme").code).toBe(2);
    expect(existsSync(store)).toBe(false);
  });
});

describe("M3-E E2: legacy bearer credentials need an explicit opt-in", () => {
  it("--scheme bearer is refused unless AGENT_BEARER_ALLOWED is exactly \"true\"", () => {
    for (const env of [{}, { AGENT_BEARER_ALLOWED: "false" }, { AGENT_BEARER_ALLOWED: "TRUE" }, { AGENT_BEARER_ALLOWED: "1" }, { AGENT_BEARER_ALLOWED: " true" }]) {
      const r = runWith(env, "create", "--agent", "writer", "--scheme", "bearer");
      expect([r.code, r.bearer, r.signing], JSON.stringify(env)).toEqual([1, [], []]);
      expect(r.err.join(" ")).toMatch(/Bearer credentials are disabled/);
    }
    expect(existsSync(store)).toBe(false);
  });

  it("with the opt-in, --scheme bearer issues a legacy bearer credential shown once and stored as a hash", () => {
    const r = legacy("create", "--agent", "writer", "--scheme", "bearer");
    expect([r.code, r.bearer.length, r.signing.length]).toEqual([0, 1, 0]);
    const [record] = records();
    expect(record?.scheme).toBe("bearer");
    expect(readFileSync(store, "utf8")).not.toContain(r.bearer[0]!.slice(22));
    expect(createCredentialStore(records(), { now: () => NOW, bearerAllowed: true }).verify(r.bearer[0]!).ok).toBe(true);
    expect(createCredentialStore(records(), { now: () => NOW }).verify(r.bearer[0]!)).toEqual({ ok: false, reason: "bearer-disabled" });
  });

  it("rotate replaces a legacy bearer credential with an Ed25519 one by default (the migration path)", () => {
    const bearer = legacy("create", "--agent", "writer", "--scheme", "bearer").bearer[0]!;
    const rotated = run("rotate", "--key", keyIdOf(bearer), "--revoke-old");
    expect([rotated.code, rotated.signing.length, rotated.bearer.length]).toEqual([0, 1, 0]);
    expect(records().map((r) => [r.scheme, r.revokedAt === null])).toEqual([
      ["bearer", false],
      ["ed25519", true],
    ]);
    expect(signsAndVerifies(rotated.signing[0]!)).toBe(true);
    expect(run("rotate", "--key", keyIdOf(rotated.signing[0]!), "--scheme", "bearer").code).toBe(1); // bearer still not allowed
  });
});

describe("M3-E E2: list, revoke and rotate", () => {
  it("list shows public metadata and the scheme only: never a hash, public key, private key or secret", () => {
    const signing = run("create", "--agent", "writer", "--label", "job").signing[0]!;
    const bearer = legacy("create", "--agent", "reader", "--scheme", "bearer").bearer[0]!;
    const stored = records();
    const secrets = [signing.slice(23), bearer.slice(22), ...stored.map((r) => (r.scheme === "ed25519" ? r.publicKey : r.sha256))];
    for (const r of [run("list"), run("list", "--json")]) {
      expect(r.code).toBe(0);
      expect(r.all).toContain(keyIdOf(signing));
      for (const secret of secrets) expect(r.all).not.toContain(secret);
      expect(r.all).not.toMatch(ANY_CREDENTIAL);
    }
    const rows = JSON.parse(run("list", "--json").out.join("\n"));
    expect(Object.keys(rows[0]).sort()).toEqual(["agentId", "createdAt", "expiresAt", "keyId", "label", "revokedAt", "scheme", "status"]);
    expect(rows.map((row: { scheme: string }) => row.scheme)).toEqual(["ed25519", "bearer"]);
    rmSync(store);
    expect(run("list").out).toEqual(["No agent credentials."]);
  });

  it("revoke keeps the record, marks it revoked, and the public key is no longer usable", () => {
    const credential = run("create", "--agent", "writer").signing[0]!;
    const r = run("revoke", "--key", keyIdOf(credential));
    expect([r.code, r.signing]).toEqual([0, []]);
    expect(records()[0]!.revokedAt).not.toBeNull();
    expect(verifier().publicKeyFor(keyIdOf(credential))).toEqual({ ok: false, reason: "revoked" });
    expect(run("revoke", "--key", keyIdOf(credential)).out.join(" ")).toMatch(/already revoked/);
    expect(run("revoke", "--key", "ffffffffffffffff").code).toBe(1);
    expect(run("revoke", "--key", "not-a-key").code).toBe(2);
  });

  it("rotate issues a new key once and keeps the old one active, or revokes it with --revoke-old", () => {
    const first = run("create", "--agent", "writer", "--label", "job").signing[0]!;
    const rotated = run("rotate", "--key", keyIdOf(first));
    expect([rotated.code, rotated.signing.length]).toEqual([0, 1]);
    const second = rotated.signing[0]!;
    expect([signsAndVerifies(first), signsAndVerifies(second)]).toEqual([true, true]);
    expect(records().find((r) => r.keyId === keyIdOf(second))).toMatchObject({ scheme: "ed25519", agentId: "writer", label: "job" });
    const third = run("rotate", "--key", keyIdOf(second), "--revoke-old").signing[0]!;
    expect(verifier().publicKeyFor(keyIdOf(second))).toEqual({ ok: false, reason: "revoked" });
    expect([signsAndVerifies(first), signsAndVerifies(third)]).toEqual([true, true]);
    expect(records()).toHaveLength(3);
    expect(run("rotate", "--key", keyIdOf(second)).code).toBe(1); // already revoked
  });
});

describe("M3-D: the CLI fails closed", () => {
  it("an invalid store is never written over", () => {
    writeFileSync(store, '{"schemaVersion":2,"credentials":[{"keyId":"bad"}]}');
    const before = readFileSync(store, "utf8");
    for (const r of [run("create", "--agent", "writer"), run("revoke", "--key", "0123456789abcdef"), run("list")]) {
      expect([r.code, r.signing, r.bearer]).toEqual([1, [], []]);
    }
    expect(readFileSync(store, "utf8")).toBe(before);
  });

  it("a second command refuses to run while the store is locked", () => {
    writeFileSync(`${store}.lock`, "");
    const r = run("create", "--agent", "writer");
    expect(r.code).toBe(1);
    expect(r.err.join(" ")).toMatch(/Another credential command is running/);
    expect(existsSync(store)).toBe(false);
  });

  it("never accepts or echoes a key or secret given as an argument", () => {
    for (const pasted of [`asag2_${"a".repeat(16)}.${"B".repeat(64)}`, `asag_${"a".repeat(16)}.${"B".repeat(43)}`]) {
      const r = run("create", "--agent", "writer", pasted);
      expect(r.code).toBe(2);
      expect(r.all).not.toContain(pasted);
      expect(run("create", "--private-key", pasted).all).not.toContain(pasted);
      expect(run("create", "--credential", pasted).all).not.toContain(pasted);
    }
    expect(run("bogus").code).toBe(2);
    expect(existsSync(store)).toBe(false);
  });
});

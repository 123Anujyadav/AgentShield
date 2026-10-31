import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { runCli } from "./cli.js";
import { createCredentialStore, parseCredentialDocument } from "./credentials.js";
import { isRestrictedToCurrentUser } from "./file-security.js";

/** M3-D D2: the credential CLI, against temporary stores only (never the real default store). */

const NOW = Date.parse("2026-11-01T09:00:00.000Z");
const CREDENTIAL = /asag_[0-9a-f]{16}\.[A-Za-z0-9_-]{43}/g;

let dir: string;
let store: string;
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "agentshield-cli-test-"));
  store = join(dir, "agent-credentials.json");
});
afterEach(() => rmSync(dir, { recursive: true, force: true }));

function run(...argv: string[]) {
  const out: string[] = [];
  const err: string[] = [];
  let now = NOW;
  const code = runCli([...argv], { env: { AGENT_CREDENTIAL_FILE: store }, now: () => now, out: (l) => out.push(l), err: (l) => err.push(l) });
  now += 1;
  const all = [...out, ...err].join("\n");
  return { code, out, err, all, credentials: all.match(CREDENTIAL) ?? [] };
}
const records = () => parseCredentialDocument(readFileSync(store, "utf8"), NOW);
const keyIdOf = (credential: string) => credential.slice(5, 21);

describe("M3-D: agent-credential create", () => {
  it("prints the new credential exactly once, stores only its hash, and restricts the store to the current user", () => {
    const r = run("create", "--agent", "writer", "--label", "nightly job");
    expect(r.code).toBe(0);
    expect(r.credentials).toHaveLength(1);
    const [credential] = r.credentials as [string];
    const [record] = records();
    expect(record).toMatchObject({ keyId: keyIdOf(credential), agentId: "writer", label: "nightly job", revokedAt: null });
    expect(Date.parse(record!.expiresAt) - NOW).toBe(90 * 24 * 60 * 60 * 1000);
    const text = readFileSync(store, "utf8");
    expect(text).not.toContain(credential.slice(22));
    expect(createCredentialStore(records(), () => NOW).verify(credential)).toEqual({ ok: true, agentId: "writer", keyId: record!.keyId });
    expect(isRestrictedToCurrentUser(store)).toBe(true);
    expect(readdirSync(dir)).toEqual(["agent-credentials.json"]);
  });

  it("--out writes the credential to a new current-user-only file and does not print it", () => {
    const out = join(dir, "writer.credential");
    const r = run("create", "--agent", "writer", "--out", out, "--days", "30");
    expect([r.code, r.credentials]).toEqual([0, []]);
    const credential = readFileSync(out, "utf8").trim();
    expect(credential).toMatch(/^asag_[0-9a-f]{16}\.[A-Za-z0-9_-]{43}$/);
    expect(isRestrictedToCurrentUser(out)).toBe(true);
    expect(records()[0]!.keyId).toBe(keyIdOf(credential));
  });

  it("--out never replaces an existing file, and then nothing is stored", () => {
    const out = join(dir, "existing.txt");
    writeFileSync(out, "keep me");
    const r = run("create", "--agent", "writer", "--out", out);
    expect(r.code).toBe(1);
    expect(r.credentials).toEqual([]);
    expect(readFileSync(out, "utf8")).toBe("keep me");
    expect(existsSync(store)).toBe(false);
  });

  it(`refuses a fifth active credential for one agent; generated key ids are unique`, () => {
    const created = [1, 2, 3, 4].map(() => run("create", "--agent", "writer").credentials[0]!);
    expect(new Set(created.map(keyIdOf)).size).toBe(4);
    const r = run("create", "--agent", "writer");
    expect([r.code, r.credentials]).toEqual([1, []]);
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
    expect(existsSync(store)).toBe(false);
  });
});

describe("M3-D: agent-credential list, revoke and rotate", () => {
  it("list shows public metadata only: never a hash or a secret", () => {
    const credential = run("create", "--agent", "writer", "--label", "job").credentials[0]!;
    const { sha256 } = records()[0]!;
    for (const r of [run("list"), run("list", "--json")]) {
      expect(r.code).toBe(0);
      expect(r.all).toContain(keyIdOf(credential));
      expect(r.all).not.toContain(sha256);
      expect(r.all).not.toContain(credential.slice(22));
      expect(r.credentials).toEqual([]);
    }
    expect(Object.keys(JSON.parse(run("list", "--json").out.join("\n"))[0]).sort()).toEqual(["agentId", "createdAt", "expiresAt", "keyId", "label", "revokedAt", "status"]);
    rmSync(store);
    expect(run("list").out).toEqual(["No agent credentials."]);
  });

  it("revoke keeps the record, marks it revoked, and the credential stops verifying", () => {
    const credential = run("create", "--agent", "writer").credentials[0]!;
    const r = run("revoke", "--key", keyIdOf(credential));
    expect([r.code, r.credentials]).toEqual([0, []]);
    const [record] = records();
    expect(record!.revokedAt).not.toBeNull();
    expect(createCredentialStore(records(), () => NOW).verify(credential)).toEqual({ ok: false, reason: "revoked" });
    expect(run("revoke", "--key", keyIdOf(credential)).out.join(" ")).toMatch(/already revoked/);
    expect(run("revoke", "--key", "ffffffffffffffff").code).toBe(1);
    expect(run("revoke", "--key", "not-a-key").code).toBe(2);
  });

  it("rotate issues a new credential once and keeps the old one active, or revokes it with --revoke-old", () => {
    const first = run("create", "--agent", "writer", "--label", "job").credentials[0]!;
    const rotated = run("rotate", "--key", keyIdOf(first));
    expect([rotated.code, rotated.credentials.length]).toEqual([0, 1]);
    const second = rotated.credentials[0]!;
    let verify = createCredentialStore(records(), () => NOW);
    expect([verify.verify(first).ok, verify.verify(second).ok]).toEqual([true, true]);
    expect(records().find((r) => r.keyId === keyIdOf(second))).toMatchObject({ agentId: "writer", label: "job" });

    const third = run("rotate", "--key", keyIdOf(second), "--revoke-old").credentials[0]!;
    verify = createCredentialStore(records(), () => NOW);
    expect([verify.verify(first).ok, verify.verify(second).ok, verify.verify(third).ok]).toEqual([true, false, true]);
    expect(records()).toHaveLength(3);
    expect(run("rotate", "--key", keyIdOf(second)).code).toBe(1); // already revoked
  });
});

describe("M3-D: the CLI fails closed", () => {
  it("an invalid store is never written over", () => {
    writeFileSync(store, '{"schemaVersion":1,"credentials":[{"keyId":"bad"}]}');
    const before = readFileSync(store, "utf8");
    for (const r of [run("create", "--agent", "writer"), run("revoke", "--key", "0123456789abcdef"), run("list")]) {
      expect([r.code, r.credentials]).toEqual([1, []]);
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

  it("never echoes unexpected arguments, which could be a pasted secret", () => {
    const pasted = `asag_${"a".repeat(16)}.${"B".repeat(43)}`;
    const r = run("create", "--agent", "writer", pasted);
    expect(r.code).toBe(2);
    expect(r.all).not.toContain(pasted);
    expect(run("create", "--credential", pasted).all).not.toContain(pasted);
    expect(run("bogus").code).toBe(2);
  });
});

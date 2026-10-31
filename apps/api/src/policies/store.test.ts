import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { DEMO_AGENT_ID, DEMO_AGENT_POLICY, type AgentPolicy } from "@agentshield/engine";
import {
  builtInPolicyStore,
  canonicalPolicyJson,
  createPolicyStore,
  loadPolicyStore,
  MAX_POLICY_FILE_BYTES,
  parsePolicyDocument,
  PolicyConfigError,
  policyHash,
} from "./store.js";

/** M3-C: the policy store. Pure; temporary files go to the OS temp directory and are removed. */

const valid: AgentPolicy = {
  agentId: "writer.v2",
  version: 1,
  description: "Writes summaries.",
  allowedActions: ["create_summary"],
  deniedActions: ["send_payment"],
  allowedDestinations: ["simulated-workspace"],
};
const doc = (policies: unknown[], extra: Record<string, unknown> = {}) => JSON.stringify({ schemaVersion: 1, policies, ...extra });
const refuses = (text: string, message: RegExp) => expect(() => parsePolicyDocument(text)).toThrowError(message);

describe("M3-C: built-in store", () => {
  it("holds only the demo agent, and every other agent is unknown", () => {
    const store = builtInPolicyStore();
    expect(store.source).toBe("built-in");
    expect(store.list().map((p) => p.policy.agentId)).toEqual([DEMO_AGENT_ID]);
    expect(store.get(DEMO_AGENT_ID)?.policy).toEqual(DEMO_AGENT_POLICY);
    for (const id of ["writer", "Demo-Summarizer", "demo-summarizer ", "__proto__", "constructor", "toString", "hasOwnProperty"]) {
      expect(store.get(id), id).toBeUndefined();
    }
  });

  it("stored policies and their lists cannot be changed at runtime", () => {
    const loaded = builtInPolicyStore().get(DEMO_AGENT_ID)!;
    expect(Object.isFrozen(loaded.policy) && Object.isFrozen(loaded.policy.allowedActions) && Object.isFrozen(loaded.ref)).toBe(true);
    expect(() => (loaded.policy.allowedActions as string[]).push("send_payment")).toThrow();
  });
});

describe("M3-C: policy documents are validated strictly", () => {
  it("accepts a valid document and keeps exactly its fields", () => {
    expect(parsePolicyDocument(doc([valid]))).toEqual([valid]);
    expect(parsePolicyDocument(`﻿${doc([valid])}`)).toEqual([valid]); // a UTF-8 BOM is tolerated
    expect(parsePolicyDocument(doc([]))).toEqual([]); // no policies: every agent is unknown
  });

  it.each([
    ["not JSON", "{", /not valid JSON/],
    ["a top-level array", "[]", /must be a JSON object/],
    ["an unknown top-level field", doc([valid], { extra: true }), /unknown field "extra"/],
    ["another schema version", JSON.stringify({ schemaVersion: 2, policies: [] }), /schemaVersion must be 1/],
    ["policies not an array", JSON.stringify({ schemaVersion: 1, policies: {} }), /policies must be an array/],
    ["too many policies", doc(Array.from({ length: 201 }, (_, i) => ({ ...valid, agentId: `a${i}` }))), /more than 200/],
    ["an unknown policy field", doc([{ ...valid, allowAll: true }]), /unknown field "allowAll"/],
    ["a missing list", doc([{ ...valid, allowedDestinations: undefined }]), /allowedDestinations is required/],
    ["a list that is not an array", doc([{ ...valid, allowedActions: "create_summary" }]), /must be an array/],
    ["a non-string entry", doc([{ ...valid, allowedActions: [1] }]), /must be a non-empty string/],
    ["an empty entry", doc([{ ...valid, allowedActions: [""] }]), /must be a non-empty string/],
    ["a wildcard", doc([{ ...valid, allowedDestinations: ["*"] }]), /wildcards are not supported/],
    ["a partial wildcard", doc([{ ...valid, allowedActions: ["create_*"] }]), /wildcards are not supported/],
    ["surrounding whitespace", doc([{ ...valid, allowedActions: [" create_summary"] }]), /whitespace/],
    ["a control character", doc([{ ...valid, allowedActions: ["create\u0000summary"] }]), /control character/],
    ["a duplicate entry", doc([{ ...valid, deniedActions: ["send_payment", "send_payment"] }]), /duplicate/],
    ["a too-long entry", doc([{ ...valid, allowedActions: ["x".repeat(129)] }]), /longer than 128/],
    ["too many entries", doc([{ ...valid, allowedActions: Array.from({ length: 65 }, (_, i) => `a${i}`) }]), /more than 64/],
    ["a too-long description", doc([{ ...valid, description: "d".repeat(501) }]), /description/],
    ["version 0", doc([{ ...valid, version: 0 }]), /positive integer/],
    ["a fractional version", doc([{ ...valid, version: 1.5 }]), /positive integer/],
    ["a string version", doc([{ ...valid, version: "1" }]), /positive integer/],
    ["an upper-case agent id", doc([{ ...valid, agentId: "Writer" }]), /agentId must match/],
    ["an agent id starting with '-'", doc([{ ...valid, agentId: "-writer" }]), /agentId must match/],
    ["an agent id like __proto__", doc([{ ...valid, agentId: "__proto__" }]), /agentId must match/],
    ["a too-long agent id", doc([{ ...valid, agentId: "a".repeat(65) }]), /agentId must match/],
    ["a non-ASCII agent id", doc([{ ...valid, agentId: "wrіter" }]), /agentId must match/], // Cyrillic 'і'
    ["duplicate agents", doc([valid, { ...valid, version: 2 }]), /duplicates an earlier policy/],
  ])("refuses %s", (_label, text, message) => {
    if (/duplicates/.test(String(message))) {
      expect(() => createPolicyStore(parsePolicyDocument(text), "file")).toThrowError(message);
    } else {
      refuses(text, message);
    }
  });

  it("refuses a document larger than the limit, and errors never echo file contents", () => {
    const huge = doc([{ ...valid, description: "ok" }]).padEnd(MAX_POLICY_FILE_BYTES + 1, " ");
    refuses(huge, /larger than/);
    try {
      parsePolicyDocument(doc([{ ...valid, allowedActions: ["fakeSecretLookingEntry*"] }]));
    } catch (error) {
      expect(error).toBeInstanceOf(PolicyConfigError);
      expect((error as Error).message).not.toContain("fakeSecretLookingEntry");
    }
  });
});

describe("M3-C: policy versioning", () => {
  it("the hash is a stable SHA-256 of the canonical policy, and any change to it changes the hash", () => {
    expect(policyHash(valid)).toMatch(/^[0-9a-f]{64}$/);
    expect(policyHash({ ...valid })).toBe(policyHash(valid));
    expect(canonicalPolicyJson({ ...valid, description: undefined })).toContain('"description":null');
    const variants: AgentPolicy[] = [
      { ...valid, version: 2 },
      { ...valid, description: "Other" },
      { ...valid, allowedActions: ["read_document"] },
      { ...valid, deniedActions: [] },
      { ...valid, allowedDestinations: ["archive"] },
      { ...valid, allowedActions: ["create_summary", "read_document"] },
    ];
    for (const variant of variants) expect(policyHash(variant)).not.toBe(policyHash(valid));
  });

  it("each loaded policy carries its agent, declared version and hash", () => {
    const store = createPolicyStore([valid], "file");
    expect(store.get("writer.v2")?.ref).toEqual({ agentId: "writer.v2", version: 1, sha256: policyHash(valid) });
  });
});

describe("M3-C: loading at start-up", () => {
  let dir: string | null = null;
  afterEach(() => {
    if (dir) rmSync(dir, { recursive: true, force: true });
    dir = null;
  });
  const file = (text: string) => {
    dir = mkdtempSync(join(tmpdir(), "agentshield-policy-test-"));
    const path = join(dir, "policies.json");
    writeFileSync(path, text);
    return path;
  };

  it("no AGENT_POLICY_FILE (unset or blank): the built-in demo policy only", () => {
    expect(loadPolicyStore({}).source).toBe("built-in");
    expect(loadPolicyStore({ AGENT_POLICY_FILE: "   " }).list()).toHaveLength(1);
  });

  it("a valid file replaces the built-in policy entirely", () => {
    const store = loadPolicyStore({ AGENT_POLICY_FILE: file(doc([valid])) });
    expect([store.source, store.list().map((p) => p.policy.agentId)]).toEqual(["file", ["writer.v2"]]);
    expect(store.get(DEMO_AGENT_ID)).toBeUndefined();
  });

  it("a configured file that is missing, oversized or invalid fails closed", () => {
    expect(() => loadPolicyStore({ AGENT_POLICY_FILE: join(tmpdir(), "agentshield-no-such-policy-file.json") })).toThrowError(PolicyConfigError);
    expect(() => loadPolicyStore({ AGENT_POLICY_FILE: file("x".repeat(MAX_POLICY_FILE_BYTES + 1)) })).toThrowError(/larger than/);
    expect(() => loadPolicyStore({ AGENT_POLICY_FILE: file(doc([{ ...valid, agentId: "BAD" }])) })).toThrowError(/agentId must match/);
  });

  it("the shipped example file is valid and keeps the seeded demo policy", () => {
    const example = readFileSync(new URL("../../../../config/agent-policies.example.json", import.meta.url), "utf8");
    const store = createPolicyStore(parsePolicyDocument(example), "file");
    expect(store.get(DEMO_AGENT_ID)?.policy).toEqual(DEMO_AGENT_POLICY);
    expect(store.get(DEMO_AGENT_ID)?.ref).toEqual(builtInPolicyStore().get(DEMO_AGENT_ID)?.ref);
  });

  it("the server stops at start-up on an invalid policy file", () => {
    const server = readFileSync(new URL("../server.ts", import.meta.url), "utf8");
    expect(server).toContain("policyStore = loadPolicyStore();");
    expect(server).toMatch(/catch \(error\) \{[\s\S]*?agent-policy status=invalid-config[\s\S]*?process\.exit\(1\);/);
    expect(server).toContain("createApp({ apiToken: tokenFile.token, policyStore })");
  });
});

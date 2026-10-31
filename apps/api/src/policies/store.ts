import { createHash } from "node:crypto";
import { readFileSync, statSync } from "node:fs";
import { DEMO_AGENT_POLICY, type AgentPolicy, type AgentPolicyRef } from "@agentshield/engine";

/**
 * Server-side agent policy store (M3-C).
 *
 * Policies are loaded once at start-up and never change at runtime; there is no
 * write API. With no AGENT_POLICY_FILE configured, only the built-in demo agent
 * (the seeded scenarios' agent) exists, and every other agent is unknown and
 * denied. A configured file replaces the built-in policy entirely and must pass
 * strict validation; an invalid file stops the server from starting (fail closed).
 */

export const AGENT_ID_PATTERN = /^[a-z0-9][a-z0-9._-]{0,63}$/;
export const MAX_POLICY_FILE_BYTES = 256 * 1024;
export const MAX_POLICIES = 200;
export const MAX_LIST_ENTRIES = 64;
export const MAX_ENTRY_LENGTH = 128;
export const MAX_DESCRIPTION_LENGTH = 500;

/** The policy file's schema version. */
export const POLICY_SCHEMA_VERSION = 1;

export interface LoadedPolicy {
  policy: Readonly<AgentPolicy>;
  ref: AgentPolicyRef;
}

export interface PolicyStore {
  /** Where the policies came from: the built-in demo policy, or the configured file. */
  readonly source: "built-in" | "file";
  get(agentId: string): LoadedPolicy | undefined;
  list(): LoadedPolicy[];
}

/** Raised for any invalid policy configuration. Messages name the field, never echo file contents. */
export class PolicyConfigError extends Error {}

const POLICY_KEYS = new Set(["agentId", "version", "description", "allowedActions", "deniedActions", "allowedDestinations"]);
const DOCUMENT_KEYS = new Set(["schemaVersion", "policies"]);
const CONTROL = /[\u0000-\u001f\u007f]/;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function validateList(value: unknown, where: string): string[] {
  if (!Array.isArray(value)) throw new PolicyConfigError(`${where} must be an array of strings.`);
  if (value.length > MAX_LIST_ENTRIES) throw new PolicyConfigError(`${where} has more than ${MAX_LIST_ENTRIES} entries.`);
  const seen = new Set<string>();
  for (const [index, entry] of value.entries()) {
    const at = `${where}[${index}]`;
    if (typeof entry !== "string" || entry.length === 0) throw new PolicyConfigError(`${at} must be a non-empty string.`);
    if (entry.length > MAX_ENTRY_LENGTH) throw new PolicyConfigError(`${at} is longer than ${MAX_ENTRY_LENGTH} characters.`);
    if (CONTROL.test(entry)) throw new PolicyConfigError(`${at} contains a control character.`);
    if (entry.includes("*")) throw new PolicyConfigError(`${at} contains "*"; wildcards are not supported.`);
    if (entry !== entry.trim()) throw new PolicyConfigError(`${at} has leading or trailing whitespace.`);
    if (seen.has(entry)) throw new PolicyConfigError(`${at} is a duplicate.`);
    seen.add(entry);
  }
  return [...value] as string[];
}

/** Validates one policy object strictly and returns a clean copy. */
export function validatePolicy(value: unknown, where = "policy"): AgentPolicy {
  if (!isRecord(value)) throw new PolicyConfigError(`${where} must be an object.`);
  for (const key of Object.keys(value)) {
    // The field name comes from the file and is never echoed (M3-D audit L4).
    if (!POLICY_KEYS.has(key)) throw new PolicyConfigError(`${where} has an unknown field.`);
  }
  const { agentId, version, description } = value;
  if (typeof agentId !== "string" || !AGENT_ID_PATTERN.test(agentId)) {
    throw new PolicyConfigError(`${where}.agentId must match ${AGENT_ID_PATTERN.source}.`);
  }
  if (typeof version !== "number" || !Number.isSafeInteger(version) || version < 1) {
    throw new PolicyConfigError(`${where}.version must be a positive integer.`);
  }
  if (description !== undefined && (typeof description !== "string" || description.length > MAX_DESCRIPTION_LENGTH || CONTROL.test(description))) {
    throw new PolicyConfigError(`${where}.description must be text of at most ${MAX_DESCRIPTION_LENGTH} characters without control characters.`);
  }
  for (const required of ["allowedActions", "deniedActions", "allowedDestinations"]) {
    if (!(required in value)) throw new PolicyConfigError(`${where}.${required} is required.`);
  }
  return {
    agentId,
    version,
    ...(description !== undefined ? { description: description as string } : {}),
    allowedActions: validateList(value.allowedActions, `${where}.allowedActions`),
    deniedActions: validateList(value.deniedActions, `${where}.deniedActions`),
    allowedDestinations: validateList(value.allowedDestinations, `${where}.allowedDestinations`),
  };
}

/** Parses and validates a policy document. */
export function parsePolicyDocument(text: string): AgentPolicy[] {
  if (Buffer.byteLength(text, "utf8") > MAX_POLICY_FILE_BYTES) throw new PolicyConfigError(`The policy file is larger than ${MAX_POLICY_FILE_BYTES} bytes.`);
  let document: unknown;
  try {
    document = JSON.parse(text.replace(/^﻿/, ""));
  } catch {
    throw new PolicyConfigError("The policy file is not valid JSON.");
  }
  if (!isRecord(document)) throw new PolicyConfigError("The policy file must be a JSON object.");
  for (const key of Object.keys(document)) {
    if (!DOCUMENT_KEYS.has(key)) throw new PolicyConfigError("The policy file has an unknown top-level field.");
  }
  if (document.schemaVersion !== POLICY_SCHEMA_VERSION) throw new PolicyConfigError(`schemaVersion must be ${POLICY_SCHEMA_VERSION}.`);
  if (!Array.isArray(document.policies)) throw new PolicyConfigError("policies must be an array.");
  if (document.policies.length > MAX_POLICIES) throw new PolicyConfigError(`policies has more than ${MAX_POLICIES} entries.`);
  return document.policies.map((policy, index) => validatePolicy(policy, `policies[${index}]`));
}

/** Canonical JSON of a policy (fixed key order, lists as declared), so the same policy always hashes the same. */
export function canonicalPolicyJson(policy: AgentPolicy): string {
  return JSON.stringify({
    agentId: policy.agentId,
    version: policy.version,
    description: policy.description ?? null,
    allowedActions: policy.allowedActions,
    deniedActions: policy.deniedActions,
    allowedDestinations: policy.allowedDestinations,
  });
}

export function policyHash(policy: AgentPolicy): string {
  return createHash("sha256").update(canonicalPolicyJson(policy), "utf8").digest("hex");
}

function deepFreeze(policy: AgentPolicy): Readonly<AgentPolicy> {
  Object.freeze(policy.allowedActions);
  Object.freeze(policy.deniedActions);
  Object.freeze(policy.allowedDestinations);
  return Object.freeze(policy);
}

/** Builds a store from already-parsed policies. Every policy is re-validated; duplicate agents are refused. */
export function createPolicyStore(policies: readonly AgentPolicy[], source: PolicyStore["source"]): PolicyStore {
  const byAgent = new Map<string, LoadedPolicy>();
  policies.forEach((candidate, index) => {
    const policy = validatePolicy(candidate, `policies[${index}]`);
    if (byAgent.has(policy.agentId)) throw new PolicyConfigError(`policies[${index}].agentId duplicates an earlier policy.`);
    const ref: AgentPolicyRef = Object.freeze({ agentId: policy.agentId, version: policy.version, sha256: policyHash(policy) });
    byAgent.set(policy.agentId, Object.freeze({ policy: deepFreeze(policy), ref }));
  });
  return {
    source,
    get: (agentId) => byAgent.get(agentId),
    list: () => [...byAgent.values()],
  };
}

/** The store used with no policy file: the demo agent for the seeded scenarios, and nothing else. */
export function builtInPolicyStore(): PolicyStore {
  return createPolicyStore([DEMO_AGENT_POLICY], "built-in");
}

/**
 * The store for the server process. AGENT_POLICY_FILE unset or empty: built-in only.
 * Set: that file, which must exist, be at most MAX_POLICY_FILE_BYTES and pass
 * validation; anything else throws PolicyConfigError so start-up fails closed.
 */
export function loadPolicyStore(env: NodeJS.ProcessEnv = process.env): PolicyStore {
  const path = env.AGENT_POLICY_FILE?.trim();
  if (!path) return builtInPolicyStore();
  let size: number;
  try {
    size = statSync(path).size;
  } catch {
    throw new PolicyConfigError("AGENT_POLICY_FILE is set, but the file cannot be read.");
  }
  if (size > MAX_POLICY_FILE_BYTES) throw new PolicyConfigError(`The policy file is larger than ${MAX_POLICY_FILE_BYTES} bytes.`);
  const text = readFileSync(path, "utf8");
  return createPolicyStore(parsePolicyDocument(text), "file");
}

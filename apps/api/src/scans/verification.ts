import { randomBytes } from "node:crypto";
import type { TxtResolver } from "@agentshield/websec";

/**
 * DNS TXT ownership verification (M1). The owner publishes
 *
 *   _agentshield-verification.<hostname>  TXT  "agentshield-verification=<challenge>"
 *
 * and AgentShield checks it through an injected resolver. Only DNS is queried;
 * the target website is never contacted to verify ownership. The proof is
 * checked when the owner asks and again before every scan.
 */

export const VERIFICATION_LABEL = "_agentshield-verification";
export const VERIFICATION_PREFIX = "agentshield-verification=";
const DNS_TIMEOUT_MS = 5000;

export function createChallenge(): string {
  return randomBytes(24).toString("base64url");
}

export function verificationRecordName(hostname: string): string {
  return `${VERIFICATION_LABEL}.${hostname}`;
}

export function verificationRecordValue(challenge: string): string {
  return `${VERIFICATION_PREFIX}${challenge}`;
}

export type ProofFailure = "record-missing" | "record-mismatch" | "resolver-error" | "timeout";
export type ProofResult = { ok: true } | { ok: false; reason: ProofFailure };

const NO_RECORD_CODES = new Set(["ENODATA", "ENOTFOUND", "NXDOMAIN"]);

/**
 * True only when one TXT record at the verification name equals the expected
 * value exactly (a record split into several strings is joined first). Missing
 * records, other values, resolver errors and timeouts all fail.
 */
export async function checkDnsProof(resolver: TxtResolver, hostname: string, challenge: string): Promise<ProofResult> {
  const controller = new AbortController();
  let timer: NodeJS.Timeout | undefined;
  const timeout = new Promise<"timeout">((resolve) => {
    timer = setTimeout(() => {
      controller.abort();
      resolve("timeout");
    }, DNS_TIMEOUT_MS);
  });
  try {
    const answer = await Promise.race([resolver(verificationRecordName(hostname), controller.signal), timeout]);
    if (answer === "timeout") return { ok: false, reason: "timeout" };
    if (!Array.isArray(answer)) return { ok: false, reason: "resolver-error" };
    const expected = verificationRecordValue(challenge);
    const records = answer.filter(Array.isArray).map((chunks) => chunks.filter((c) => typeof c === "string").join(""));
    if (records.some((record) => record.trim() === expected)) return { ok: true };
    return { ok: false, reason: records.length === 0 ? "record-missing" : "record-mismatch" };
  } catch (error) {
    return { ok: false, reason: NO_RECORD_CODES.has((error as { code?: string }).code ?? "") ? "record-missing" : "resolver-error" };
  } finally {
    clearTimeout(timer);
  }
}

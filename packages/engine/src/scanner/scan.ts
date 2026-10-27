import type { Finding } from "../types.js";
import { SCANNER_RULES } from "./rules.js";

export type ScannerStatus = "clean" | "suspicious" | "empty";

export interface ScannerResult {
  status: ScannerStatus;
  findings: Finding[];
  contentLength: number;
}

export const MAX_SCAN_LENGTH = 8000;

const SECRET_VALUE_PATTERNS: RegExp[] = [
  /\b(?:api[-_ ]?key|secret|password|passwd|token)\s*[:=]\s*\S+/gi,
  /\bBearer\s+\S+/gi,
  /\bsk-[A-Za-z0-9_-]{6,}\b/g,
  /\bFAKE_[A-Z0-9_]*SECRET[A-Z0-9_]*\b/g,
  /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g,
];

/** Redact seeded-secret-shaped values and addresses. Applied to all evidence. */
export function redactEvidence(text: string): string {
  let out = text.replace(/\s+/g, " ").trim();
  for (const pattern of SECRET_VALUE_PATTERNS) out = out.replace(pattern, "[REDACTED]");
  return out.length > 160 ? `${out.slice(0, 157)}...` : out;
}

function sentenceAround(text: string, index: number): string {
  const start = Math.max(text.lastIndexOf(".", index - 1), text.lastIndexOf("\n", index - 1)) + 1;
  const endDot = text.indexOf(".", index);
  const end = endDot === -1 ? Math.min(text.length, index + 160) : endDot + 1;
  return text.slice(start, end).trim();
}

function evidenceAround(text: string, index: number, matchLength: number): string {
  const start = Math.max(0, index - 30);
  const end = Math.min(text.length, index + matchLength + 50);
  return redactEvidence(text.slice(start, end));
}

/**
 * Scan explicitly labelled untrusted content. The content is treated as data:
 * it is never executed, evaluated as code, or followed as instruction.
 * Malformed input (non-string, null) returns an empty result, never throws.
 */
export function scanUntrustedContent(input: unknown): ScannerResult {
  if (typeof input !== "string" || input.trim().length === 0) {
    return { status: "empty", findings: [], contentLength: 0 };
  }
  const text = input.slice(0, MAX_SCAN_LENGTH);
  const findings: Finding[] = [];

  for (const rule of SCANNER_RULES) {
    let matched: RegExpExecArray | null = null;
    for (const pattern of rule.patterns) {
      pattern.lastIndex = 0;
      matched = pattern.exec(text);
      if (matched) break;
    }
    if (!matched) continue;

    const sentence = sentenceAround(text, matched.index);
    if (rule.suppressIfSentenceMatches?.some((guard) => guard.test(sentence))) continue;

    findings.push({
      ruleId: rule.ruleId,
      category: "injection",
      severity: rule.severity,
      title: rule.title,
      explanation: `${rule.explanation} (rule-based matching, not an ML classifier)`,
      evidence: evidenceAround(text, matched.index, matched[0].length),
    });
  }

  return { status: findings.length > 0 ? "suspicious" : "clean", findings, contentLength: text.length };
}

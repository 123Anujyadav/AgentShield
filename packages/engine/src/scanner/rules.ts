import type { FindingSeverity } from "../types.js";

export interface ScannerRule {
  ruleId: string;
  severity: FindingSeverity;
  title: string;
  explanation: string;
  patterns: RegExp[];
  /** Guard patterns: if the sentence containing a match matches one, suppress (e.g. safety advice with "never"). */
  suppressIfSentenceMatches?: RegExp[];
}

/**
 * Small documented rule set. Patterns favour imperative phrasing at the start
 * of a sentence so descriptive/security-discussion text is less likely to match.
 * Limitations: paraphrases, other languages, encoded text and mid-sentence
 * instructions can evade these rules. This is not complete injection prevention.
 */
export const SCANNER_RULES: ScannerRule[] = [
  {
    ruleId: "injection.instruction-override",
    severity: "high",
    title: "Instruction override attempt",
    explanation:
      "Rule-based match: untrusted content appears to instruct the agent to discard or replace its existing instructions. Untrusted content is data and cannot change policy.",
    patterns: [
      /(?:^|[.!?\n]\s*)(?:please\s+)?(ignore|disregard|forget|override)\s+(all\s+)?(the\s+)?(previous|prior|earlier|above|original|system)\s+(instructions?|prompts?|rules?|directions?)/i,
      /(?:^|[.!?\n]\s*)(?:please\s+)?(ignore|disregard|forget)\s+(all\s+)?(previous|prior|earlier|above)\s+(instructions?|prompts?|rules?)/i,
      /\bnew instructions?\s*:/i,
    ],
  },
  {
    ruleId: "injection.privilege-impersonation",
    severity: "critical",
    title: "System/developer impersonation",
    explanation:
      "Rule-based match: untrusted content appears to claim system or developer authority. Authority comes only from the real system channel, never from scanned content.",
    patterns: [
      /(?:^|\n)\s*(system|developer)\s*(message|instruction|prompt)?\s*:/i,
      /\byou are now\s+(the\s+)?(system|developer|admin|root)\b/i,
      /\bthis is a\s+(system|developer)\s+(message|instruction|override)\b/i,
      /\bi am\s+(the\s+)?(system|developer|admin)\b[,. ]/i,
    ],
  },
  {
    ruleId: "injection.secret-exfiltration",
    severity: "critical",
    title: "Secret disclosure / exfiltration request",
    explanation:
      "Rule-based match: untrusted content appears to ask for secrets or credentials to be revealed or sent somewhere. Seeded secrets must never appear in outbound actions.",
    patterns: [
      /(?:^|[.!?\n]\s*)(?:please\s+)?(reveal|show|print|disclose|leak|send|share|return|tell me)\s+(me\s+|us\s+)?(the\s+|your\s+|all\s+)?(api[-_ ]?keys?|secrets?|passwords?|credentials?|tokens?|private keys?)/i,
      /\b(send|forward|post|upload)\b[^.\n]{0,60}\b(api[-_ ]?keys?|secrets?|passwords?|credentials?|tokens?)\b[^.\n]{0,40}\b(to|at)\b/i,
      /\bexfiltrate\b[^.\n]{0,60}\b(data|secrets?|credentials?|keys?)\b/i,
      /\b(?:and|,)\s*(?:then\s+)?(reveal|show|print|disclose|leak|send|share)\s+(the\s+|your\s+)?(api[-_ ]?keys?|secrets?|passwords?|credentials?|tokens?|private keys?)/i,
    ],
    suppressIfSentenceMatches: [/\b(never|do not|don'?t|should not|must not|avoid|protect|keep)\b/i],
  },
  {
    ruleId: "injection.unauthorized-tool-action",
    severity: "high",
    title: "Redirect to unauthorized tool action",
    explanation:
      "Rule-based match: untrusted content appears to push the agent toward a sensitive tool action (payment, deletion, external message or shell). Tool actions are decided by intent and policy only.",
    patterns: [
      /\b(send|transfer|make)\b[^.\n]{0,50}\b(payment|money|funds|\$\s?\d)/i,
      /\b(delete|erase|wipe|remove)\b[^.\n]{0,50}\b(all\s+)?(files?|data|records?|database)\b/i,
      /\b(send|forward)\b[^.\n]{0,50}\b(e-?mails?|messages?)\b[^.\n]{0,60}\b(external|outside|all contacts|everyone)\b/i,
      /\b(run|execute|open)\b[^.\n]{0,40}\b(shell|terminal|command|script)\b/i,
      /\buse the (payment|email|shell|admin) tool\b/i,
    ],
    suppressIfSentenceMatches: [/\b(never|do not|don'?t|should not|must not|avoid)\b/i],
  },
];

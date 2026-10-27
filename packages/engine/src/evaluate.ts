import { scanUntrustedContent } from "./scanner/scan.js";
import type { EvaluationInput, EvaluationResult, Finding } from "./types.js";

export const POLICY_VERSION = "agentshield-policy-v1";

/** Product-wide hard denies. Approval and risk score can never override these. */
export const HARD_DENY_ACTIONS = new Set(["send_payment", "delete_data", "send_external_message"]);

/**
 * Explicit policy rule (not an automatic scanner override):
 * suspicious untrusted content escalates an otherwise-allowed action to
 * CONFIRM. It never turns a BLOCK into an allow, and hard deny stays first.
 */
export const SCANNER_CONFIRM_RULE_ID = "policy.suspicious-content-requires-confirmation";

export function evaluateAction(input: EvaluationInput): EvaluationResult {
  const { intent, action } = input;

  const scan = input.untrustedContent
    ? scanUntrustedContent(input.untrustedContent.text)
    : null;
  const scannerFindings: Finding[] = scan?.findings ?? [];
  const scannerStatus = scan ? scan.status : "not-scanned";
  const withScanner = (policyFindings: Finding[]): Finding[] => [...scannerFindings, ...policyFindings];

  const blocked = (
    riskScore: number,
    finding: Finding,
    explanation: string,
  ): EvaluationResult => ({
    decision: "BLOCK",
    policyVersion: POLICY_VERSION,
    riskScore,
    findings: withScanner([finding]),
    scannerFindings,
    scannerStatus,
    explanation,
    actionType: action.type,
  });

  if (HARD_DENY_ACTIONS.has(action.type) || intent.deniedActions.includes(action.type)) {
    return {
      decision: "BLOCK",
      policyVersion: POLICY_VERSION,
      riskScore: 95,
      findings: withScanner([
        {
          ruleId: "hard-deny.explicitly-forbidden-action",
          category: "hard-deny",
          severity: "critical",
          title: "Explicitly forbidden action",
          explanation:
            "This action type is hard-denied. It cannot execute through the guarded simulator, and user approval cannot override this rule.",
          evidence: `action.type=${action.type}`,
        },
      ]),
      scannerFindings,
      scannerStatus,
      explanation: `Blocked: "${action.type}" is explicitly forbidden for this task. Approval does not override a hard deny.`,
      actionType: action.type,
    };
  }

  // Intent Firewall: missing/ambiguous permissions are treated conservatively.
  if (!Array.isArray(intent.allowedActions) || intent.allowedActions.length === 0) {
    return blocked(
      60,
      {
        ruleId: "intent.permissions-missing",
        category: "intent",
        severity: "high",
        title: "Missing or ambiguous permissions",
        explanation:
          "The intent lists no permitted action types, so no action can be authorised. Permission is never inferred from vague intent.",
        evidence: `intent.allowedActions is empty; action.type=${action.type}`,
      },
      `Blocked: permissions are missing or ambiguous for "${action.type}". Conservative default is to block.`,
    );
  }

  if (!intent.allowedActions.includes(action.type)) {
    return blocked(
      scannerFindings.length > 0 ? 75 : 70,
      {
        ruleId: "intent.action-not-allowed",
        category: "intent",
        severity: "high",
        title: "Action outside explicit intent",
        explanation: "The proposed action type is not in the user's allowed actions for this task.",
        evidence: `action.type=${action.type}; allowed=${intent.allowedActions.join(",")}`,
      },
      `Blocked: "${action.type}" is not allowed by the user's explicit intent.`,
    );
  }

  // Intent Firewall: destination check when the intent restricts destinations.
  if (
    intent.allowedDestinations !== undefined &&
    (intent.allowedDestinations.length === 0 || !intent.allowedDestinations.includes(action.destination))
  ) {
    return blocked(
      70,
      {
        ruleId: "intent.destination-not-allowed",
        category: "intent",
        severity: "high",
        title: "Destination outside explicit intent",
        explanation:
          "The action type is permitted, but its target/destination is not in the intent's allowed destinations.",
        evidence: `action.destination=${action.destination}; allowed=${intent.allowedDestinations.join(",") || "(none)"}`,
      },
      `Blocked: destination "${action.destination}" is not allowed by the user's explicit intent.`,
    );
  }

  const allowedFinding: Finding = {
    ruleId: "intent.action-allowed",
    category: "intent",
    severity: "low",
    title: "Action matches explicit intent",
    explanation: "The proposed action type is listed in the user's allowed actions and is not hard-denied.",
    evidence: `action.type=${action.type}`,
  };

  const hasSeriousScannerFinding = scannerFindings.some(
    (f) => f.severity === "high" || f.severity === "critical",
  );
  if (hasSeriousScannerFinding) {
    const hasCritical = scannerFindings.some((f) => f.severity === "critical");
    return {
      decision: "CONFIRM",
      policyVersion: POLICY_VERSION,
      riskScore: hasCritical ? 80 : 65,
      findings: withScanner([
        allowedFinding,
        {
          ruleId: SCANNER_CONFIRM_RULE_ID,
          category: "policy",
          severity: hasCritical ? "critical" : "high",
          title: "Suspicious untrusted content requires confirmation",
          explanation:
            "Explicit policy: the proposed action matches intent, but the rule-based scanner flagged the untrusted content, so a human must confirm before any simulated execution. The scanner alone did not hard-block this action.",
          evidence: `scanner rules: ${scannerFindings.map((f) => f.ruleId).join(", ")}`,
        },
      ]),
      scannerFindings,
      scannerStatus,
      explanation: `Confirmation required: "${action.type}" matches intent, but untrusted content triggered ${scannerFindings.length} scanner rule(s). Policy (${SCANNER_CONFIRM_RULE_ID}) requires confirmation; the action was not executed.`,
      actionType: action.type,
    };
  }

  return {
    decision: "ALLOW",
    policyVersion: POLICY_VERSION,
    riskScore: scannerFindings.length > 0 ? 30 : 10,
    findings: withScanner([allowedFinding]),
    scannerFindings,
    scannerStatus,
    explanation: `Allowed: "${action.type}" matches the user's explicit intent and no hard-deny rule matched.`,
    actionType: action.type,
  };
}

import { detectOutboundSecret, payloadAssignment, redactSecretValue, scanUntrustedContent, type OutboundSecretMatch } from "./scanner/scan.js";
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

/**
 * Outbound fields inspected by the Data-Leak Guard, in deterministic order.
 * Field labels are fixed and positional (action.payload.value[N]); raw
 * attacker-controlled payload keys are never copied into findings. Only
 * flat string/number/boolean values are inspected; unsupported values are
 * skipped without coercion (the API rejects them with 400 before this runs).
 */
function findOutboundSecret(action: EvaluationInput["action"]): OutboundSecretMatch | null {
  const summaryMatch = detectOutboundSecret("action.summary", action.summary);
  if (summaryMatch) return summaryMatch;
  if (action.payload && typeof action.payload === "object") {
    const entries = Object.entries(action.payload);
    for (let index = 0; index < entries.length; index += 1) {
      const [key, value] = entries[index] as [string, unknown];
      if (typeof value !== "string" && typeof value !== "number" && typeof value !== "boolean") continue;
      const field = `action.payload.value[${index}]`;
      const text = typeof value === "string" ? value : String(value);
      // Test the "key=value" form so labelled assignments inside payload
      // entries are recognized, and the bare value for token-shaped formats.
      const match = detectOutboundSecret(field, payloadAssignment(key, text)) ?? detectOutboundSecret(field, text);
      if (match) return match;
    }
  }
  const destinationMatch = detectOutboundSecret("action.destination", action.destination);
  if (destinationMatch) return destinationMatch;
  return null;
}

export function evaluateAction(input: EvaluationInput): EvaluationResult {
  const { intent, action } = input;
  // Display copies only (Phase I): secret-shaped request metadata is never echoed in
  // evidence or explanations. Every decision below still uses the raw values.
  const shownType = redactSecretValue(action.type);
  const shownList = (values: string[]): string => values.map(redactSecretValue).join(",");

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
    actionType: shownType,
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
          evidence: `action.type=${shownType}`,
        },
      ]),
      scannerFindings,
      scannerStatus,
      explanation: `Blocked: "${shownType}" is explicitly forbidden for this task. Approval does not override a hard deny.`,
      actionType: shownType,
    };
  }

  // Data-Leak Guard: a recognized secret-shaped value in the outbound action
  // is a hard BLOCK. It runs before permissions, destination, and the scanner
  // CONFIRM escalation, so it can never be downgraded to CONFIRM or ALLOW,
  // and approval/policy recheck (which re-run this evaluator) cannot execute
  // it. Evidence names only the field and pattern kind, never the value.
  const outboundSecret = findOutboundSecret(action);
  if (outboundSecret) {
    return blocked(95, {
      ruleId: "data-leak.outbound-secret",
      category: "hard-deny",
      severity: "critical",
      title: "Outbound action contains a secret-shaped value",
      explanation:
        outboundSecret.kind === "field-too-long-to-inspect"
          ? "The proposed action has a summary, payload, or destination field too long to fully inspect for secret-shaped values, so it cannot be allowed or confirmed. Only the field position is reported."
          : "The proposed action's summary, payload, or destination contains a value matching a supported secret pattern. Outbound actions must not carry secrets. Only the matching pattern family is reported; detection is limited to the documented patterns and is not comprehensive secret detection.",
      evidence: `field=${outboundSecret.field}; pattern=${outboundSecret.kind}; value=[REDACTED]`,
    }, `Blocked: "${shownType}" would send a secret-shaped value (${outboundSecret.kind} in ${outboundSecret.field}). This is a hard block; approval cannot override it and nothing was executed.`);
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
        evidence: `intent.allowedActions is empty; action.type=${shownType}`,
      },
      `Blocked: permissions are missing or ambiguous for "${shownType}". Conservative default is to block.`,
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
        evidence: `action.type=${shownType}; allowed=${shownList(intent.allowedActions)}`,
      },
      `Blocked: "${shownType}" is not allowed by the user's explicit intent.`,
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
        evidence: `action.destination=${redactSecretValue(action.destination)}; allowed=${shownList(intent.allowedDestinations) || "(none)"}`,
      },
      `Blocked: destination "${redactSecretValue(action.destination)}" is not allowed by the user's explicit intent.`,
    );
  }

  const allowedFinding: Finding = {
    ruleId: "intent.action-allowed",
    category: "intent",
    severity: "low",
    title: "Action matches explicit intent",
    explanation: "The proposed action type is listed in the user's allowed actions and is not hard-denied.",
    evidence: `action.type=${shownType}`,
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
      explanation: `Confirmation required: "${shownType}" matches intent, but untrusted content triggered ${scannerFindings.length} scanner rule(s). Policy (${SCANNER_CONFIRM_RULE_ID}) requires confirmation; the action was not executed.`,
      actionType: shownType,
    };
  }

  return {
    decision: "ALLOW",
    policyVersion: POLICY_VERSION,
    riskScore: scannerFindings.length > 0 ? 30 : 10,
    findings: withScanner([allowedFinding]),
    scannerFindings,
    scannerStatus,
    explanation: `Allowed: "${shownType}" matches the user's explicit intent and no hard-deny rule matched.`,
    actionType: shownType,
  };
}

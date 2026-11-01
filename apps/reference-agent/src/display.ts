import type { EvaluationSummary, FailureReason, TaskOutcome } from "./agent.js";

/**
 * Turns an outcome into lines for a terminal (M3-E E6). Text that came from the server can
 * contain parts of the document, so it is made inert first: control, format and bidi
 * characters (terminal escapes, hidden or reordered text) are replaced and long text is
 * cut. The document itself, the summary text and finding evidence are never displayed;
 * neither is anything about the credential.
 */

const UNSAFE = /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]+/gu;
export const MAX_DISPLAY_TEXT = 300;

/** Makes untrusted text safe to print on one line. */
export function inert(value: string, max = MAX_DISPLAY_TEXT): string {
  const flat = value.replace(UNSAFE, " ").replace(/\s+/g, " ").trim();
  return flat.length <= max ? flat : `${flat.slice(0, max - 1)}…`;
}

const REASONS: Record<FailureReason, string> = {
  authentication: "AgentShield did not accept the agent's credential (unknown, expired or revoked, or the clock is off). Ask the operator to check or rotate it.",
  forbidden: "AgentShield refused the request for this agent.",
  "bad-request": "AgentShield refused the request as invalid.",
  "rate-limited": "AgentShield is rate limiting this agent.",
  unavailable: "AgentShield is temporarily unavailable.",
  timeout: "AgentShield did not answer in time.",
  network: "AgentShield could not be reached.",
  "server-error": "AgentShield reported an internal error.",
  "response-format": "AgentShield's answer was not in the expected format.",
  cancelled: "Waiting was cancelled.",
  "request-too-large": "The request is larger than AgentShield's 32 KB limit once encoded (control characters take six bytes each), so the SDK did not send it.",
  "approval-queue-full": "AgentShield's approval queue is full: it reported that the action needs an operator's confirmation, but no approval was created and nothing was executed.",
};

function decisionLines(evaluation: EvaluationSummary): string[] {
  const lines = [`AgentShield decision: ${evaluation.decision} (risk ${Number.isFinite(evaluation.riskScore) ? evaluation.riskScore : "?"})`];
  if (evaluation.explanation) lines.push(`Reason: ${inert(evaluation.explanation)}`);
  for (const finding of evaluation.findings.slice(0, 10)) lines.push(`- [${inert(finding.severity, 20)}] ${inert(finding.title, 120)} (${inert(finding.ruleId, 80)})`);
  if (evaluation.findings.length > 10) lines.push(`- and ${evaluation.findings.length - 10} more`);
  return lines;
}

export function describeOutcome(outcome: TaskOutcome): string[] {
  switch (outcome.status) {
    case "completed":
      return [
        ...decisionLines(outcome.evaluation),
        outcome.approvalId ? `Approved by the operator (${outcome.approvalId}) and executed.` : "Allowed and executed.",
        `Saved ${outcome.saved.id} (${outcome.saved.summary.length} characters) to the simulated workspace.`,
      ];
    case "blocked":
      return [...decisionLines(outcome.evaluation), "Blocked. Nothing was saved."];
    case "not-executed":
      return [...decisionLines(outcome.evaluation), "AgentShield did not execute the action, so nothing was saved."];
    case "rejected":
      return [...decisionLines(outcome.evaluation), `The operator rejected ${outcome.approvalId}. Nothing was saved.`];
    case "expired":
      return [...decisionLines(outcome.evaluation), `${outcome.approvalId} expired before an operator decided. Nothing was saved. Run the task again to ask again.`];
    case "blocked-on-recheck":
      return [...decisionLines(outcome.evaluation), `${outcome.approvalId} was approved but failed AgentShield's check at approval time (for example the policy changed or the credential was revoked). Nothing was saved.`];
    case "pending":
      return [...decisionLines(outcome.evaluation), `${outcome.approvalId} is still waiting for an operator. Nothing has been saved yet.`];
    case "wait-interrupted":
      return [
        ...decisionLines(outcome.evaluation),
        `Stopped following ${outcome.approvalId}: ${REASONS[outcome.reason]}`,
        "Its outcome is unknown and nothing was saved. The approval itself was not changed.",
      ];
    case "approval-missing":
      return [...decisionLines(outcome.evaluation), `AgentShield no longer knows ${outcome.approvalId} (it may have restarted). Nothing was saved. Run the task again to ask again.`];
    case "unconfirmed":
      if (outcome.reason === "approval-queue-full") {
        return [
          REASONS[outcome.reason],
          "The evaluation was not sent again and nothing was saved.",
          "Ask the operator to approve, reject or let pending approvals expire before running the task again.",
        ];
      }
      return [
        `${REASONS[outcome.reason]}`,
        "The evaluation may or may not have been processed, so it was not sent again and nothing was saved.",
        "Check this agent's approvals before running the task again.",
      ];
    case "refused":
      return [
        REASONS[outcome.reason],
        ...(outcome.retryAfterSeconds !== null ? [`Try again in ${outcome.retryAfterSeconds} seconds.`] : []),
        "The request was not processed and nothing was saved.",
      ];
  }
}

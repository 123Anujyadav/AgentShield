import type { ApprovalStatus, RequestActor } from "@agentshield/engine";

/**
 * M3-E E15: what the operator needs to see before deciding an approval, and how a decided one is shown.
 * Pure helpers (unit-tested without a browser).
 */

/**
 * Who made the request: the agent and its key id, or the operator. An operator either ran a seeded scenario
 * (it has a scenarioId) or, M3-E E17, decided an agent's approval (no scenarioId): the two are worded apart.
 */
export function requesterLabel(item: { agentId?: string | null; requestedBy?: RequestActor; actor?: RequestActor; scenarioId?: string | null }): string {
  const by = item.requestedBy ?? item.actor;
  const agent = item.agentId ? item.agentId : null;
  if (by?.kind === "agent") return `Agent ${agent ?? "(unknown)"} · key ${by.credentialId}`;
  if (by?.kind === "operator") {
    const who = `Operator (${by.method === "session" ? "dashboard" : "API token"})`;
    if (!agent) return who;
    return item.scenarioId ? `${who} · scenario as ${agent}` : `${who} · on agent ${agent}'s request`;
  }
  return agent ? `Agent ${agent} · requester not recorded` : "Requester not recorded";
}

export type StatusTone = "allow" | "confirm" | "block";

/**
 * EXECUTED is green. Outcomes that are not a block are amber: approved with no handler, and OUTCOME_UNKNOWN
 * (interrupted, damaged or restored: it will never run, and whether it ran before is unknown). Refusals are red.
 */
export function statusTone(status: ApprovalStatus): StatusTone {
  if (status === "EXECUTED") return "allow";
  if (status === "APPROVED_NOT_EXECUTED" || status === "OUTCOME_UNKNOWN" || status === "PENDING") return "confirm";
  return "block";
}

export const TONE_COLOR: Record<StatusTone, string> = { allow: "var(--allow)", confirm: "var(--confirm)", block: "var(--block)" };

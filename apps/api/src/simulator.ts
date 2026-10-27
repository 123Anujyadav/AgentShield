import type { Decision, ProposedAction, SimulatedExecution } from "@agentshield/engine";

type Handler = (action: ProposedAction) => string;

/** Explicit allowlist of harmless simulated handlers. No real side effects. */
const HANDLERS: Record<string, Handler> = {
  create_summary: (action) =>
    `Simulated summary preview created for destination "${action.destination}". No file was written.`,
  read_document: () => "Simulated document read complete. No file was accessed.",
  create_report: (action) =>
    `Simulated mock report produced for destination "${action.destination}". No data left this process.`,
};

export function isRegisteredHandler(actionType: string): boolean {
  return Object.prototype.hasOwnProperty.call(HANDLERS, actionType);
}

export interface Simulator {
  invocationCount: number;
  invocations: string[];
  /** Independently re-checks the decision before any handler can run. */
  execute(action: ProposedAction, decision: Decision): SimulatedExecution;
}

export function createSimulator(): Simulator {
  const simulator: Simulator = {
    invocationCount: 0,
    invocations: [],
    execute(action, decision) {
      if (decision === "BLOCK") {
        return { executed: false, handler: null, result: null, reason: "Decision is BLOCK. No handler invoked." };
      }
      if (decision === "CONFIRM") {
        return {
          executed: false,
          handler: null,
          result: null,
          reason: "Decision is CONFIRM. Approval and policy recheck are required before execution.",
        };
      }
      const handler = HANDLERS[action.type];
      if (!handler) {
        return {
          executed: false,
          handler: null,
          result: null,
          reason: `No registered simulated handler for action type "${action.type}".`,
        };
      }
      simulator.invocationCount += 1;
      simulator.invocations.push(action.type);
      return { executed: true, handler: action.type, result: handler(action), reason: null };
    },
  };
  return simulator;
}

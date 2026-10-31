/**
 * The simulated workspace (M3-E E6): an in-memory list of saved summaries. Saving a
 * summary is the reference agent's only side effect, and the agent does it only after
 * AgentShield reports the action as executed. Nothing is written to disk or sent anywhere.
 */

export interface SavedSummary {
  id: string;
  title: string;
  summary: string;
  /** The AgentShield approval that authorised it, for a CONFIRM; null for an ALLOW. */
  approvalId: string | null;
}

export class SimulatedWorkspace {
  readonly #items: SavedSummary[] = [];

  save(item: Omit<SavedSummary, "id">): SavedSummary {
    const saved = Object.freeze({ ...item, id: `summary-${this.#items.length + 1}` });
    this.#items.push(saved);
    return saved;
  }

  list(): readonly SavedSummary[] {
    return [...this.#items];
  }
}

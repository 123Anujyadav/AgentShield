/**
 * The reference agent's only task (M3-E E6): summarize a document into the simulated
 * workspace. The input describes the document and nothing else. It cannot name an agent,
 * an action, a tool, a destination or a credential: those are fixed by the agent and its
 * credential, so a document or a caller cannot change who acts or what is done.
 */

/**
 * AgentShield's limit for untrusted content (the API refuses `untrustedContent.text` longer
 * than this with 400; engine MAX_SCAN_LENGTH). Counted the way the API counts: JavaScript
 * string length, in UTF-16 code units, so a character outside the Basic Multilingual Plane
 * (such as most emoji) counts as two. The API stays authoritative; this check only stops a
 * request that would certainly be refused from being sent at all.
 */
export const MAX_DOCUMENT_CHARACTERS = 8000;
/**
 * A document file larger than this cannot hold MAX_DOCUMENT_CHARACTERS characters (at most
 * 3 UTF-8 bytes per UTF-16 code unit, plus a byte-order mark), so it is refused unread.
 */
export const MAX_DOCUMENT_BYTES = 24 * 1024;
export const MAX_TITLE_LENGTH = 100;

export interface SummaryTask {
  /** A short label for the saved summary (local only; never sent to AgentShield). */
  title: string;
  /** The document to summarize. Treated as untrusted data, never as instructions. */
  text: string;
}

export class TaskInputError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "TaskInputError";
  }
}

/** The document is longer than AgentShield accepts. It was not sent, and it is never shortened. */
export class DocumentTooLongError extends TaskInputError {
  readonly limit = MAX_DOCUMENT_CHARACTERS;
  constructor(readonly length: number) {
    super(`The document is ${length} characters long; AgentShield accepts at most ${MAX_DOCUMENT_CHARACTERS}. It was not sent, and it was not shortened.`);
    this.name = "DocumentTooLongError";
  }
}

const TASK_KEYS = ["text", "title"];
// Printable title: no control, format or bidi characters.
const UNSAFE_TITLE = /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/u;

/** Accepts exactly { title, text }. Any other field (an agent id, an action, a credential) is refused, not ignored. */
export function parseSummaryTask(input: unknown): SummaryTask {
  if (typeof input !== "object" || input === null || Array.isArray(input)) throw new TaskInputError("The task must be an object with a title and a text.");
  const keys = Object.keys(input).sort();
  if (keys.join(",") !== TASK_KEYS.join(",")) {
    throw new TaskInputError("The task accepts only a title and a text. The agent's identity comes from its credential, and its action is fixed.");
  }
  const { title, text } = input as Record<string, unknown>;
  if (typeof title !== "string" || title.trim().length === 0 || title.length > MAX_TITLE_LENGTH || UNSAFE_TITLE.test(title)) {
    throw new TaskInputError(`The title must be 1 to ${MAX_TITLE_LENGTH} printable characters.`);
  }
  if (typeof text !== "string" || text.trim().length === 0) throw new TaskInputError("The document text is empty.");
  // Refused whole, never truncated: a cut document could change what AgentShield scans.
  if (text.length > MAX_DOCUMENT_CHARACTERS) throw new DocumentTooLongError(text.length);
  return { title: title.trim(), text };
}

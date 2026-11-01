import { closeSync, constants, fstatSync, openSync, readSync } from "node:fs";
import { basename, extname } from "node:path";
import { parseArgs } from "node:util";
import { AgentShieldClient, AgentShieldError, type AgentShieldClientOptions } from "@agentshield/agent-sdk";
import { ReferenceAgent, type TaskOutcome } from "./agent.js";
import { AgentConfigError, loadAgentConfig } from "./config.js";
import { describeOutcome, inert } from "./display.js";
import { MAX_DOCUMENT_BYTES, MAX_DOCUMENT_CHARACTERS, MAX_TITLE_LENGTH, TaskInputError } from "./task.js";

/**
 * Command line for the reference agent (M3-E E6):
 *
 *   npm start -w @agentshield/reference-agent -- --document <file> [--title <text>] [--wait-minutes <1-60>]
 *
 * Exit codes: 0 completed (summary saved); 2 not done (blocked, rejected, expired, not
 * executed); 3 outcome open (still pending, unknown, or the evaluation is unconfirmed);
 * 1 refused, or a configuration or usage error.
 */

export interface CliIo {
  env: NodeJS.ProcessEnv;
  out: (line: string) => void;
  err: (line: string) => void;
  /** Tests only: replaces the SDK client's fetch, sleep and request timeout. */
  client?: Pick<AgentShieldClientOptions, "fetch" | "sleep" | "timeoutMs">;
}

const USAGE = "Usage: --document <file> [--title <text>] [--wait-minutes <1-60>]";

/**
 * Reads at most `maxBytes` from a regular file (M3-E E9). The checks are made on the opened file
 * itself, so a FIFO, device or directory is refused instead of blocking or being read without end,
 * and a file that grows after the check is still read only up to the limit. Opened non-blocking where
 * the platform supports it, so opening a FIFO cannot hang either.
 */
function readSmallRegularFile(path: string, maxBytes: number, notRegular: () => Error, tooLarge: () => Error): string {
  const fd = openSync(path, constants.O_RDONLY | (constants.O_NONBLOCK ?? 0));
  try {
    const stat = fstatSync(fd);
    if (!stat.isFile()) throw notRegular();
    if (stat.size > maxBytes) throw tooLarge();
    const buffer = Buffer.alloc(maxBytes + 1);
    let length = 0;
    while (length < buffer.length) {
      const read = readSync(fd, buffer, length, buffer.length - length, null);
      if (read === 0) break;
      length += read;
    }
    if (length > maxBytes) throw tooLarge();
    return buffer.subarray(0, length).toString("utf8");
  } finally {
    closeSync(fd);
  }
}

export function exitCode(outcome: TaskOutcome): number {
  switch (outcome.status) {
    case "completed":
      return 0;
    case "blocked":
    case "not-executed":
    case "rejected":
    case "expired":
    case "blocked-on-recheck":
    case "approval-missing":
      return 2;
    case "pending":
    case "wait-interrupted":
    case "unconfirmed":
      return 3;
    case "refused":
      return 1;
  }
}

export async function runReferenceAgent(argv: string[], io: CliIo): Promise<number> {
  let values: { document?: string; title?: string; "wait-minutes"?: string };
  try {
    ({ values } = parseArgs({ args: argv, options: { document: { type: "string" }, title: { type: "string" }, "wait-minutes": { type: "string" } }, strict: true, allowPositionals: false }));
  } catch {
    io.err(USAGE);
    return 1;
  }
  if (!values.document) {
    io.err(USAGE);
    return 1;
  }
  const waitMinutes = values["wait-minutes"] === undefined ? 16 : Number(values["wait-minutes"]);
  if (!Number.isInteger(waitMinutes) || waitMinutes < 1 || waitMinutes > 60) {
    io.err("--wait-minutes must be a whole number from 1 to 60.");
    return 1;
  }

  try {
    const config = loadAgentConfig(io.env);
    let text: string;
    try {
      const tooLarge = () =>
        new TaskInputError(`The document file is larger than ${MAX_DOCUMENT_BYTES} bytes, so it is over AgentShield's ${MAX_DOCUMENT_CHARACTERS}-character limit. It was not sent.`);
      text = readSmallRegularFile(values.document, MAX_DOCUMENT_BYTES, () => new TaskInputError("The document is not a regular file."), tooLarge);
    } catch (error) {
      if (error instanceof TaskInputError) throw error;
      throw new TaskInputError("The document cannot be read.");
    }
    const title = (values.title ?? basename(values.document, extname(values.document))).slice(0, MAX_TITLE_LENGTH);
    const client = new AgentShieldClient({ baseUrl: config.baseUrl, credential: config.credential, ...io.client });
    io.out(`Agent credential ${config.credential.keyId}; AgentShield at ${client.toJSON().baseUrl}`);
    const agent = new ReferenceAgent({ client, approvalWaitMs: waitMinutes * 60 * 1000 });
    const outcome = await agent.run({ title, text });
    for (const line of describeOutcome(outcome)) io.out(line);
    return exitCode(outcome);
  } catch (error) {
    // Fixed messages only: config, credential and task errors never echo secrets or the document.
    if (error instanceof AgentConfigError || error instanceof TaskInputError || error instanceof AgentShieldError) {
      io.err(inert(error.message));
      return 1;
    }
    io.err("The reference agent stopped because of an unexpected error.");
    return 1;
  }
}

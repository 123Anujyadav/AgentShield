import { randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { FileSecurityError, writeRestrictedFileAtomically } from "../agents/file-security.js";

/**
 * The local API token (M0). It is generated once, stored in the user's profile
 * (outside the repository, so it cannot be committed), and never printed,
 * logged, or put in a URL. Only the server entry point loads it.
 */
export const API_TOKEN_FILE_NAME = "api-token";

/** 32 random bytes as base64url is 43 characters; longer hand-made tokens are accepted. */
const TOKEN_PATTERN = /^[A-Za-z0-9_-]{43,256}$/;

/**
 * %LOCALAPPDATA%\AgentShield on Windows. The folder inherits the profile's permissions, which on some machines
 * also grant other local groups read access (M3-E E17 found two), so files in it are restricted individually.
 */
export function defaultTokenDirectory(env: NodeJS.ProcessEnv = process.env): string {
  return join(env.LOCALAPPDATA ?? join(homedir(), ".local", "state"), "AgentShield");
}

export interface ApiTokenFile {
  token: string;
  path: string;
  created: boolean;
}

/**
 * Returns the stored token, or creates one if the file does not exist. A file
 * that exists but does not hold a valid token is an error and is never
 * overwritten; its content is never included in the error.
 */
export function loadOrCreateApiToken(directory: string = defaultTokenDirectory()): ApiTokenFile {
  const path = join(directory, API_TOKEN_FILE_NAME);
  let existing: string | null = null;
  try {
    existing = readFileSync(path, "utf8").trim();
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
  }
  if (existing !== null) {
    if (!TOKEN_PATTERN.test(existing)) {
      throw new Error(`The API token file does not hold a valid token: ${path}. Delete it to generate a new one.`);
    }
    return { token: existing, path, created: false };
  }
  const token = randomBytes(32).toString("base64url");
  // M3-E E17: restricted to the current user (one ACL entry on Windows, mode 0600 elsewhere) before the token
  // is written, like every other AgentShield state file. Before, the file inherited the folder's permissions on
  // Windows (mode is ignored there). Never replaces a file created in the meantime.
  try {
    writeRestrictedFileAtomically(path, token, { overwrite: false });
  } catch (error) {
    if (error instanceof FileSecurityError) throw new Error(`The API token file could not be created restricted to the current user: ${path}.`);
    throw error;
  }
  return { token, path, created: true };
}

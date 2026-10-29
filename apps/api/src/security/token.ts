import { randomBytes } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

/**
 * The local API token (M0). It is generated once, stored in the user's profile
 * (outside the repository, so it cannot be committed), and never printed,
 * logged, or put in a URL. Only the server entry point loads it.
 */
export const API_TOKEN_FILE_NAME = "api-token";

/** 32 random bytes as base64url is 43 characters; longer hand-made tokens are accepted. */
const TOKEN_PATTERN = /^[A-Za-z0-9_-]{43,256}$/;

/** %LOCALAPPDATA%\AgentShield on Windows (readable only by this Windows account by default). */
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
  mkdirSync(directory, { recursive: true, mode: 0o700 });
  const token = randomBytes(32).toString("base64url");
  // "wx": never replace a file created in the meantime. mode is ignored on Windows,
  // where the per-user profile folder's permissions apply instead.
  writeFileSync(path, token, { flag: "wx", mode: 0o600 });
  return { token, path, created: true };
}

import { existsSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

/**
 * Load the repo-root .env into process.env using Node's built-in loader.
 * No dependency is needed on Node 22 (process.loadEnvFile is built in).
 * Existing process environment values are not overwritten by the file.
 * Only the server entry point calls this; tests importing createApp do not.
 */
export function loadLocalEnv(fromUrl: string = import.meta.url): boolean {
  // src/ and dist/ are both three levels below the repo root that contains .env
  // (root -> apps -> api -> src|dist).
  const envPath = resolve(dirname(fileURLToPath(fromUrl)), "../../../.env");
  if (!existsSync(envPath)) return false;
  process.loadEnvFile(envPath);
  return true;
}

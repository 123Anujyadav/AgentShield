import { AgentCredential } from "@agentshield/agent-sdk";

/**
 * The reference agent's configuration (M3-E E6), from environment variables it names
 * explicitly. The credential is loaded only by the SDK's loaders. There is no setting for
 * the agent's identity: AgentShield takes it from the credential.
 *
 *   AGENTSHIELD_URL                     AgentShield's origin (default http://127.0.0.1:4000)
 *   AGENTSHIELD_AGENT_CREDENTIAL_FILE   path of the credential file (preferred), or
 *   AGENTSHIELD_AGENT_CREDENTIAL        the credential itself
 */

export const DEFAULT_BASE_URL = "http://127.0.0.1:4000";
export const URL_VARIABLE = "AGENTSHIELD_URL";
export const CREDENTIAL_FILE_VARIABLE = "AGENTSHIELD_AGENT_CREDENTIAL_FILE";
export const CREDENTIAL_VARIABLE = "AGENTSHIELD_AGENT_CREDENTIAL";
/** Refused if set, so nobody believes it has an effect. */
const IDENTITY_VARIABLES = ["AGENTSHIELD_AGENT_ID", "AGENTSHIELD_AGENT"];

export class AgentConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AgentConfigError";
  }
}

export interface AgentConfig {
  baseUrl: string;
  credential: AgentCredential;
}

export function loadAgentConfig(env: NodeJS.ProcessEnv): AgentConfig {
  for (const name of IDENTITY_VARIABLES) {
    if (env[name] !== undefined) throw new AgentConfigError(`${name} is not supported: the agent's identity comes only from its credential.`);
  }
  const file = env[CREDENTIAL_FILE_VARIABLE];
  const inline = env[CREDENTIAL_VARIABLE];
  if (file && inline) throw new AgentConfigError(`Set either ${CREDENTIAL_FILE_VARIABLE} or ${CREDENTIAL_VARIABLE}, not both.`);
  if (!file && !inline) throw new AgentConfigError(`Set ${CREDENTIAL_FILE_VARIABLE} to the agent's credential file.`);
  // CredentialError messages never echo the credential.
  const credential = file ? AgentCredential.fromFile(file) : AgentCredential.fromEnv(CREDENTIAL_VARIABLE, env);
  return { baseUrl: env[URL_VARIABLE] || DEFAULT_BASE_URL, credential };
}

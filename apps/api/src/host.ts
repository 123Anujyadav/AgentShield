/**
 * Network address the API server listens on (Phase J). IPv4 loopback only:
 * the API has no authentication, so it must not accept connections from other
 * hosts. Loopback does not protect against other processes on this machine.
 *
 * This module deliberately imports nothing, so loading it never reads .env or
 * any configuration that could hold secrets.
 */
export const API_HOST = "127.0.0.1";

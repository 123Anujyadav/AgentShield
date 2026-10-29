/**
 * API client (M0). Every request sends the HttpOnly session cookie
 * (credentials: "include"); the web app never sees or stores the API token
 * after sign-in, and never puts it in a URL.
 */
export const API_URL = import.meta.env.VITE_API_URL ?? "http://localhost:4000";

/** The session is missing or expired: the user must sign in again. */
export class UnauthorizedError extends Error {
  constructor() {
    super("Authentication required.");
    this.name = "UnauthorizedError";
  }
}

export async function apiFetch(path: string, init: RequestInit = {}): Promise<Response> {
  const res = await fetch(`${API_URL}${path}`, { ...init, credentials: "include" });
  if (res.status === 401) throw new UnauthorizedError();
  return res;
}

/** True when the browser already holds a live session. Throws if the API is unreachable. */
export async function hasSession(): Promise<boolean> {
  const res = await fetch(`${API_URL}/api/session`, { credentials: "include" });
  if (!res.ok) throw new Error(`API ${res.status}`);
  return ((await res.json()) as { authenticated?: boolean }).authenticated === true;
}

export type LoginResult = "ok" | "invalid" | "rate-limited" | "unreachable";

/** Exchanges the token for a session cookie. The token is sent once, in the request body. */
export async function login(token: string): Promise<LoginResult> {
  try {
    const res = await fetch(`${API_URL}/api/session`, {
      method: "POST",
      credentials: "include",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ token }),
    });
    if (res.ok) return "ok";
    if (res.status === 429) return "rate-limited";
    return "invalid";
  } catch {
    return "unreachable";
  }
}

export async function logout(): Promise<void> {
  try {
    await fetch(`${API_URL}/api/session`, { method: "DELETE", credentials: "include" });
  } catch {
    // Signing out locally still happens; the session also expires on its own.
  }
}

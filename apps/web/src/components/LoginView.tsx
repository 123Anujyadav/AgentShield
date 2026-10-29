import { useState, type FormEvent } from "react";
import { login, type LoginResult } from "../api.js";
import { ShieldIcon } from "./icons.js";

const TOKEN_COPY_COMMAND = 'Get-Content -Raw "$env:LOCALAPPDATA\\AgentShield\\api-token" | Set-Clipboard';

const MESSAGES: Record<Exclude<LoginResult, "ok">, string> = {
  invalid: "That token was not accepted.",
  "rate-limited": "Too many sign-in attempts. Wait a minute and try again.",
  unreachable: "Could not reach the AgentShield API on http://localhost:4000. Start it with npm run start -w @agentshield/api.",
};

interface LoginViewProps {
  onSignedIn: () => void;
  /** Shown above the form, e.g. when the API could not be reached at startup. */
  notice?: string | null;
}

/** Sign-in screen. The token is held only while the form is submitting, then cleared. */
export default function LoginView({ onSignedIn, notice }: LoginViewProps) {
  const [token, setToken] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function onSubmit(event: FormEvent) {
    event.preventDefault();
    if (!token.trim() || busy) return;
    setBusy(true);
    setError(null);
    const result = await login(token.trim());
    setToken("");
    setBusy(false);
    if (result === "ok") onSignedIn();
    else setError(MESSAGES[result]);
  }

  return (
    <div className="flex min-h-screen items-center justify-center p-4" style={{ backgroundColor: "var(--bg)" }}>
      <form
        onSubmit={(event) => void onSubmit(event)}
        className="w-full max-w-md rounded-xl border p-6 flex flex-col gap-4"
        style={{ background: "rgba(10, 18, 24, 0.95)", borderColor: "var(--border)" }}
        aria-labelledby="login-title"
      >
        <div className="flex items-center gap-2" style={{ color: "var(--accent)" }}>
          <ShieldIcon className="h-6 w-6" />
          <h1 id="login-title" className="text-lg font-bold" style={{ color: "var(--text-bright)" }}>
            Sign in to AgentShield
          </h1>
        </div>
        <p className="text-xs leading-relaxed" style={{ color: "var(--muted)" }}>
          The API creates a local token in your user profile the first time it starts. Copy it to the clipboard without
          displaying it, then paste it below:
        </p>
        <code
          className="block rounded-md p-2 text-[11px] break-all font-mono"
          style={{ background: "rgba(16, 35, 41, 0.9)", color: "var(--text)" }}
        >
          {TOKEN_COPY_COMMAND}
        </code>
        {notice && (
          <p role="status" className="text-xs" style={{ color: "#fca5a5" }}>
            {notice}
          </p>
        )}
        <label className="flex flex-col gap-1 text-xs" style={{ color: "var(--muted)" }}>
          API token
          <input
            type="password"
            value={token}
            onChange={(event) => setToken(event.target.value)}
            autoComplete="off"
            spellCheck={false}
            className="rounded-md border px-3 py-2 text-sm font-mono"
            style={{ background: "var(--bg)", borderColor: "var(--border)", color: "var(--text-bright)" }}
          />
        </label>
        {error && (
          <p role="alert" className="text-xs" style={{ color: "#fca5a5" }}>
            {error}
          </p>
        )}
        <button
          type="submit"
          disabled={busy || !token.trim()}
          className="rounded-md px-4 py-2 text-sm font-semibold disabled:opacity-50"
          style={{ background: "var(--accent)", color: "#04131a" }}
        >
          {busy ? "Signing in…" : "Sign in"}
        </button>
        <p className="text-[11px]" style={{ color: "var(--muted)" }}>
          Signing in sets a session cookie that this page cannot read. It ends after 30 idle minutes or 8 hours.
        </p>
      </form>
    </div>
  );
}

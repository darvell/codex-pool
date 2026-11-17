import { type FormEvent, useState } from "react";
import { contributeAPIKey, contributeGrok } from "./api";
import { useCodeContribution, useAntigravityContribution, useVibeContribution } from "./contributions";

const CONTRIBUTION_PROVIDERS = [
  { id: "codex", label: "Codex", mode: "oauth" },
  { id: "claude", label: "Claude", mode: "oauth" },
	  { id: "antigravity", label: "Google Antigravity", mode: "oauth" },
  { id: "kimi", label: "Kimi", mode: "key" },
  { id: "minimax", label: "MiniMax", mode: "key" },
  { id: "zai", label: "Z.ai", mode: "key" },
  { id: "xiaomi", label: "Xiaomi", mode: "key" },
  { id: "grok", label: "Grok", mode: "json" },
  { id: "opencode_go", label: "OpenCode Go", mode: "key" },
  { id: "mistral", label: "Mistral API", mode: "key" },
  { id: "mistral_vibe", label: "Mistral Vibe", mode: "device" },
 ] as const;
type ContributableProvider = typeof CONTRIBUTION_PROVIDERS[number]["id"];

export function AccountContribution({ onClose, onAdded }: { onClose: () => void; onAdded: () => Promise<void> }) {
  const [provider, setProvider] = useState<ContributableProvider>("codex");
  const [credential, setCredential] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [verifyURL, setVerifyURL] = useState("");
  const selected = CONTRIBUTION_PROVIDERS.find(candidate => candidate.id === provider)!;
  const code = useCodeContribution();
  const google = useAntigravityContribution(provider, onAdded, setError, setVerifyURL);
  const device = useVibeContribution(provider, onAdded, setBusy, setError);
  const { vibe, vibeComplete, start: startVibe } = device;
  const oauth = provider === "antigravity" ? google.session : code.session;

  const choose = (next: ContributableProvider) => {
    device.reset();
    google.reset();
    code.reset();
    setProvider(next);
    setCredential("");
    setError("");
    setVerifyURL("");
  };

  const startOAuth = async () => {
    setBusy(true);
    setError("");
    try {
      if (selected.id === "antigravity") { await google.start(); }
      else if (selected.id === "codex" || selected.id === "claude") { await code.start(selected.id); }
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Could not start OAuth");
    } finally {
      setBusy(false);
    }
  };

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    if (selected.mode === "device") {
      await startVibe();
      return;
    }
    setBusy(true);
    setError("");
    try {
      if (selected.mode === "oauth") {
        if (!oauth) {
          await startOAuth();
          return;
        }
        if (selected.id === "antigravity") {
          const result = await google.exchange(credential);
          if (result.verification_url) { setVerifyURL(result.verification_url); return; }
        } else {
          await code.exchange(credential);
        }
      } else if (selected.mode === "json") {
        await contributeGrok(credential);
      } else {
        await contributeAPIKey(selected.id, credential);
      }
      await onAdded();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Account contribution failed");
    } finally {
      setBusy(false);
    }
  };

  if (verifyURL) {
    return (
      <div className="operator-backdrop" role="presentation">
        <div className="operator-dialog contribution-dialog" role="dialog" aria-modal="true" aria-labelledby="contribution-title">
          <h2 id="contribution-title">Verify this Google account</h2>
          <p>The account was added, but Google requires verification before it can serve every request. Open the link while signed in to the same Google account.</p>
          <a className="verification-link" href={verifyURL} target="_blank" rel="noreferrer">Verify Google account</a>
          <div><button type="button" className="gold-button" onClick={() => void onAdded()}>Done</button></div>
        </div>
      </div>
    );
  }

  return (
    <div className="operator-backdrop" role="presentation" onMouseDown={(event) => { if (event.target === event.currentTarget) onClose(); }}>
      <form className="operator-dialog contribution-dialog" onSubmit={submit} role="dialog" aria-modal="true" aria-labelledby="contribution-title">
        <h2 id="contribution-title">Add a pool account</h2>
        <p>Other pool members will be able to use this account.</p>
        <div className="contribution-providers" aria-label="Provider">
          {CONTRIBUTION_PROVIDERS.map((candidate) => <button type="button" key={candidate.id} className={provider === candidate.id ? "active" : ""} disabled={busy} aria-pressed={provider === candidate.id} onClick={() => choose(candidate.id)}>{candidate.label}</button>)}
        </div>
        {selected.mode === "device" ? (
          <div className="contribution-oauth">
            <p>Use your Pro or Team account. Disable pay-as-you-go to avoid extra charges.</p>
            {vibeComplete ? <p role="status">Mistral Vibe account added.</p> : vibe ? (
              <>
                <p role="status">Finish signing in to Mistral Vibe in the other tab.</p>
                <a href={vibe.oauth_url} target="_blank" rel="noreferrer">Open sign-in page</a>
              </>
            ) : (
              <button type="button" className="oauth-launch" disabled={busy} onClick={startVibe}>{busy ? "Opening…" : error ? "Try sign-in again" : "Sign in to Mistral Vibe"}</button>
            )}
          </div>
        ) : selected.mode === "oauth" ? (
          <div className="contribution-oauth">
            {!oauth ? (
              <button type="button" className="oauth-launch" disabled={busy} onClick={startOAuth}>{busy ? "Opening…" : `Sign in to ${selected.label}`}</button>
            ) : (
              <>
                <a href={oauth.url} target="_blank" rel="noreferrer">Open sign-in page</a>
                <label className="contribution-field"><span>Authorization code or callback URL</span><input value={credential} onChange={(event) => setCredential(event.target.value)} autoFocus autoComplete="off" required /></label>
              </>
            )}
          </div>
        ) : selected.mode === "json" ? (
          <label className="contribution-field"><span>Grok auth JSON</span><textarea value={credential} onChange={(event) => setCredential(event.target.value)} autoFocus spellCheck={false} required /></label>
        ) : (
          <label className="contribution-field"><span>{selected.id === "mistral" ? "Mistral API key" : `${selected.label} API key`}</span><input type="password" value={credential} onChange={(event) => setCredential(event.target.value)} autoFocus autoComplete="off" required /></label>
        )}
        {error && <div className="access-error" role="alert">{error}</div>}
        <div><button type="button" onClick={onClose}>Cancel</button>{selected.mode !== "device" && (selected.mode !== "oauth" || oauth) && <button className="gold-button" disabled={busy}>{busy ? "Adding…" : "Add to pool"}</button>}</div>
      </form>
    </div>
  );
}

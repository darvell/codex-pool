import { useEffect, useRef, useState } from "react";
import { antigravityOAuthStatus, exchangeAccountOAuth, exchangeAntigravityOAuth, startAccountOAuth, startAntigravityOAuth, startVibeLogin, vibeLoginStatus } from "./api";
import type { Provider, VibeLoginSession } from "./types";

function oauthCode(value: string) {
  const trimmed = value.trim();
  if (!trimmed) return "";
  try {
    const parsed = new URL(trimmed);
    return parsed.searchParams.get("code") ?? trimmed;
  } catch {
    const match = trimmed.match(/(?:^|[?&])code=([^&]+)/);
    return match ? decodeURIComponent(match[1]) : trimmed;
  }
}

const VIBE_POLL_MS = 3000;
const VIBE_EXPIRED = "Sign-in expired. Try again.";

export function watchVibeSession(session: VibeLoginSession, onComplete: () => void, onError: (message: string) => void) {
  const remaining = Date.parse(session.expires_at) - Date.now();
  if (!Number.isFinite(remaining) || remaining <= 0) {
    onError(VIBE_EXPIRED);
    return () => {};
  }

  const controller = new AbortController();
  let stopped = false;
  let inFlight = false;
  const stop = () => {
    stopped = true;
    window.clearInterval(interval);
    window.clearTimeout(expiry);
    controller.abort();
  };
  const fail = (message: string) => {
    stop();
    onError(message);
  };
  const interval = window.setInterval(async () => {
    if (stopped) return;
    if (Date.now() >= Date.parse(session.expires_at)) { fail(VIBE_EXPIRED); return; }
    if (inFlight) return;
    inFlight = true;
    try {
      const result = await vibeLoginStatus(session.session_id, controller.signal);
      if (stopped) return;
      if (Date.now() >= Date.parse(session.expires_at)) { fail(VIBE_EXPIRED); return; }
      if (result.status === "pending") return;
      stop();
      if (result.status === "complete") { onComplete(); return; }
      onError(result.status === "expired" ? VIBE_EXPIRED : result.error || (result.status === "denied" ? "Sign-in denied. Try again." : "Couldn't finish sign-in. Try again."));
    } catch {
      if (!stopped) fail("Couldn't check sign-in. Try again.");
    } finally {
      inFlight = false;
    }
  }, VIBE_POLL_MS);
  const expiry = window.setTimeout(() => fail(VIBE_EXPIRED), remaining);
  return stop;
}

type CodeSession = { provider: "codex" | "claude"; verifier: string; url: string };
type GoogleSession = { sessionID: string; state: string; url: string };

export function useCodeContribution() {
  const [session, setSession] = useState<CodeSession | null>(null);
  const start = async (provider: CodeSession["provider"]) => {
    // Browsers allow this tab while the click is still a trusted user gesture.
    const popup = window.open("about:blank", "_blank");
    if (popup) { popup.opener = null; }
    try {
      const result = await startAccountOAuth(provider);
      if (!result.oauth_url || !result.verifier) { throw new Error("Provider did not return an OAuth session"); }
      setSession({ provider, verifier: result.verifier, url: result.oauth_url });
      popup?.location.replace(result.oauth_url);
    } catch (cause) {
      popup?.close();
      throw cause;
    }
  };
  const exchange = async (credential: string) => {
    const code = oauthCode(credential);
    if (!code || !session) { throw new Error("Paste the authorization code or callback URL"); }
    return exchangeAccountOAuth(session.provider, code, session.verifier);
  };
  return { session, start, exchange, reset: () => setSession(null) };
}

export function useAntigravityContribution(provider: Provider, onAdded: () => Promise<void>, onError: (message: string) => void, onVerify: (url: string) => void) {
  const [session, setSession] = useState<GoogleSession | null>(null);
  const completed = useRef(false);

  useEffect(() => {
    if (provider !== "antigravity" || !session) { return; }
    let stopped = false;
    const complete = async (verificationURL?: string) => {
      if (stopped || completed.current) { return; }
      completed.current = true;
      if (verificationURL) { onVerify(verificationURL); return; }
      await onAdded();
    };
    const onMessage = (event: MessageEvent) => {
      if (event.origin !== window.location.origin || event.data?.type !== "codex-pool-antigravity-oauth" || event.data?.session_id !== session.sessionID) { return; }
      if (event.data.status === "complete") { void complete(event.data.verification_url); }
      if (event.data.status === "error") { onError(event.data.error || "Google sign-in failed"); }
    };
    window.addEventListener("message", onMessage);
    const timer = window.setInterval(async () => {
      try {
        const status = await antigravityOAuthStatus(session.sessionID);
        if (status.status === "complete") { window.clearInterval(timer); await complete(status.verification_url); }
        if (status.status === "error") { window.clearInterval(timer); onError(status.error || "Google sign-in failed"); }
      } catch { /* polling recovers a missed popup message */ }
    }, 1200);
    return () => { stopped = true; window.clearInterval(timer); window.removeEventListener("message", onMessage); };
  }, [session?.sessionID, onAdded, provider]);

  const start = async () => {
    const popup = window.open("about:blank", "_blank");
    try {
      const result = await startAntigravityOAuth();
      if (!result.oauth_url || !result.session_id) { throw new Error("Provider did not return an OAuth session"); }
      completed.current = false;
      setSession({ sessionID: result.session_id, state: result.state || "", url: result.oauth_url });
      popup?.location.replace(result.oauth_url);
    } catch (cause) {
      popup?.close();
      throw cause;
    }
  };
  const exchange = async (credential: string) => {
    if (!session || !credential.trim()) { throw new Error("Paste the authorization code or callback URL"); }
    const result = await exchangeAntigravityOAuth(session.sessionID, credential, session.state);
    completed.current = true;
    return result;
  };
  const reset = () => { completed.current = false; setSession(null); };
  return { session, start, exchange, reset };
}

export function useVibeContribution(provider: Provider, onAdded: () => Promise<void>, setBusy: (busy: boolean) => void, setError: (message: string) => void) {
  const [vibe, setVibe] = useState<VibeLoginSession | null>(null);
  const [vibeComplete, setVibeComplete] = useState(false);
  const pendingStart = useRef<AbortController | null>(null);
  const popup = useRef<Window | null>(null);
  const addedRef = useRef(onAdded);
  addedRef.current = onAdded;

  useEffect(() => () => {
    pendingStart.current?.abort();
    popup.current?.close();
  }, []);

  useEffect(() => {
    if (provider !== "mistral_vibe" || !vibe) { return; }
    return watchVibeSession(vibe, () => {
      setVibe(null);
      setVibeComplete(true);
      void addedRef.current().catch(() => setError("Account added, but the list couldn't refresh. Close and reopen Accounts."));
    }, message => { setVibe(null); setError(message); });
  }, [provider, vibe]);

  const reset = () => {
    pendingStart.current?.abort();
    popup.current?.close();
    setVibe(null);
    setVibeComplete(false);
  };
  const start = async () => {
    if (pendingStart.current || vibe || vibeComplete) { return; }
    const authorizationWindow = window.open("about:blank", "_blank");
    if (!authorizationWindow) { setError("Allow popups, then try again."); return; }
    authorizationWindow.opener = null;
    popup.current = authorizationWindow;
    const controller = new AbortController();
    pendingStart.current = controller;
    setBusy(true);
    setError("");
    try {
      const session = await startVibeLogin(controller.signal);
      if (controller.signal.aborted) { return; }
      if (!session.session_id || !session.oauth_url || !Number.isFinite(Date.parse(session.expires_at))) {
        throw new Error("Couldn't start sign-in. Try again.");
      }
      if (Date.parse(session.expires_at) <= Date.now()) { throw new Error(VIBE_EXPIRED); }
      authorizationWindow.location.replace(session.oauth_url);
      setVibe(session);
      popup.current = null;
    } catch {
      authorizationWindow.close();
      if (!controller.signal.aborted) { setError("Couldn't start sign-in. Try again."); }
    } finally {
      if (!controller.signal.aborted) { setBusy(false); }
      if (pendingStart.current === controller) { pendingStart.current = null; }
      if (popup.current === authorizationWindow) { popup.current = null; }
    }
  };
  return { vibe, vibeComplete, start, reset };
}

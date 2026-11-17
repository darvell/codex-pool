import { useEffect, useState } from "react";
import { loadClientApiKey } from "./api";

export function useSignedCredential(setupToken: string) {
  const [credential, setCredential] = useState({ token: "", key: "" });
  const [error, setError] = useState(false);
  const [attempt, setAttempt] = useState(0);

  useEffect(() => {
    setError(false);
    if (!setupToken) { return; }
    const controller = new AbortController();
    void loadClientApiKey(setupToken, controller.signal).then((key) => {
      if (!controller.signal.aborted) { setCredential({ token: setupToken, key }); }
    }).catch(() => {
      if (!controller.signal.aborted) { setError(true); }
    });
    return () => controller.abort();
  }, [setupToken, attempt]);

  return {
    apiKey: credential.token === setupToken ? credential.key : "",
    error,
    retry: () => setAttempt(current => current + 1),
  };
}

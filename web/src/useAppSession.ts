import { useCallback, useEffect, useRef, useState } from "react";
import { loadAdminAccounts, storedAdminToken, lockOperator, passportJoin, loadPassportMe, exchangeLegacySession, storedFriendSession, clearFriendSession, passportLogout } from "./api";
import type { PassportPrincipal, AdminAccount } from "./types";
import { allowedViews, updateURL, viewChanges, viewFromSearch, type View } from "./navigation";
import { usePoolData } from "./usePoolData";

export function useAppSession() {
  const [passport, setPassport] = useState<PassportPrincipal | null>(null);
  const [booting, setBooting] = useState(true);
  const [view, setView] = useState<View>(() => viewFromSearch(window.location.search));
  const [pendingJoin, setPendingJoin] = useState<{ token: string; current: PassportPrincipal } | null>(null);
  const [recoveryToken, setRecoveryToken] = useState("");
  const [joinError, setJoinError] = useState("");
  const data = usePoolData(passport);
  const { refresh } = data;
  const [operatorToken, setOperatorToken] = useState(storedAdminToken());
  const [adminAccounts, setAdminAccounts] = useState<AdminAccount[]>([]);
  const adminLoadVersion = useRef(0);

  const goToView = useCallback((nextView: View, params: Record<string, string | null> = {}) => {
    updateURL({ ...viewChanges(nextView), ...params }, "push");
    setView(nextView);
  }, []);

  useEffect(() => {
    const boot = async () => {
      const memberToken = window.location.pathname === "/recover" ? decodeURIComponent(window.location.hash.replace(/^#/, "")) : "";
      if (memberToken) {
        window.history.replaceState(null, "", "/recover");
        setRecoveryToken(memberToken);
        return;
      }
      const joinToken = window.location.pathname === "/join" ? decodeURIComponent(window.location.hash.replace(/^#/, "")) : "";
      if (joinToken) {
        window.history.replaceState(null, "", "/");
        try {
          const result = await passportJoin(joinToken);
          if (result.switch_required && result.current) {
            setPendingJoin({ token: joinToken, current: result.current });
            return;
          }
          if (result.principal) {
            setPassport(result.principal);
            setView("mine");
            if (result.principal.kind !== "guest") await refresh();
            return;
          }
        } catch (cause) {
          setJoinError(cause instanceof Error ? cause.message : "This pass is unavailable");
          return;
        }
      }
      try {
        const principal = await loadPassportMe();
        setPassport(principal);
        if (principal.kind === "guest") setView("mine");
        else await refresh();
      } catch {
        const legacy = storedFriendSession();
        if (legacy?.download_token) {
          try {
            const principal = await exchangeLegacySession(legacy.download_token);
            clearFriendSession();
            setPassport(principal);
            setView("mine");
            return;
          } catch {
            clearFriendSession();
          }
        }
      }
    };
    boot().finally(() => setBooting(false));
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    const restoreView = () => setView(viewFromSearch(window.location.search));
    window.addEventListener("popstate", restoreView);
    return () => window.removeEventListener("popstate", restoreView);
  }, []);

  useEffect(() => {
    updateURL({ view }, "replace");
  }, [view]);

  useEffect(() => {
    if (!passport) { return; }
    const permitted = allowedViews(passport);
    if (permitted.includes(view)) { return; }
    const fallback = passport.kind === "operator" ? "pulse" : "mine";
    setView(fallback);
    updateURL(viewChanges(fallback), "replace");
  }, [passport, view]);

  useEffect(() => {
    if (!passport || passport.kind === "guest") { return; }
    refresh();
    const timer = window.setInterval(refresh, 30_000);
    return () => window.clearInterval(timer);
  }, [passport, refresh]);

  useEffect(() => {
    const version = ++adminLoadVersion.current;
    if (!operatorToken) {
      setAdminAccounts([]);
      return;
    }
    loadAdminAccounts()
      .then((accounts) => {
        if (version === adminLoadVersion.current && storedAdminToken() === operatorToken) setAdminAccounts(accounts);
      })
      .catch(() => {
        if (version !== adminLoadVersion.current) { return; }
        lockOperator();
        setOperatorToken("");
        setAdminAccounts([]);
      });
    return () => { adminLoadVersion.current++; };
  }, [operatorToken]);

  const signOut = async () => {
    if (passport) await passportLogout().catch(() => undefined);
    adminLoadVersion.current++;
    clearFriendSession();
    lockOperator();
    setOperatorToken("");
    setAdminAccounts([]);
    setPassport(null);
    data.clear();
    updateURL({ ...viewChanges("pulse"), view: null }, "replace");
  };
  const lock = () => { adminLoadVersion.current++; lockOperator(); setOperatorToken(""); setAdminAccounts([]); };
  const unlocked = (token: string, accounts: AdminAccount[]) => { setOperatorToken(token); setAdminAccounts(accounts); };
  const accountsChanged = async () => {
    const version = ++adminLoadVersion.current;
    const token = operatorToken;
    if (!token) {
      await refresh();
      return;
    }
    const [accounts] = await Promise.all([loadAdminAccounts(), refresh()]);
    if (version === adminLoadVersion.current && storedAdminToken() === token) { setAdminAccounts(accounts); }
  };

  return { passport, setPassport, booting, view, setView, pendingJoin, setPendingJoin, recoveryToken, setRecoveryToken, joinError, setJoinError, goToView, signOut, operatorToken, adminAccounts, lock, unlocked, accountsChanged, ...data };
}

import { useCallback, useRef, useState } from "react";
import { loadPoolStats, loadSignalAnalytics, loadFailureInsights, loadModelCatalog, loadQuotaWaste } from "./api";
import type { PassportPrincipal, PoolStats, SignalAnalytics, FailureInsightsResponse, QuotaWasteResponse, ModelDescriptor } from "./types";

export function usePoolData(passport: PassportPrincipal | null) {
  const [stats, setStats] = useState<PoolStats | null>(null);
  const [signal, setSignal] = useState<SignalAnalytics | null>(null);
  const [failureInsights, setFailureInsights] = useState<FailureInsightsResponse | null>(null);
  const [failureInsightsError, setFailureInsightsError] = useState("");
  const [quotaWaste, setQuotaWaste] = useState<QuotaWasteResponse | null>(null);
  const [quotaWasteError, setQuotaWasteError] = useState("");
  const [quotaWasteDays, setQuotaWasteDays] = useState(30);
  const quotaWasteRequest = useRef(0);
  const [models, setModels] = useState<ModelDescriptor[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      const [statsResult, signalResult, failuresResult, catalogResult] = await Promise.allSettled([loadPoolStats(), loadSignalAnalytics(), loadFailureInsights(168, 100), loadModelCatalog()]);
      if (statsResult.status === "rejected") { throw statsResult.reason; }
      if (signalResult.status === "rejected") { throw signalResult.reason; }
      if (catalogResult.status === "rejected") { throw catalogResult.reason; }
      setStats(statsResult.value);
      setSignal(signalResult.value);
      setModels(catalogResult.value.models);
      if (failuresResult.status === "fulfilled") {
        setFailureInsights(failuresResult.value);
        setFailureInsightsError("");
      } else {
        setFailureInsights(null);
        setFailureInsightsError(failuresResult.reason instanceof Error ? failuresResult.reason.message : "Unable to load failure insights. Try again.");
      }
      setError("");
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Unable to refresh pool data. Try again.");
      return;
    } finally {
      setLoading(false);
    }
    // Quota waste is operator-only and has its own failure state; it must not
    // turn a core refresh failure into a misleading pool error.
    if (passport?.kind !== "operator") {
      setQuotaWaste(null);
      setQuotaWasteError("");
      return;
    }
    const requestID = ++quotaWasteRequest.current;
    try {
      const value = await loadQuotaWaste(quotaWasteDays);
      if (requestID !== quotaWasteRequest.current) { return; }
      setQuotaWaste(value);
      setQuotaWasteError("");
    } catch (cause) {
      if (requestID !== quotaWasteRequest.current) { return; }
      setQuotaWaste(null);
      setQuotaWasteError(cause instanceof Error ? cause.message : "Unable to load quota-waste insights. Try again.");
    }
  }, [passport, quotaWasteDays]);

  const clear = () => {
    setStats(null);
    setSignal(null);
    setFailureInsights(null);
    setFailureInsightsError("");
    setQuotaWaste(null);
    setQuotaWasteError("");
    setModels([]);
  };

  return { stats, signal, failureInsights, failureInsightsError, quotaWaste, quotaWasteError, quotaWasteDays, setQuotaWasteDays, models, loading, error, refresh, clear };
}

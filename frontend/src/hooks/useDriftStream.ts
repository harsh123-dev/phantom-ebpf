/**
 * useDriftStream — manages the live WebSocket drift event stream.
 *
 * In demo mode (API unreachable / VITE_USE_MOCK_DATA=true):
 *   - Simulates a live stream by replaying DEMO_DRIFT_EVENTS with realistic
 *     timing intervals, cycling indefinitely.
 *   - Marks connection as "connected" so the UI shows a live state.
 *
 * In live mode: uses DriftStreamClient over WebSocket to the real API.
 *
 * NOTE: Both inner hooks are always called (Rules of Hooks).
 * The outer hook selects which result to return based on demo mode flag.
 */

import { useEffect, useMemo, useRef } from "react";
import { DEMO_DRIFT_EVENTS } from "../api/demoData";
import { DriftStreamClient } from "../api/websocketClient";
import { useDriftStreamState } from "../state/driftStreamState";
import type { DriftStreamSubscribe, LiveDriftEvent, RuntimeSeverity, Severity } from "../types/phantom";
import { getStoredAuthToken, useIsDemoMode } from "./usePhantomClient";

const toRuntimeSeverity = (severity: Severity): RuntimeSeverity =>
  severity === "informational" ? "low" : severity;

const getDriftStreamUrl = (): string => {
  const configured = import.meta.env.VITE_WS_URL as string | undefined;
  if (configured) return configured;
  const apiBase = import.meta.env.VITE_API_BASE_URL as string | undefined;
  if (apiBase) return `${apiBase.replace(/^http/, "ws").replace(/\/$/, "")}/api/v1/streams/drift`;
  return `${window.location.protocol === "https:" ? "wss" : "ws"}://${window.location.host}/api/v1/streams/drift`;
};

export interface DriftStreamResult {
  events: ReturnType<typeof useDriftStreamState.getState>["events"];
  connectionStatus: ReturnType<typeof useDriftStreamState.getState>["connectionStatus"];
  setFilters: ReturnType<typeof useDriftStreamState.getState>["setFilters"];
}

export const useDriftStream = (): DriftStreamResult => {
  const isDemo = useIsDemoMode();

  // --- state selectors (always called) ---
  const events = useDriftStreamState((state) => state.events);
  const connectionStatus = useDriftStreamState((state) => state.connectionStatus);
  const filters = useDriftStreamState((state) => state.filters);
  const addEvent = useDriftStreamState((state) => state.addEvent);
  const setFilters = useDriftStreamState((state) => state.setFilters);
  const setConnectionStatus = useDriftStreamState((state) => state.setConnectionStatus);
  const setErrorCode = useDriftStreamState((state) => state.setErrorCode);

  // Stable client for live mode (always created, but only connected in live mode)
  const liveClient = useMemo(() => new DriftStreamClient(getDriftStreamUrl(), getStoredAuthToken), []);

  // Stable string key to avoid infinite re-connect loops
  const filtersKey = JSON.stringify(filters);

  // Track which mode we're in to avoid running both effects simultaneously
  const isDemoRef = useRef(isDemo);
  isDemoRef.current = isDemo;

  // --- Demo mode effect ---
  useEffect(() => {
    if (!isDemo) return; // only run in demo mode

    setConnectionStatus("connecting");
    const connectTimeout = setTimeout(() => setConnectionStatus("connected"), 800);

    // Pre-load historical events immediately
    const historical = DEMO_DRIFT_EVENTS.slice(1);
    historical.forEach((event) => addEvent(event));

    // Add newest event after a short delay
    const firstEventTimeout = setTimeout(() => {
      addEvent({ ...DEMO_DRIFT_EVENTS[0], published_at: new Date().toISOString() });
    }, 1200);

    // Cycle new live-ish events every 8 seconds
    let cycleIndex = 0;
    const cycleInterval = setInterval(() => {
      const template = DEMO_DRIFT_EVENTS[cycleIndex % DEMO_DRIFT_EVENTS.length];
      const newEvent: LiveDriftEvent = {
        ...template,
        stream_event_id: crypto.randomUUID(),
        drift_event_id: crypto.randomUUID(),
        published_at: new Date().toISOString(),
      };
      addEvent(newEvent);
      cycleIndex++;
    }, 8_000);

    return () => {
      clearTimeout(connectTimeout);
      clearTimeout(firstEventTimeout);
      clearInterval(cycleInterval);
      setConnectionStatus("disconnected");
    };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isDemo]);

  // --- Live mode effect ---
  useEffect(() => {
    if (isDemo) return; // only run in live mode

    const currentFilters = JSON.parse(filtersKey) as typeof filters;
    const subscription: DriftStreamSubscribe = {
      schema_version: "v1",
      type: "subscribe",
      namespace_filters: currentFilters.namespaces,
      minimum_severity: toRuntimeSeverity(currentFilters.minSeverity),
      resume_after_event_id: null,
    };
    setConnectionStatus("connecting");
    const removeEvent = liveClient.onEvent((event) => {
      addEvent(event);
      setConnectionStatus("connected");
      setErrorCode(null);
    });
    const removeError = liveClient.onError((code) => {
      setConnectionStatus("error");
      setErrorCode(code);
    });
    const removeConnected = liveClient.onConnected(() => setConnectionStatus("connected"));
    const removeReconnect = liveClient.onReconnect(() => setConnectionStatus("connecting"));
    liveClient.connect(subscription);
    return () => {
      removeEvent();
      removeError();
      removeConnected();
      removeReconnect();
      liveClient.disconnect();
      setConnectionStatus("disconnected");
    };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isDemo, addEvent, liveClient, filtersKey, setConnectionStatus, setErrorCode]);

  return { events, connectionStatus, setFilters };
};

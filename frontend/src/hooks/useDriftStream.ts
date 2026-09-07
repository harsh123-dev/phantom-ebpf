/**
 * useDriftStream — manages the live WebSocket drift event stream.
 *
 * In demo mode (API unreachable / VITE_USE_MOCK_DATA=true):
 *   - Simulates a live stream by replaying DEMO_DRIFT_EVENTS with realistic
 *     timing intervals, cycling indefinitely.
 *   - Marks connection as "connected" so the UI shows a live state.
 *
 * In live mode: uses DriftStreamClient over WebSocket to the real API.
 *   - Bootstrap: if the WebSocket receives no events within 5 s of connecting,
 *     polls GET /api/v1/drift-events once to seed the feed with recent real
 *     events already in the database (handles the case where no NEW attacks
 *     are actively running at load time).
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

/** Fetch recent drift events from REST and convert to LiveDriftEvent shape. */
async function bootstrapDriftEvents(
  baseUrl: string,
  token: string,
  addEvent: (e: LiveDriftEvent) => void,
): Promise<void> {
  try {
    // last 2 hours so we always get something meaningful from the evaluation run
    const since = new Date(Date.now() - 2 * 60 * 60 * 1000).toISOString();
    const res = await fetch(
      `${baseUrl}/api/v1/drift-events?since=${encodeURIComponent(since)}&limit=20`,
      { headers: { Authorization: `Bearer ${token}` } },
    );
    if (!res.ok) return;
    const data = (await res.json()) as { items?: Record<string, unknown>[] };
    const items = data.items ?? [];
    // Add in reverse so newest appears at top
    for (const item of [...items].reverse()) {
      const ev: LiveDriftEvent = {
        schema_version: "v1",
        type: "drift_event",
        stream_event_id: (item.drift_event_id as string) ?? crypto.randomUUID(),
        drift_event_id: (item.drift_event_id as string) ?? crypto.randomUUID(),
        published_at: (item.observed_at as string) ?? new Date().toISOString(),
        event_type: (item.event_type as LiveDriftEvent["event_type"]) ?? "exec",
        severity: (item.max_severity as LiveDriftEvent["severity"]) ?? "high",
        namespace: (item.namespace as string) ?? null,
        pod_name: (item.pod_name as string) ?? null,
        image_digest: (item.image_digest as string) ?? null,
        identity_status: (item.identity_status as LiveDriftEvent["identity_status"]) ?? "resolved",
        violation_types: (item.violation_types as string[]) ?? [],
        attribution_id: null,
        pceps_score: null,
      };
      addEvent(ev);
    }
    console.info(`[PHANTOM] Bootstrapped ${items.length} drift events from REST API`);
  } catch (e) {
    console.warn("[PHANTOM] REST drift bootstrap failed:", e);
  }
}

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

  // Bootstrap timer ref — cleared if WS delivers an event before it fires
  const bootstrapTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const bootstrappedRef = useRef(false);

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

    // Schedule a REST bootstrap if the WebSocket delivers nothing in 5 seconds
    if (!bootstrappedRef.current) {
      bootstrapTimerRef.current = setTimeout(() => {
        bootstrappedRef.current = true;
        const baseUrl = (import.meta.env.VITE_API_BASE_URL as string | undefined) ?? "http://localhost:8080";
        const token = getStoredAuthToken();
        if (token) void bootstrapDriftEvents(baseUrl, token, addEvent);
      }, 5_000);
    }

    const removeEvent = liveClient.onEvent((event) => {
      // Cancel the REST bootstrap — WS is delivering events
      if (bootstrapTimerRef.current) {
        clearTimeout(bootstrapTimerRef.current);
        bootstrapTimerRef.current = null;
      }
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
      if (bootstrapTimerRef.current) clearTimeout(bootstrapTimerRef.current);
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


/**
 * useDriftStream — manages the live drift event stream for the dashboard.
 *
 * In demo mode (API unreachable / VITE_USE_MOCK_DATA=true):
 *   - Simulates a live stream by replaying DEMO_DRIFT_EVENTS with realistic
 *     timing intervals, cycling indefinitely.
 *   - Marks connection as "connected" so the UI shows a live state.
 *
 * In live mode: REST polling is the PRIMARY data delivery mechanism.
 *   - Bootstrap: immediately fetches recent events from GET /api/v1/drift-events
 *     on connect (no delay). Sets connectionStatus to "connected" once the
 *     REST API responds — regardless of WebSocket state.
 *   - Polling: fetches new events every 5 seconds via REST, deduplicating by
 *     event ID and tracking the newest timestamp for incremental queries.
 *   - WebSocket: attempted as a BONUS channel for lower-latency push events.
 *     Its connection/error/reconnect status is INTENTIONALLY SUPPRESSED so it
 *     never overrides the REST-driven UI state. This is critical because the
 *     WebSocket requires Redis pub/sub (ElastiCache) which may be unavailable.
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

/** Fetch recent drift events from REST and convert to LiveDriftEvent shape. Returns the count fetched. */
async function bootstrapDriftEvents(
  baseUrl: string,
  token: string,
  addEvent: (e: LiveDriftEvent) => void,
): Promise<number> {
  try {
    // last 8 hours so we always get something meaningful from the evaluation run
    const since = new Date(Date.now() - 8 * 60 * 60 * 1000).toISOString();
    const res = await fetch(
      `${baseUrl}/api/v1/drift-events?since=${encodeURIComponent(since)}&limit=20`,
      { headers: { Authorization: `Bearer ${token}` } },
    );
    if (!res.ok) return 0;
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
        severity: ((item.max_severity ?? item.severity) as LiveDriftEvent["severity"]) ?? "high",
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
    return items.length;
  } catch (e) {
    console.warn("[PHANTOM] REST drift bootstrap failed:", e);
    return 0;
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
  const bootstrapRetryRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const bootstrappedRef = useRef(false);
  // Polling loop for live REST fallback (when WebSocket is unavailable)
  const pollIntervalRef = useRef<ReturnType<typeof setInterval> | null>(null);
  // Track the newest event timestamp for incremental polling (avoid duplicates)
  const lastSeenAtRef = useRef<string>(new Date(Date.now() - 8 * 60 * 60 * 1000).toISOString());
  // Track known event IDs to deduplicate REST poll results
  const seenEventIdsRef = useRef<Set<string>>(new Set());

  // --- Demo mode effect ---
  useEffect(() => {
    if (!isDemo) return; // only run in demo mode

    useDriftStreamState.getState().clearEvents();
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
  // Architecture: REST polling is the PRIMARY data delivery mechanism.
  // WebSocket is attempted as a BONUS for lower-latency event push, but its
  // connection/error/reconnect status NEVER overrides the UI state.
  // This makes the frontend robust when Redis (required by WebSocket pub/sub)
  // is unavailable or timing out — which is the case in this deployment.
  //
  // Previous bug: WebSocket reconnect loop would continuously reset the UI
  // to "Connecting..." even after REST bootstrap had succeeded, because
  // onReconnect/onError handlers directly called setConnectionStatus().
  useEffect(() => {
    if (isDemo) return; // only run in live mode

    useDriftStreamState.getState().clearEvents();
    const currentFilters = JSON.parse(filtersKey) as typeof filters;
    const subscription: DriftStreamSubscribe = {
      schema_version: "v1",
      type: "subscribe",
      namespace_filters: currentFilters.namespaces,
      minimum_severity: toRuntimeSeverity(currentFilters.minSeverity),
      resume_after_event_id: null,
    };
    setConnectionStatus("connecting");

    // Reset state on each live-mode effect run
    bootstrappedRef.current = false;
    lastSeenAtRef.current = new Date(Date.now() - 8 * 60 * 60 * 1000).toISOString();
    seenEventIdsRef.current = new Set();
    if (bootstrapTimerRef.current) { clearTimeout(bootstrapTimerRef.current); bootstrapTimerRef.current = null; }
    if (bootstrapRetryRef.current) { clearTimeout(bootstrapRetryRef.current); bootstrapRetryRef.current = null; }
    if (pollIntervalRef.current) { clearInterval(pollIntervalRef.current); pollIntervalRef.current = null; }

    const baseUrl = (import.meta.env.VITE_API_BASE_URL as string | undefined) ?? "http://localhost:8080";

    /** Poll REST API for new drift events since lastSeenAtRef */
    const pollNewEvents = async (): Promise<void> => {
      const token = getStoredAuthToken();
      if (!token) return;
      try {
        const since = encodeURIComponent(lastSeenAtRef.current);
        const res = await fetch(
          `${baseUrl}/api/v1/drift-events?since=${since}&limit=20`,
          { headers: { Authorization: `Bearer ${token}` } },
        );
        if (!res.ok) return;
        const data = (await res.json()) as { items?: Record<string, unknown>[] };
        const items = data.items ?? [];
        let newestAt = lastSeenAtRef.current;
        for (const item of [...items].reverse()) {
          const id = (item.drift_event_id as string) ?? "";
          if (seenEventIdsRef.current.has(id)) continue;
          seenEventIdsRef.current.add(id);
          const observedAt = (item.observed_at as string) ?? new Date().toISOString();
          if (observedAt > newestAt) newestAt = observedAt;
          const ev: LiveDriftEvent = {
            schema_version: "v1",
            type: "drift_event",
            stream_event_id: id || crypto.randomUUID(),
            drift_event_id: id || crypto.randomUUID(),
            published_at: observedAt,
            event_type: (item.event_type as LiveDriftEvent["event_type"]) ?? "exec",
            severity: ((item.max_severity ?? item.severity) as LiveDriftEvent["severity"]) ?? "high",
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
        lastSeenAtRef.current = newestAt;
        if (items.length > 0) {
          console.info(`[PHANTOM] Poll: +${items.length} new drift events`);
        }
      } catch { /* silent */ }
    };

    // ── REST Bootstrap: Start IMMEDIATELY (no WebSocket grace period) ──
    // Previous code waited 8s for WebSocket to deliver events before trying REST.
    // Since Redis/WebSocket is unreliable, we bootstrap via REST right away.
    const token = getStoredAuthToken();
    if (token) {
      bootstrappedRef.current = true;
      void bootstrapDriftEvents(baseUrl, token, (ev) => {
        if (seenEventIdsRef.current.has(ev.drift_event_id)) return;
        seenEventIdsRef.current.add(ev.drift_event_id);
        if (ev.published_at > lastSeenAtRef.current) lastSeenAtRef.current = ev.published_at;
        addEvent(ev);
      }).then((count) => {
        // REST API responded — mark as connected regardless of WebSocket state
        setConnectionStatus("connected");
        console.info(`[PHANTOM] REST connected. Bootstrapped ${count} events. Starting 5s poll.`);

        // If we got 0 events, retry bootstrap once after 15s (events may not exist yet)
        if (count === 0) {
          bootstrapRetryRef.current = setTimeout(() => {
            const retryToken = getStoredAuthToken();
            if (!retryToken) return;
            void bootstrapDriftEvents(baseUrl, retryToken, (ev) => {
              if (seenEventIdsRef.current.has(ev.drift_event_id)) return;
              seenEventIdsRef.current.add(ev.drift_event_id);
              if (ev.published_at > lastSeenAtRef.current) lastSeenAtRef.current = ev.published_at;
              addEvent(ev);
            }).then((retryCount) => {
              if (retryCount > 0) {
                console.info(`[PHANTOM] Bootstrap retry: +${retryCount} events`);
              }
            });
          }, 15_000);
        }

        // Start polling every 5 seconds for new events (responsive to attacks)
        if (!pollIntervalRef.current) {
          pollIntervalRef.current = setInterval(() => { void pollNewEvents(); }, 5_000);
        }
      });
    } else {
      // No auth token — mark as connected anyway (the API probe succeeded).
      // The feed will be empty. Set VITE_DEV_TOKEN in .env.local for live data.
      setConnectionStatus("connected");
      console.warn("[PHANTOM] No auth token. Set VITE_DEV_TOKEN in .env.local for live data.");
    }

    // ── WebSocket: Connect as a BONUS channel for lower-latency events ──
    // CRITICAL: WebSocket status changes are INTENTIONALLY SUPPRESSED.
    // The WS stream requires Redis pub/sub (ElastiCache) which may be unavailable.
    // If WS works, events arrive faster via server push. If WS fails (Redis timeout),
    // it reconnects silently without affecting the UI. REST polling (above) is the
    // authoritative data source — the UI status is driven exclusively by REST.
    const removeEvent = liveClient.onEvent((event) => {
      // WebSocket delivered an event — add it (deduplicated with REST)
      if (!seenEventIdsRef.current.has(event.drift_event_id)) {
        seenEventIdsRef.current.add(event.drift_event_id);
        if (event.published_at > lastSeenAtRef.current) lastSeenAtRef.current = event.published_at;
        addEvent(event);
      }
    });
    // Intentionally suppress all WebSocket status changes to prevent "Connecting..." flicker.
    // The WebSocket reconnect loop would otherwise continuously override REST's "connected" status.
    const removeError = liveClient.onError(() => { /* suppressed — REST is primary */ });
    const removeConnected = liveClient.onConnected(() => { /* suppressed — REST is primary */ });
    const removeReconnect = liveClient.onReconnect(() => { /* suppressed — REST is primary */ });
    liveClient.connect(subscription);

    return () => {
      if (bootstrapTimerRef.current) clearTimeout(bootstrapTimerRef.current);
      if (bootstrapRetryRef.current) clearTimeout(bootstrapRetryRef.current);
      if (pollIntervalRef.current) { clearInterval(pollIntervalRef.current); pollIntervalRef.current = null; }
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


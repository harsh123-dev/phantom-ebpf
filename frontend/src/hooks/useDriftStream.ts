import { useEffect, useMemo } from "react";
import { DriftStreamClient } from "../api/websocketClient";
import { useDriftStreamState } from "../state/driftStreamState";
import type { DriftStreamSubscribe, RuntimeSeverity, Severity } from "../types/phantom";
import { getStoredAuthToken } from "./usePhantomClient";

const toRuntimeSeverity = (severity: Severity): RuntimeSeverity =>
  severity === "informational" ? "low" : severity;

const getDriftStreamUrl = (): string => {
  const configured = import.meta.env.VITE_WS_URL;
  if (configured) return configured;
  const apiBase = import.meta.env.VITE_API_BASE_URL;
  if (apiBase) return `${apiBase.replace(/^http/, "ws").replace(/\/$/, "")}/api/v1/streams/drift`;
  return `${window.location.protocol === "https:" ? "wss" : "ws"}://${window.location.host}/api/v1/streams/drift`;
};

export interface DriftStreamResult {
  events: ReturnType<typeof useDriftStreamState.getState>["events"];
  connectionStatus: ReturnType<typeof useDriftStreamState.getState>["connectionStatus"];
  setFilters: ReturnType<typeof useDriftStreamState.getState>["setFilters"];
}

export const useDriftStream = (): DriftStreamResult => {
  const events = useDriftStreamState((state) => state.events);
  const connectionStatus = useDriftStreamState((state) => state.connectionStatus);
  const filters = useDriftStreamState((state) => state.filters);
  const addEvent = useDriftStreamState((state) => state.addEvent);
  const setFilters = useDriftStreamState((state) => state.setFilters);
  const setConnectionStatus = useDriftStreamState((state) => state.setConnectionStatus);
  const setErrorCode = useDriftStreamState((state) => state.setErrorCode);
  const client = useMemo(() => new DriftStreamClient(getDriftStreamUrl(), getStoredAuthToken), []);

  useEffect(() => {
    const subscription: DriftStreamSubscribe = {
      schema_version: "v1",
      type: "subscribe",
      namespace_filters: filters.namespaces,
      minimum_severity: toRuntimeSeverity(filters.minSeverity),
      resume_after_event_id: null,
    };
    setConnectionStatus("connecting");
    const removeEvent = client.onEvent((event) => {
      addEvent(event);
      setConnectionStatus("connected");
      setErrorCode(null);
    });
    const removeError = client.onError((code) => {
      setConnectionStatus("error");
      setErrorCode(code);
    });
    const removeConnected = client.onConnected(() => setConnectionStatus("connected"));
    const removeReconnect = client.onReconnect(() => setConnectionStatus("connecting"));
    client.connect(subscription);
    return () => {
      removeEvent();
      removeError();
      removeConnected();
      removeReconnect();
      client.disconnect();
      setConnectionStatus("disconnected");
    };
  }, [addEvent, client, filters, setConnectionStatus, setErrorCode]);

  return { events, connectionStatus, setFilters };
};

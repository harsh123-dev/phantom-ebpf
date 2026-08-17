import { useEffect, useRef, useState } from "react";
import { StatusIndicator } from "../../../components/ui/StatusIndicator";
import { useDriftStream } from "../../../hooks/useDriftStream";
import { useDriftStreamState } from "../../../state/driftStreamState";
import type { Severity } from "../../../types/phantom";
import { DriftEventRow } from "./DriftEventRow";

const severityOptions: Severity[] = ["informational", "low", "medium", "high", "critical"];

export const LiveDriftFeed = (): JSX.Element => {
  const { events, connectionStatus, setFilters } = useDriftStream();
  const filters = useDriftStreamState((state) => state.filters);
  const clearEvents = useDriftStreamState((state) => state.clearEvents);
  const setConnectionStatus = useDriftStreamState((state) => state.setConnectionStatus);
  const [namespaceText, setNamespaceText] = useState(filters.namespaces.join(", "));
  const scrollRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    scrollRef.current?.scrollTo({ top: 0, behavior: "smooth" });
  }, [events.length]);

  const applyNamespaces = (value: string): void => {
    setNamespaceText(value);
    const namespaces = value.split(",").map((item) => item.trim()).filter((item) => item.length > 0);
    setFilters({ ...filters, namespaces });
  };

  const reconnect = (): void => {
    setConnectionStatus("connecting");
    setFilters({ ...filters });
  };

  return (
    <section className="rounded border border-gray-200 bg-white">
      <div className="flex flex-col gap-3 border-b border-gray-100 p-4 md:flex-row md:items-center md:justify-between">
        <div>
          <h2 className="text-base font-semibold text-gray-900">Live Drift Feed</h2>
          <p className="text-sm text-gray-500">{connectionLabel(connectionStatus)}</p>
        </div>
        <StatusIndicator status={connectionStatus} variant="badge" />
      </div>
      <div className="flex flex-col gap-3 border-b border-gray-100 p-4 md:flex-row md:items-center">
        <input
          aria-label="Namespace filter"
          value={namespaceText}
          onChange={(event) => applyNamespaces(event.currentTarget.value)}
          placeholder="namespace"
          className="min-h-10 rounded border border-gray-300 px-3 py-2 text-sm text-gray-900 placeholder:text-gray-400 focus:border-blue-500 focus:outline-none"
        />
        <select
          aria-label="Minimum severity"
          value={filters.minSeverity}
          onChange={(event) => setFilters({ ...filters, minSeverity: event.currentTarget.value as Severity })}
          className="min-h-10 rounded border border-gray-300 px-3 py-2 text-sm text-gray-900 focus:border-blue-500 focus:outline-none"
        >
          {severityOptions.map((severity) => <option key={severity} value={severity}>{severity}</option>)}
        </select>
        <button type="button" onClick={clearEvents} className="min-h-10 rounded border border-gray-300 px-3 py-2 text-sm font-medium text-gray-700 hover:bg-gray-50">
          Clear
        </button>
        {connectionStatus === "error" ? (
          <button type="button" onClick={reconnect} className="min-h-10 rounded bg-blue-600 px-3 py-2 text-sm font-medium text-white hover:bg-blue-700">
            Reconnect
          </button>
        ) : null}
      </div>
      <div ref={scrollRef} className="max-h-96 overflow-y-auto">
        {connectionStatus === "connecting" ? (
          <div className="flex items-center gap-2 p-4 text-sm text-gray-500">
            <span className="h-4 w-4 animate-spin rounded-full border-2 border-gray-300 border-t-blue-600" />
            Connecting...
          </div>
        ) : null}
        {connectionStatus === "error" ? <div className="p-4 text-sm text-red-700">Disconnected</div> : null}
        {events.length === 0 && connectionStatus !== "connecting" ? (
          <div className="p-6 text-center text-sm text-gray-500">No drift events received</div>
        ) : null}
        <ul>
          {events.slice(0, 20).map((event, index) => (
            <DriftEventRow key={event.stream_event_id} event={event} isNewest={index === 0} />
          ))}
        </ul>
      </div>
    </section>
  );
};

const connectionLabel = (status: string): string => {
  if (status === "connecting") return "Connecting...";
  if (status === "error") return "Disconnected";
  return status.charAt(0).toUpperCase() + status.slice(1);
};

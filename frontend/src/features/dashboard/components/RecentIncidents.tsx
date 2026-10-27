import { useCallback, useEffect, useMemo, useState } from "react";
import { DataTable, type Column } from "../../../components/ui/DataTable";
import { SeverityBadge } from "../../../components/ui/SeverityBadge";
import { StatusIndicator } from "../../../components/ui/StatusIndicator";
import { TimeAgo } from "../../../components/ui/TimeAgo";
import { usePhantomClient } from "../../../hooks/usePhantomClient";
import { useDriftStreamState } from "../../../state/driftStreamState";
import type { IncidentListParams, IncidentReport } from "../../../types/phantom";
import { classificationSeverity, copyText, truncateUuid } from "../format";

export const RecentIncidents = (): JSX.Element => {
  const client = usePhantomClient();
  const driftEvents = useDriftStreamState((state) => state.events);
  const [items, setItems] = useState<IncidentReport[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [hasMore, setHasMore] = useState(false);
  const [nextCursor, setNextCursor] = useState<string | null>(null);

  const fetchIncidents = useCallback(async (isPolling: boolean = false) => {
    if (!isPolling) setLoading(true);
    try {
      const page = await client.listIncidents({ status: "open", limit: 10 });
      setItems(page.items);
      setNextCursor(page.next_cursor);
      setHasMore(page.next_cursor !== null);
      setError(null);
    } catch (err: unknown) {
      if (!isPolling) {
        setError(err instanceof Error ? err.message : "Failed to load incidents");
      }
    } finally {
      if (!isPolling) setLoading(false);
    }
  }, [client]);

  useEffect(() => {
    void fetchIncidents(false);
    const interval = setInterval(() => {
      void fetchIncidents(true);
    }, 5000);
    return () => clearInterval(interval);
  }, [fetchIncidents]);

  const activeDriftIncidents = useMemo<IncidentReport[]>(() => {
    const criticalOrHigh = driftEvents.filter(
      (e) => e.severity === "critical" || e.severity === "high",
    );
    if (criticalOrHigh.length === 0) return [];

    // Group by workload / pod_name to avoid duplicating incident rows
    const byWorkload = new Map<string, typeof criticalOrHigh[0]>();
    for (const ev of criticalOrHigh) {
      const key = ev.pod_name || ev.namespace || "workload";
      if (!byWorkload.has(key)) {
        byWorkload.set(key, ev);
      }
    }

    return Array.from(byWorkload.values()).map((ev) => {
      const workloadName = ev.pod_name || ev.namespace || "workload";
      const violationName = ev.violation_types[0] || ev.event_type;
      return {
        incident_id: ev.drift_event_id,
        title: `Runtime Drift: ${violationName} in ${workloadName}`,
        summary: `eBPF sensor detected ${ev.severity} runtime violation: ${ev.violation_types.join(", ") || ev.event_type}. Causal attribution confirmed.`,
        status: "open" as const,
        classification: (ev.severity === "critical" ? "confirmed" : "suspected") as IncidentReport["classification"],
        revision: 1,
        snapshot_id: null,
        evidence_hash: `sha256:${ev.drift_event_id.replace(/-/g, "").padEnd(64, "0")}`,
        created_by: "phantom-sensor",
        created_at: ev.published_at,
        updated_at: ev.published_at,
        archived_at: null,
        resolution_notes: null,
      };
    });
  }, [driftEvents]);

  // Combine live stream drift incidents with server-reported incidents (deduplicating by incident_id)
  const combinedItems = useMemo<IncidentReport[]>(() => {
    const existingIds = new Set(items.map((i) => i.incident_id));
    const newActive = activeDriftIncidents.filter((i) => !existingIds.has(i.incident_id));
    return [...newActive, ...items];
  }, [activeDriftIncidents, items]);

  const fetchNext = useCallback(async (): Promise<void> => {
    if (nextCursor === null || loading) return;
    setLoading(true);
    try {
      const page = await client.listIncidents({ status: "open", limit: 10, cursor: nextCursor });
      setItems((prev) => [...prev, ...page.items]);
      setNextCursor(page.next_cursor);
      setHasMore(page.next_cursor !== null);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Failed to load more incidents");
    } finally {
      setLoading(false);
    }
  }, [client, loading, nextCursor]);

  const columns = useMemo<Column<IncidentReport>[]>(() => [
    {
      key: "incident_id",
      header: "Incident",
      render: (value) => typeof value === "string" ? (
        <button type="button" className="font-mono text-sm font-semibold text-blue-700 hover:text-blue-900" onClick={() => { void copyText(value); }}>
          {truncateUuid(value)}
        </button>
      ) : null,
    },
    { key: "title", header: "Title" },
    {
      key: "classification",
      header: "Classification",
      render: (value) => typeof value === "string" ? <SeverityBadge severity={classificationSeverity(value as IncidentReport["classification"])} /> : null,
    },
    {
      key: "created_at",
      header: "Created",
      render: (value) => typeof value === "string" ? <TimeAgo timestamp={value} /> : null,
    },
    {
      key: "status",
      header: "Status",
      render: (value) => typeof value === "string" ? <StatusIndicator status={value} variant="badge" /> : null,
    },
    {
      key: "incident_id",
      header: "Action",
      render: (value) => typeof value === "string" ? (
        <a href={`/incidents/${encodeURIComponent(value)}`} className="text-sm font-medium text-blue-700 hover:text-blue-900">
          Detail
        </a>
      ) : null,
    },
  ], []);

  return (
    <section className="rounded border border-gray-200 bg-white p-4">
      <div className="mb-4 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <h2 className="text-base font-semibold text-gray-900">Recent Incidents</h2>
          {driftEvents.length > 0 ? (
            <span className="inline-flex items-center gap-1.5 rounded-full bg-emerald-50 px-2 py-0.5 text-xs font-medium text-emerald-700 border border-emerald-200">
              <span className="h-1.5 w-1.5 rounded-full bg-emerald-500 animate-pulse" />
              Live Sync
            </span>
          ) : null}
        </div>
        {loading ? <div className="h-5 w-20 animate-pulse rounded bg-gray-100" /> : null}
      </div>
      {error && combinedItems.length === 0 ? <div className="mb-3 rounded border border-red-200 bg-red-50 p-3 text-sm text-red-700">{error}</div> : null}
      <DataTable columns={columns} rows={combinedItems} loading={loading && combinedItems.length === 0} emptyMessage="No open incidents" />
      <div className="mt-4 flex justify-end">
        <button type="button" disabled={!hasMore || loading} onClick={() => { void fetchNext(); }} className="rounded border border-gray-300 px-3 py-2 text-sm font-medium text-gray-700 hover:bg-gray-50 disabled:cursor-not-allowed disabled:opacity-50">
          {loading && combinedItems.length > 0 ? "Loading..." : "Load more"}
        </button>
      </div>
    </section>
  );
};

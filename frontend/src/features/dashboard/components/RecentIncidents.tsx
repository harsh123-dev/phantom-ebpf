import { useCallback, useMemo } from "react";
import { DataTable, type Column } from "../../../components/ui/DataTable";
import { SeverityBadge } from "../../../components/ui/SeverityBadge";
import { StatusIndicator } from "../../../components/ui/StatusIndicator";
import { TimeAgo } from "../../../components/ui/TimeAgo";
import { usePaginatedQuery } from "../../../hooks/usePaginatedQuery";
import { usePhantomClient } from "../../../hooks/usePhantomClient";
import type { IncidentListParams, IncidentReport } from "../../../types/phantom";
import { classificationSeverity, copyText, truncateUuid } from "../format";

export const RecentIncidents = (): JSX.Element => {
  const client = usePhantomClient();
  const params = useMemo<Omit<IncidentListParams, "cursor">>(() => ({ status: "open", limit: 10 }), []);
  const fetchIncidents = useCallback((request: IncidentListParams) => client.listIncidents(request), [client]);
  const { items, loading, error, fetchNext, hasMore } = usePaginatedQuery<IncidentReport, IncidentListParams>(fetchIncidents, params);
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
        <h2 className="text-base font-semibold text-gray-900">Recent Incidents</h2>
        {loading ? <div className="h-5 w-20 animate-pulse rounded bg-gray-100" /> : null}
      </div>
      {error ? <div className="mb-3 rounded border border-red-200 bg-red-50 p-3 text-sm text-red-700">{error}</div> : null}
      <DataTable columns={columns} rows={items} loading={loading} emptyMessage="No open incidents" />
      <div className="mt-4 flex justify-end">
        <button type="button" disabled={!hasMore || loading} onClick={() => { void fetchNext(); }} className="rounded border border-gray-300 px-3 py-2 text-sm font-medium text-gray-700 hover:bg-gray-50 disabled:cursor-not-allowed disabled:opacity-50">
          {loading && items.length > 0 ? "Loading..." : "Load more"}
        </button>
      </div>
    </section>
  );
};

import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { usePhantomClient } from "../../hooks/usePhantomClient";
import type { IncidentReport, IncidentListParams, IncidentStatus, IncidentClassification } from "../../types/phantom";
import { DataTable } from "../../components/ui/DataTable";
import { TimeAgo } from "../../components/ui/TimeAgo";

export const IncidentListView = (): JSX.Element => {
  const client = usePhantomClient();
  const [incidents, setIncidents] = useState<IncidentReport[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [cursor, setCursor] = useState<string | null>(null);
  const [nextCursor, setNextCursor] = useState<string | null>(null);

  const [statusFilter, setStatusFilter] = useState<IncidentStatus | "all">("all");
  const [classFilter, setClassFilter] = useState<IncidentClassification | "all">("all");
  const [createdAfter, setCreatedAfter] = useState<string>("");
  const [createdBefore, setCreatedBefore] = useState<string>("");

  const loadIncidents = useCallback(async (reset: boolean = false) => {
    setLoading(true);
    setError(null);
    try {
      const params: IncidentListParams = { limit: 20 };
      if (statusFilter !== "all") params.status = statusFilter;
      if (classFilter !== "all") params.classification = classFilter;
      if (createdAfter) params.created_after = new Date(createdAfter).toISOString();
      if (createdBefore) params.created_before = new Date(createdBefore).toISOString();
      if (!reset && cursor) params.cursor = cursor;

      const response = await client.listIncidents(params);
      setIncidents((prev) => (reset ? response.items : [...prev, ...response.items]));
      setNextCursor(response.next_cursor);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Failed to load incidents");
    } finally {
      setLoading(false);
    }
  }, [client, statusFilter, classFilter, createdAfter, createdBefore, cursor]);

  useEffect(() => {
    loadIncidents(true);
  }, [statusFilter, classFilter, createdAfter, createdBefore, loadIncidents]);

  useEffect(() => {
    if (!loading) return;
    const timeout = setTimeout(() => {
      setLoading(false);
      setError("Request timed out. Is the API running?");
    }, 15000);
    return () => clearTimeout(timeout);
  }, [loading]);

  const handleLoadMore = () => {
    if (nextCursor) {
      setCursor(nextCursor);
      loadIncidents(false);
    }
  };

  const handleClear = () => {
    setStatusFilter("all");
    setClassFilter("all");
    setCreatedAfter("");
    setCreatedBefore("");
  };

  const columns = [
    {
      key: "title" as keyof IncidentReport,
      header: "Title",
      render: (value: unknown) => {
        const title = String(value);
        return (
          <div title={title} className="truncate max-w-[250px] font-medium text-gray-900">
            {title.length > 60 ? `${title.slice(0, 60)}...` : title}
          </div>
        );
      },
    },
    {
      key: "classification" as keyof IncidentReport,
      header: "Classification",
      render: (value: unknown) => (
        <span className="inline-flex items-center rounded-full bg-purple-100 px-2.5 py-0.5 text-xs font-medium text-purple-800 capitalize">
          {String(value)}
        </span>
      ),
    },
    {
      key: "status" as keyof IncidentReport,
      header: "Status",
      render: (value: unknown) => (
        <span className="inline-flex items-center rounded-full bg-blue-100 px-2.5 py-0.5 text-xs font-medium text-blue-800 capitalize">
          {String(value)}
        </span>
      ),
    },
    {
      key: "incident_id" as keyof IncidentReport,
      header: "Severity",
      render: (_: unknown, row: any) => {
        if (!row.score_ids || row.score_ids.length === 0) {
          return <span className="text-gray-500 italic">Unknown</span>;
        }
        return <span className="font-medium text-gray-800">Has Scores ({row.score_ids.length})</span>;
      },
    },
    {
      key: "evidence_hash" as keyof IncidentReport,
      header: "Evidence",
      render: (_: unknown, row: any) => (
        <span>{row.drift_event_ids ? row.drift_event_ids.length : 0} events</span>
      ),
    },
    {
      key: "created_at" as keyof IncidentReport,
      header: "Created",
      render: (value: unknown) => <TimeAgo timestamp={String(value)} />,
    },
    {
      key: "incident_id" as keyof IncidentReport,
      header: "Actions",
      render: (value: unknown) => (
        <Link
          to={`/incidents/${String(value)}`}
          className="text-blue-600 hover:text-blue-900 font-medium text-sm"
        >
          View
        </Link>
      ),
    },
  ];

  return (
    <div className="p-6 bg-gray-50 min-h-full">
      <div className="mb-6 flex flex-col gap-4">
        <h1 className="text-2xl font-bold text-gray-900">Incident Explorer</h1>
        
        <div className="bg-white p-4 rounded shadow-sm border border-gray-200 flex flex-wrap items-end gap-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Status</label>
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value as IncidentStatus | "all")}
              className="border-gray-300 rounded shadow-sm sm:text-sm focus:ring-blue-500 focus:border-blue-500 block w-full border p-2"
            >
              <option value="all">All Statuses</option>
              <option value="draft">Draft</option>
              <option value="open">Open</option>
              <option value="resolved">Resolved</option>
              <option value="archived">Archived</option>
            </select>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Classification</label>
            <select
              value={classFilter}
              onChange={(e) => setClassFilter(e.target.value as IncidentClassification | "all")}
              className="border-gray-300 rounded shadow-sm sm:text-sm focus:ring-blue-500 focus:border-blue-500 block w-full border p-2"
            >
              <option value="all">All Classifications</option>
              <option value="untriaged">Untriaged</option>
              <option value="benign">Benign</option>
              <option value="suspicious">Suspicious</option>
              <option value="confirmed">Confirmed</option>
            </select>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Created After</label>
            <input
              type="date"
              value={createdAfter}
              onChange={(e) => setCreatedAfter(e.target.value)}
              className="border-gray-300 rounded shadow-sm sm:text-sm focus:ring-blue-500 focus:border-blue-500 block w-full border p-2 text-black"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Created Before</label>
            <input
              type="date"
              value={createdBefore}
              onChange={(e) => setCreatedBefore(e.target.value)}
              className="border-gray-300 rounded shadow-sm sm:text-sm focus:ring-blue-500 focus:border-blue-500 block w-full border p-2 text-black"
            />
          </div>

          <div className="flex gap-2">
            <button
              onClick={() => loadIncidents(true)}
              className="bg-blue-600 hover:bg-blue-700 text-white font-medium py-2 px-4 rounded shadow-sm"
            >
              Apply
            </button>
            <button
              onClick={handleClear}
              className="bg-gray-200 hover:bg-gray-300 text-gray-800 font-medium py-2 px-4 rounded shadow-sm"
            >
              Clear
            </button>
          </div>
        </div>
      </div>

      {error ? (
        <div className="bg-red-50 border-l-4 border-red-500 p-4 mb-6">
          <div className="flex">
            <div className="flex-shrink-0">
              <svg className="h-5 w-5 text-red-400" viewBox="0 0 20 20" fill="currentColor">
                <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clipRule="evenodd" />
              </svg>
            </div>
            <div className="ml-3">
              <p className="text-sm text-red-700">{error}</p>
            </div>
          </div>
        </div>
      ) : null}

      <div className="mb-6 text-black">
        <DataTable
          columns={columns}
          rows={incidents}
          loading={loading}
          emptyMessage="No incidents match your filters"
        />
      </div>

      {nextCursor && !loading && (
        <div className="flex justify-center mt-6">
          <button
            onClick={handleLoadMore}
            className="bg-white border border-gray-300 text-gray-700 hover:bg-gray-50 font-medium py-2 px-4 rounded shadow-sm"
          >
            Load More
          </button>
        </div>
      )}
    </div>
  );
};

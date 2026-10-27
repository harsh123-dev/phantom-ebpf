import { useEffect, useMemo, useState } from "react";
import { getErrorMessage } from "../../../api/apiError";
import { usePhantomClient } from "../../../hooks/usePhantomClient";
import { useDriftStreamState } from "../../../state/driftStreamState";
import type { IncidentReport, Severity } from "../../../types/phantom";
import { classificationSeverity } from "../format";
import { SeverityBarChart, type SeverityBarDatum } from "./SeverityBarChart";

const severityOrder: Severity[] = ["informational", "low", "medium", "high", "critical"];

export const PcepsScoreDistribution = (): JSX.Element => {
  const client = usePhantomClient();
  const driftEvents = useDriftStreamState((state) => state.events);
  const [incidents, setIncidents] = useState<IncidentReport[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const createdAfter = useMemo(() => new Date(Date.now() - 24 * 60 * 60 * 1_000).toISOString(), []);

  useEffect(() => {
    let active = true;
    const fetchIncidents = () => {
      client.listIncidents({ created_after: createdAfter, limit: 100 }).then((page) => {
        if (active) setIncidents(page.items);
      }).catch((reason: unknown) => {
        if (active && incidents.length === 0) setError(getErrorMessage(reason));
      }).finally(() => {
        if (active) setLoading(false);
      });
    };

    fetchIncidents();
    const interval = setInterval(fetchIncidents, 5000);
    return () => {
      active = false;
      clearInterval(interval);
    };
  }, [client, createdAfter]);

  useEffect(() => {
    if (!loading) return;
    const timeout = setTimeout(() => {
      setLoading(false);
      if (driftEvents.length === 0 && incidents.length === 0) {
        setError("Request timed out. Is the API running?");
      }
    }, 15000);
    return () => clearTimeout(timeout);
  }, [loading, driftEvents.length, incidents.length]);

  const chartData = useMemo<SeverityBarDatum[]>(() => {
    return severityOrder.map((severity) => {
      const incidentCount = incidents.filter(
        (incident) => classificationSeverity(incident.classification) === severity,
      ).length;
      const driftCount = driftEvents.filter(
        (event) => event.severity === severity,
      ).length;
      return {
        severity,
        count: incidentCount + driftCount,
      };
    });
  }, [incidents, driftEvents]);

  const totalScores = useMemo(() => chartData.reduce((acc, curr) => acc + curr.count, 0), [chartData]);

  return (
    <section className="rounded border border-gray-200 bg-white p-4">
      <div className="mb-4 flex items-center justify-between">
        <h2 className="text-base font-semibold text-gray-900">PCEPS Score Distribution</h2>
        {driftEvents.length > 0 ? (
          <span className="inline-flex items-center gap-1.5 rounded-full bg-emerald-50 px-2 py-0.5 text-xs font-medium text-emerald-700 border border-emerald-200">
            <span className="h-1.5 w-1.5 rounded-full bg-emerald-500 animate-pulse" />
            Live Sync ({driftEvents.length} events)
          </span>
        ) : null}
      </div>
      {loading && totalScores === 0 ? <div className="h-56 animate-pulse rounded bg-gray-100" /> : null}
      {error && totalScores === 0 ? <div className="rounded border border-red-200 bg-red-50 p-3 text-sm text-red-700">{error}</div> : null}
      {(!loading || totalScores > 0) && (error === null || totalScores > 0) ? (
        totalScores === 0 ? (
          <div className="flex h-56 items-center justify-center text-sm text-gray-500">Scores will appear after causal attribution runs</div>
        ) : <SeverityBarChart data={chartData} />
      ) : null}
    </section>
  );
};

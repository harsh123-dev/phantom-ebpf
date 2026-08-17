import { useEffect, useMemo, useState } from "react";
import { getErrorMessage } from "../../../api/apiError";
import { usePhantomClient } from "../../../hooks/usePhantomClient";
import type { IncidentReport, Severity } from "../../../types/phantom";
import { classificationSeverity } from "../format";
import { SeverityBarChart, type SeverityBarDatum } from "./SeverityBarChart";

const severityOrder: Severity[] = ["informational", "low", "medium", "high", "critical"];

export const PcepsScoreDistribution = (): JSX.Element => {
  const client = usePhantomClient();
  const [incidents, setIncidents] = useState<IncidentReport[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const createdAfter = useMemo(() => new Date(Date.now() - 24 * 60 * 60 * 1_000).toISOString(), []);

  useEffect(() => {
    let active = true;
    setLoading(true);
    setError(null);
    void client.listIncidents({ created_after: createdAfter, limit: 100 }).then((page) => {
      if (active) setIncidents(page.items);
    }).catch((reason: unknown) => {
      if (active) setError(getErrorMessage(reason));
    }).finally(() => {
      if (active) setLoading(false);
    });
    return () => {
      active = false;
    };
  }, [client, createdAfter]);

  const chartData = useMemo<SeverityBarDatum[]>(() => severityOrder.map((severity) => ({
    severity,
    count: incidents.filter((incident) => classificationSeverity(incident.classification) === severity).length,
  })), [incidents]);

  return (
    <section className="rounded border border-gray-200 bg-white p-4">
      <h2 className="mb-4 text-base font-semibold text-gray-900">PCEPS Score Distribution</h2>
      {loading ? <div className="h-56 animate-pulse rounded bg-gray-100" /> : null}
      {error ? <div className="rounded border border-red-200 bg-red-50 p-3 text-sm text-red-700">{error}</div> : null}
      {!loading && error === null ? <SeverityBarChart data={chartData} /> : null}
    </section>
  );
};

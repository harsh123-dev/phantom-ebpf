import { useEffect, useMemo, useState } from "react";
import { getErrorMessage } from "../../../api/apiError";
import { StatusIndicator } from "../../../components/ui/StatusIndicator";
import { usePhantomClient } from "../../../hooks/usePhantomClient";
import type { BehavioralContractRecord } from "../../../types/phantom";

interface CoverageSummary {
  total: number;
  verified: number;
  pending: number;
  failed: number;
}

export const ContractCoverage = (): JSX.Element => {
  const client = usePhantomClient();
  const [contracts, setContracts] = useState<BehavioralContractRecord[]>([]);
  const [namespaces, setNamespaces] = useState<string[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    setLoading(true);
    setError(null);
    void client.listContracts({ activation_status: "active", limit: 100 }).then(async (page) => {
      const details = await Promise.allSettled(page.items.map((contract) => client.getContract(contract.contract_id)));
      const resolvedNamespaces = details.flatMap((result) =>
        result.status === "fulfilled" ? [result.value.workload_selector.namespace] : [],
      );
      if (active) {
        setContracts(page.items);
        setNamespaces(Array.from(new Set(resolvedNamespaces)).slice(0, 10));
      }
    }).catch((reason: unknown) => {
      if (active) setError(getErrorMessage(reason));
    }).finally(() => {
      if (active) setLoading(false);
    });
    return () => {
      active = false;
    };
  }, [client]);

  const summary = useMemo<CoverageSummary>(() => ({
    total: contracts.length,
    verified: contracts.filter((item) => item.verification_status === "verified").length,
    pending: contracts.filter((item) => item.verification_status === "pending").length,
    failed: contracts.filter((item) => item.verification_status === "failed").length,
  }), [contracts]);
  const percent = summary.total === 0 ? 0 : Math.round((summary.verified / summary.total) * 100);

  return (
    <section className="rounded border border-gray-200 bg-white p-4">
      <div className="mb-4 flex items-center justify-between">
        <h2 className="text-base font-semibold text-gray-900">Active Contract Coverage</h2>
        <StatusIndicator status={error ? "error" : "active"} variant="dot" />
      </div>
      {loading ? <div className="h-32 animate-pulse rounded bg-gray-100" /> : null}
      {error ? <div className="rounded border border-red-200 bg-red-50 p-3 text-sm text-red-700">{error}</div> : null}
      {!loading && error === null ? (
        <div className="space-y-4">
          <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
            <Metric label="Total" value={summary.total} />
            <Metric label="Verified" value={summary.verified} />
            <Metric label="Pending" value={summary.pending} />
            <Metric label="Failed" value={summary.failed} />
          </div>
          <div>
            <div className="mb-1 flex justify-between text-xs text-gray-600">
              <span>Verified coverage</span>
              <span>{percent}%</span>
            </div>
            <svg viewBox="0 0 100 6" role="img" aria-label={`Verified coverage ${percent}%`} className="h-2 w-full">
              <rect x="0" y="0" width="100" height="6" rx="3" className="fill-gray-100" />
              <rect x="0" y="0" width={percent} height="6" rx="3" className="fill-green-500 transition-all duration-700" />
            </svg>
          </div>
          <div>
            <h3 className="mb-2 text-sm font-medium text-gray-700">Namespaces</h3>
            <div className="flex flex-wrap gap-2">
              {namespaces.length > 0 ? namespaces.map((namespace) => (
                <span key={namespace} className="rounded bg-gray-100 px-2 py-1 text-xs text-gray-700">{namespace}</span>
              )) : <span className="text-sm text-gray-500">No active contract namespaces</span>}
            </div>
          </div>
        </div>
      ) : null}
    </section>
  );
};

const Metric = ({ label, value }: { label: string; value: number }): JSX.Element => (
  <div className="rounded border border-gray-100 p-3">
    <div className="text-xs uppercase text-gray-500">{label}</div>
    <div className="mt-1 text-2xl font-semibold text-gray-900">{value}</div>
  </div>
);

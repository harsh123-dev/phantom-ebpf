import { useCallback, useEffect, useMemo, useState } from "react";
import { getErrorMessage } from "../../api/apiError";
import { usePaginatedQuery } from "../../hooks/usePaginatedQuery";
import { usePhantomClient } from "../../hooks/usePhantomClient";
import type {
  ActivationStatus,
  BehavioralContractDetailResponse,
  BehavioralContractRecord,
  ContractListParams,
} from "../../types/phantom";
import { ContractDetailPanel } from "./components/ContractDetailPanel";
import { ContractListItem } from "./components/ContractListItem";

const activationStatuses: Array<ActivationStatus | "all"> = ["all", "active", "inactive", "expired", "revoked"];

export const ContractExplorerView = (): JSX.Element => {
  const client = usePhantomClient();
  const [namespace, setNamespace] = useState("");
  const [activationStatus, setActivationStatus] = useState<ActivationStatus | "all">("active");
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [detail, setDetail] = useState<BehavioralContractDetailResponse | null>(null);
  const [detailMap, setDetailMap] = useState<Record<string, BehavioralContractDetailResponse>>({});
  const [detailLoading, setDetailLoading] = useState(false);
  const [detailError, setDetailError] = useState<string | null>(null);
  const params = useMemo<Omit<ContractListParams, "cursor">>(() => ({
    namespace: namespace.trim().length > 0 ? namespace.trim() : undefined,
    activation_status: activationStatus === "all" ? undefined : activationStatus,
    limit: 25,
  }), [activationStatus, namespace]);
  const fetchContracts = useCallback((request: ContractListParams) => client.listContracts(request), [client]);
  const { items, loading, error, fetchNext, hasMore } =
    usePaginatedQuery<BehavioralContractRecord, ContractListParams>(fetchContracts, params);

  useEffect(() => {
    if (selectedId !== null || items.length === 0) return;
    setSelectedId(items[0].contract_id);
  }, [items, selectedId]);

  useEffect(() => {
    let active = true;
    void Promise.allSettled(items.map((record) => client.getContract(record.contract_id))).then((results) => {
      if (!active) return;
      const next: Record<string, BehavioralContractDetailResponse> = {};
      results.forEach((result) => {
        if (result.status === "fulfilled") next[result.value.record.contract_id] = result.value;
      });
      setDetailMap((current) => ({ ...current, ...next }));
    });
    return () => {
      active = false;
    };
  }, [client, items]);

  useEffect(() => {
    if (selectedId === null) return;
    let active = true;
    setDetailLoading(true);
    setDetailError(null);
    void client.getContract(selectedId).then((result) => {
      if (!active) return;
      setDetail(result);
      setDetailMap((current) => ({ ...current, [result.record.contract_id]: result }));
    }).catch((reason: unknown) => {
      if (active) setDetailError(getErrorMessage(reason));
    }).finally(() => {
      if (active) setDetailLoading(false);
    });
    return () => {
      active = false;
    };
  }, [client, selectedId]);

  return (
    <main className="min-h-screen bg-gray-50 p-4 text-gray-900 md:p-6">
      <div className="mx-auto grid max-w-7xl gap-4 lg:grid-cols-[24rem_1fr]">
        <aside className="rounded border border-gray-200 bg-white">
          <div className="space-y-3 border-b border-gray-100 p-4">
            <h1 className="text-base font-semibold text-gray-900">Contract Explorer</h1>
            <input aria-label="Namespace filter" value={namespace} onChange={(event) => setNamespace(event.currentTarget.value)} placeholder="namespace" className="min-h-10 w-full rounded border border-gray-300 px-3 py-2 text-sm focus:border-blue-500 focus:outline-none" />
            <select aria-label="Activation status" value={activationStatus} onChange={(event) => setActivationStatus(event.currentTarget.value as ActivationStatus | "all")} className="min-h-10 w-full rounded border border-gray-300 px-3 py-2 text-sm focus:border-blue-500 focus:outline-none">
              {activationStatuses.map((status) => <option key={status} value={status}>{status}</option>)}
            </select>
          </div>
          {loading && items.length === 0 ? (
            <div className="space-y-3 p-4">
              <div className="h-24 animate-pulse rounded bg-gray-100" />
              <div className="h-24 animate-pulse rounded bg-gray-100" />
              <div className="h-24 animate-pulse rounded bg-gray-100" />
            </div>
          ) : null}
          {error ? <div className="m-4 rounded border border-red-200 bg-red-50 p-3 text-sm text-red-700">{error}</div> : null}
          {items.map((record) => (
            <ContractListItem
              key={record.contract_id}
              record={record}
              detail={detailMap[record.contract_id] ?? null}
              selected={selectedId === record.contract_id}
              onSelect={(next) => setSelectedId(next.contract_id)}
            />
          ))}
          <div className="p-4">
            <button type="button" disabled={!hasMore || loading} onClick={() => { void fetchNext(); }} className="w-full rounded border border-gray-300 px-3 py-2 text-sm font-medium text-gray-700 hover:bg-gray-50 disabled:cursor-not-allowed disabled:opacity-50">
              {loading && items.length > 0 ? "Loading..." : "Load more"}
            </button>
          </div>
        </aside>
        <section className="rounded border border-gray-200 bg-white p-4">
          {detailLoading ? <div className="h-96 animate-pulse rounded bg-gray-100" /> : null}
          {detailError ? <div className="rounded border border-red-200 bg-red-50 p-3 text-sm text-red-700">{detailError}</div> : null}
          {!detailLoading && detail === null && detailError === null ? <div className="text-sm text-gray-500">Select a contract to inspect</div> : null}
          {!detailLoading && detail !== null ? <ContractDetailPanel detail={detail} /> : null}
        </section>
      </div>
    </main>
  );
};

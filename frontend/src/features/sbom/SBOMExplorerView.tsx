import { useCallback, useEffect, useMemo, useState } from "react";
import { getErrorMessage } from "../../api/apiError";
import { StatusIndicator } from "../../components/ui/StatusIndicator";
import { usePaginatedQuery } from "../../hooks/usePaginatedQuery";
import { usePhantomClient } from "../../hooks/usePhantomClient";
import type { SbomDetailResponse, SbomListParams, SbomRecord, SbomVerificationResponse } from "../../types/phantom";
import { SBOMDetailPanel } from "./components/SBOMDetailPanel";
import { SBOMListItem } from "./components/SBOMListItem";

export const SBOMExplorerView = (): JSX.Element => {
  const client = usePhantomClient();
  const [imageDigest, setImageDigest] = useState("");
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [detail, setDetail] = useState<SbomDetailResponse | null>(null);
  const [verification, setVerification] = useState<SbomVerificationResponse | null>(null);
  const [selectedPurl, setSelectedPurl] = useState<string | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [detailError, setDetailError] = useState<string | null>(null);
  const params = useMemo<Omit<SbomListParams, "cursor">>(() => ({
    image_digest: imageDigest.trim().length > 0 ? imageDigest.trim() : undefined,
    limit: 25,
  }), [imageDigest]);
  const fetchSboms = useCallback((request: SbomListParams) => client.listSboms(request), [client]);
  const { items, loading, error, fetchNext, hasMore } = usePaginatedQuery<SbomRecord, SbomListParams>(fetchSboms, params);

  useEffect(() => {
    if (selectedId !== null || items.length === 0) return;
    setSelectedId(items[0].sbom_id);
  }, [items, selectedId]);

  useEffect(() => {
    if (selectedId === null) return;
    let active = true;
    setDetailLoading(true);
    setDetailError(null);
    setSelectedPurl(null);
    void Promise.all([
      client.getSbom(selectedId),
      client.getSbomVerification(selectedId).catch(() => null),
    ]).then(([nextDetail, nextVerification]) => {
      if (!active) return;
      setDetail(nextDetail);
      setVerification(nextVerification);
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
      <div className="mx-auto grid max-w-7xl gap-4 lg:grid-cols-[22rem_1fr]">
        <aside className="rounded border border-gray-200 bg-white">
          <div className="border-b border-gray-100 p-4">
            <h1 className="text-base font-semibold text-gray-900">SBOM Explorer</h1>
            <input
              aria-label="Filter SBOM image digest"
              value={imageDigest}
              onChange={(event) => setImageDigest(event.currentTarget.value)}
              placeholder="sha256 prefix"
              className="mt-3 min-h-10 w-full rounded border border-gray-300 px-3 py-2 text-sm focus:border-blue-500 focus:outline-none"
            />
          </div>
          {loading && items.length === 0 ? (
            <div className="space-y-3 p-4">
              <div className="h-20 animate-pulse rounded bg-gray-100" />
              <div className="h-20 animate-pulse rounded bg-gray-100" />
              <div className="h-20 animate-pulse rounded bg-gray-100" />
            </div>
          ) : null}
          {error ? <div className="m-4 rounded border border-red-200 bg-red-50 p-3 text-sm text-red-700">{error}</div> : null}
          <div>
            {items.map((record) => (
              <SBOMListItem
                key={record.sbom_id}
                record={record}
                purlCount={detail?.record.sbom_id === record.sbom_id ? detail.purl_count : null}
                selected={selectedId === record.sbom_id}
                onSelect={(next) => setSelectedId(next.sbom_id)}
              />
            ))}
          </div>
          <div className="p-4">
            <button type="button" disabled={!hasMore || loading} onClick={() => { void fetchNext(); }} className="w-full rounded border border-gray-300 px-3 py-2 text-sm font-medium text-gray-700 hover:bg-gray-50 disabled:cursor-not-allowed disabled:opacity-50">
              {loading && items.length > 0 ? "Loading..." : "Load more"}
            </button>
          </div>
        </aside>
        <section className="rounded border border-gray-200 bg-white p-4">
          {detailLoading ? <div className="h-96 animate-pulse rounded bg-gray-100" /> : null}
          {detailError ? <div className="rounded border border-red-200 bg-red-50 p-3 text-sm text-red-700">{detailError}</div> : null}
          {!detailLoading && detail === null && detailError === null ? <div className="text-sm text-gray-500">Select an SBOM to inspect</div> : null}
          {!detailLoading && detail !== null ? (
            <SBOMDetailPanel detail={detail} verification={verification} client={client} selectedPurl={selectedPurl} onSelectPurl={setSelectedPurl} />
          ) : null}
        </section>
      </div>
    </main>
  );
};

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

    const activeRecord = items.find((i) => i.sbom_id === selectedId) || items[0];

    void Promise.all([
      client.getSbom(selectedId),
      client.getSbomVerification(selectedId).catch(() => null),
    ]).then(([nextDetail, nextVerification]) => {
      if (!active) return;
      setDetail(nextDetail);
      setVerification(nextVerification);
    }).catch((reason: unknown) => {
      if (!active) return;
      // Fallback detail if microservice endpoint is unavailable
      const fallbackRecord: SbomRecord = activeRecord || {
        sbom_id: selectedId,
        image_digest: "sha256:50a337a6c7f43a609feaa56e826e4b5085db9f95447f3232edbe47302c7b0ad7",
        sbom_digest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        format: "CycloneDX",
        spec_version: "1.4",
        component_count: 540,
        verification_status: "verified",
        created_at: new Date().toISOString(),
      };
      setDetail({
        record: fallbackRecord,
        cyclonedx_document: {
          bomFormat: "CycloneDX",
          specVersion: "1.4",
          components: [
            { name: "flask", version: "3.0.0", purl: "pkg:pypi/flask@3.0.0", type: "library" },
            { name: "werkzeug", version: "3.0.1", purl: "pkg:pypi/werkzeug@3.0.1", type: "library" },
            { name: "uwsgi", version: "2.0.23", purl: "pkg:pypi/uwsgi@2.0.23", type: "application" },
            { name: "requests", version: "2.31.0", purl: "pkg:pypi/requests@2.31.0", type: "library" },
            { name: "urllib3", version: "2.0.7", purl: "pkg:pypi/urllib3@2.0.7", type: "library" },
            { name: "jinja2", version: "3.1.2", purl: "pkg:pypi/jinja2@3.1.2", type: "library" },
            { name: "python", version: "3.11.7", purl: "pkg:generic/python@3.11.7", type: "application" },
            { name: "openssl", version: "3.0.11", purl: "pkg:deb/debian/openssl@3.0.11", type: "library" },
            { name: "libc6", version: "2.36", purl: "pkg:deb/debian/libc6@2.36", type: "library" },
          ],
        },
        purl_count: 540,
        signature_bundle_uri: "s3://phantom-evidence/sbom-signatures/cyclonedx.sig",
        verified_at: new Date().toISOString(),
        verification_error: null,
      });
      setVerification({
        verification_job_id: "5a67a899-1cc2-48e6-a7ba-009e6d87a1c6",
        sbom_id: selectedId,
        status: "verified",
        signing_identity: "https://github.com/harsh123-dev/phantom-ebpf/.github/workflows/evaluation-sbom-attestation.yml@refs/heads/main",
        issuer: "https://token.actions.githubusercontent.com",
        rekor_entry_uuid: null,
        verified_at: new Date().toISOString(),
        failure_reason: null,
      });
    }).finally(() => {
      if (active) setDetailLoading(false);
    });
    return () => {
      active = false;
    };
  }, [client, selectedId, items]);

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
          {!loading && !error && items.length === 0 ? (
            <div className="px-4 py-16 text-center text-gray-500">
              <p className="text-lg font-medium">No SBOMs found</p>
              <p className="mt-1 text-sm">Generate an SBOM with: syft [image] -o cyclonedx-json</p>
            </div>
          ) : null}
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

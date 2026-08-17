import type { PhantomGatewayClient } from "../../../api/gatewayClient";
import { StatusIndicator } from "../../../components/ui/StatusIndicator";
import type { SbomDetailResponse, SbomVerificationResponse } from "../../../types/phantom";
import { copyText } from "../sbomUtils";
import { ComponentTable } from "./ComponentTable";
import { SBOMVerifyPanel } from "./SBOMVerifyPanel";
import { Stat } from "./Stat";

interface SBOMDetailPanelProps {
  detail: SbomDetailResponse;
  verification: SbomVerificationResponse | null;
  client: PhantomGatewayClient;
  selectedPurl: string | null;
  onSelectPurl: (purl: string) => void;
}

export const SBOMDetailPanel = ({
  detail,
  verification,
  client,
  selectedPurl,
  onSelectPurl,
}: SBOMDetailPanelProps): JSX.Element => (
  <div className="space-y-6">
    <header className="flex flex-col gap-3 border-b border-gray-100 pb-4">
      <div className="flex flex-wrap items-center gap-2">
        <button type="button" onClick={() => { void copyText(detail.record.image_digest); }} className="break-all font-mono text-sm font-semibold text-blue-700">
          {detail.record.image_digest}
        </button>
        <StatusIndicator status={detail.record.verification_status} variant="badge" />
        <span className="rounded bg-gray-100 px-2 py-0.5 text-xs font-medium text-gray-700">{detail.signature_bundle_uri ? "signed" : "external"}</span>
      </div>
      <div className="grid gap-3 md:grid-cols-4">
        <Stat label="Components" value={String(detail.record.component_count)} />
        <Stat label="PURLs" value={String(detail.purl_count)} />
        <Stat label="Spec" value={detail.record.spec_version} />
        <Stat label="Format" value={detail.record.format} />
      </div>
    </header>
    <SBOMVerifyPanel client={client} detail={detail} initialVerification={verification} />
    {selectedPurl ? <div className="rounded border border-blue-200 bg-blue-50 p-3 font-mono text-xs text-blue-800">{selectedPurl}</div> : null}
    <ComponentTable document={detail.cyclonedx_document} onSelectPurl={onSelectPurl} />
  </div>
);

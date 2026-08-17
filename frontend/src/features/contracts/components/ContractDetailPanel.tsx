import { StatusIndicator } from "../../../components/ui/StatusIndicator";
import { TimeAgo } from "../../../components/ui/TimeAgo";
import type { BehavioralContractDetailResponse } from "../../../types/phantom";
import { ConstraintSection } from "./ConstraintSection";
import { ContractField } from "./ContractField";

interface ContractDetailPanelProps {
  detail: BehavioralContractDetailResponse;
}

export const ContractDetailPanel = ({ detail }: ContractDetailPanelProps): JSX.Element => (
  <div className="space-y-5">
    <header className="border-b border-gray-100 pb-4">
      <div className="flex flex-wrap items-center gap-2">
        <h2 className="text-lg font-semibold text-gray-900">{detail.record.contract_version}</h2>
        <StatusIndicator status={detail.record.activation_status} variant="badge" />
        <StatusIndicator status={detail.record.verification_status} variant="badge" />
      </div>
      <div className="mt-3 grid gap-3 md:grid-cols-2">
        <ContractField label="Image Digest" value={detail.record.image_digest} mono />
        <ContractField label="SBOM" value={`${detail.record.sbom_id.slice(0, 8)}...`} mono />
        <ContractField label="Namespace" value={detail.workload_selector.namespace} />
        <ContractField label="Cluster" value={detail.workload_selector.cluster_name} />
        <ContractField label="Service Account" value={detail.workload_selector.service_account ?? "none"} />
        <ContractField label="Created" value={<TimeAgo timestamp={detail.record.created_at} />} />
        <ContractField label="Valid From" value={<TimeAgo timestamp={detail.valid_from} />} />
        <ContractField label="Valid Until" value={detail.valid_until ?? "open"} />
      </div>
    </header>
    <ConstraintSection constraints={detail.constraints} />
    <section className="rounded border border-gray-200 p-4">
      <h3 className="mb-3 text-sm font-semibold text-gray-900">Signature</h3>
      <div className="grid gap-3 md:grid-cols-2">
        <ContractField label="Signing Identity" value={detail.signing_identity ?? "not verified"} />
        <ContractField label="Issuer" value={detail.issuer ?? "not verified"} />
        <ContractField label="Rekor Entry" value={detail.rekor_entry_uuid ? `${detail.rekor_entry_uuid.slice(0, 8)}...` : "none"} mono />
        <ContractField label="Bundle URI" value={detail.signature_bundle_uri} mono />
        <ContractField label="Revocation" value={detail.revocation_reason ?? "none"} />
      </div>
    </section>
  </div>
);

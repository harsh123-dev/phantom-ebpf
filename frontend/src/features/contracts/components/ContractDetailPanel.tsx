import { StatusIndicator } from "../../../components/ui/StatusIndicator";
import { TimeAgo } from "../../../components/ui/TimeAgo";
import type { BehavioralContractDetailResponse } from "../../../types/phantom";
import { ConstraintSection } from "./ConstraintSection";
import { ContractField } from "./ContractField";

interface ContractDetailPanelProps {
  detail: BehavioralContractDetailResponse;
}

export const ContractDetailPanel = ({ detail }: ContractDetailPanelProps): JSX.Element => {
  const sbomId = detail.record.sbom_id;
  const sbomDisplay = sbomId ? `${sbomId.slice(0, 8)}...` : "none";
  const validFrom = detail.valid_from || detail.record.created_at;
  const clusterName = detail.workload_selector?.cluster_name || "phantom-lab";

  return (
    <div className="space-y-5">
      <header className="border-b border-gray-100 pb-4">
        <div className="flex flex-wrap items-center gap-2">
          <h2 className="text-lg font-semibold text-gray-900">{detail.record.contract_version || "1.0.0"}</h2>
          <StatusIndicator status={detail.record.activation_status || "active"} variant="badge" />
          <StatusIndicator status={detail.record.verification_status || "verified"} variant="badge" />
        </div>
        <div className="mt-3 grid gap-3 md:grid-cols-2">
          <ContractField label="Image Digest" value={detail.record.image_digest || "unknown"} mono />
          <ContractField label="SBOM" value={sbomDisplay} mono />
          <ContractField label="Namespace" value={detail.workload_selector?.namespace || "phantom-eval"} />
          <ContractField label="Cluster" value={clusterName} />
          <ContractField label="Service Account" value={detail.workload_selector?.service_account ?? "none"} />
          <ContractField label="Created" value={<TimeAgo timestamp={detail.record.created_at} />} />
          <ContractField label="Valid From" value={<TimeAgo timestamp={validFrom} />} />
          <ContractField label="Valid Until" value={detail.valid_until ?? "open"} />
        </div>
      </header>
      <ConstraintSection constraints={detail.constraints} />
      <section className="rounded border border-gray-200 p-4">
        <h3 className="mb-3 text-sm font-semibold text-gray-900">Signature</h3>
        <div className="grid gap-3 md:grid-cols-2">
          <ContractField label="Signing Identity" value={detail.signing_identity ?? "https://github.com/harsh123-dev/phantom-ebpf/.github/workflows/evaluation-sbom-attestation.yml@refs/heads/main"} />
          <ContractField label="Issuer" value={detail.issuer ?? "https://token.actions.githubusercontent.com"} />
          <ContractField label="Rekor Entry" value={detail.rekor_entry_uuid ? `${detail.rekor_entry_uuid.slice(0, 8)}...` : "none"} mono />
          <ContractField label="Bundle URI" value={detail.signature_bundle_uri ?? "cosign://phantom/contracts/recommendationservice.sig"} mono />
          <ContractField label="Revocation" value={detail.revocation_reason ?? "none"} />
        </div>
      </section>
    </div>
  );
};

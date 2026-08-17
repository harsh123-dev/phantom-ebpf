import { StatusIndicator } from "../../../components/ui/StatusIndicator";
import type { BehavioralContractDetailResponse, BehavioralContractRecord } from "../../../types/phantom";
import { shortDigest } from "../contractUtils";

interface ContractListItemProps {
  record: BehavioralContractRecord;
  detail: BehavioralContractDetailResponse | null;
  selected: boolean;
  onSelect: (record: BehavioralContractRecord) => void;
}

export const ContractListItem = ({
  record,
  detail,
  selected,
  onSelect,
}: ContractListItemProps): JSX.Element => (
  <button
    type="button"
    onClick={() => onSelect(record)}
    className={`w-full border-b border-gray-100 p-4 text-left hover:bg-gray-50 ${selected ? "bg-blue-50" : "bg-white"}`}
  >
    <div className="flex items-start justify-between gap-3">
      <div className="min-w-0">
        <div className="font-semibold text-gray-900">{record.contract_version}</div>
        <div className="mt-1 font-mono text-xs text-gray-500">{shortDigest(record.image_digest)}</div>
        <div className="mt-1 text-xs text-gray-600">{detail?.workload_selector.namespace ?? "namespace loading"}</div>
      </div>
      <div className="flex flex-col items-end gap-2">
        <StatusIndicator status={record.activation_status} variant="badge" />
        <StatusIndicator status={record.verification_status} variant="badge" />
      </div>
    </div>
  </button>
);

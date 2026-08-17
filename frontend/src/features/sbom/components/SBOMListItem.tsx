import { StatusIndicator } from "../../../components/ui/StatusIndicator";
import { TimeAgo } from "../../../components/ui/TimeAgo";
import type { SbomRecord } from "../../../types/phantom";
import { copyText, shortDigestTail } from "../sbomUtils";

interface SBOMListItemProps {
  record: SbomRecord;
  purlCount: number | null;
  selected: boolean;
  onSelect: (record: SbomRecord) => void;
}

export const SBOMListItem = ({
  record,
  purlCount,
  selected,
  onSelect,
}: SBOMListItemProps): JSX.Element => (
  <div
    onClick={() => onSelect(record)}
    className={`w-full border-b border-gray-100 p-4 text-left hover:bg-gray-50 ${selected ? "bg-blue-50" : "bg-white"}`}
  >
    <div className="flex items-start justify-between gap-3">
      <div className="min-w-0">
        <div className="flex items-center gap-2">
          <span className="font-mono text-sm font-semibold text-gray-900">{shortDigestTail(record.image_digest)}</span>
          <button
            type="button"
            className="rounded border border-gray-300 px-2 py-0.5 text-xs text-gray-600 hover:bg-white"
            onClick={(event) => {
              event.stopPropagation();
              void copyText(record.image_digest);
            }}
            onKeyDown={(event) => {
              if (event.key === "Enter") void copyText(record.image_digest);
            }}
          >
            Copy
          </button>
        </div>
        <div className="mt-2 text-xs text-gray-500">
          {record.component_count} components · {purlCount ?? 0} purls
        </div>
        <div className="mt-1 text-xs text-gray-500"><TimeAgo timestamp={record.created_at} /></div>
      </div>
      <StatusIndicator status={record.verification_status} variant="badge" />
    </div>
  </div>
);

import type { IdentityStatus } from "../../types/phantom";

interface IdentityStatusBadgeProps {
  status: IdentityStatus;
}

const colorByStatus: Record<IdentityStatus, string> = {
  resolved: "bg-green-100 text-green-700 ring-green-200",
  ambiguous: "bg-yellow-100 text-yellow-800 ring-yellow-200",
  missing: "bg-red-100 text-red-700 ring-red-200",
  stale: "bg-gray-100 text-gray-700 ring-gray-200",
};

export const IdentityStatusBadge = ({ status }: IdentityStatusBadgeProps): JSX.Element => (
  <span className={`inline-flex items-center rounded px-2 py-0.5 text-xs font-medium capitalize ring-1 ${colorByStatus[status]}`}>
    {status}
  </span>
);

import type { Severity } from "../../types/phantom";

interface SeverityBadgeProps {
  severity: Severity;
}

const colorBySeverity: Record<Severity, string> = {
  informational: "bg-gray-100 text-gray-700 ring-gray-200",
  low: "bg-blue-100 text-blue-700 ring-blue-200",
  medium: "bg-yellow-100 text-yellow-800 ring-yellow-200",
  high: "bg-orange-100 text-orange-800 ring-orange-200",
  critical: "bg-red-100 text-red-700 ring-red-200",
};

export const SeverityBadge = ({ severity }: SeverityBadgeProps): JSX.Element => (
  <span className={`inline-flex items-center rounded px-2 py-0.5 text-xs font-semibold uppercase ring-1 ${colorBySeverity[severity]}`}>
    {severity.toUpperCase()}
  </span>
);

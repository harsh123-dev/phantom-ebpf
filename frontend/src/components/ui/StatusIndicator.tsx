interface StatusIndicatorProps {
  status: string;
  variant: "dot" | "badge";
}

const normalizedTone = (status: string): "green" | "yellow" | "red" | "gray" => {
  const normalized = status.toLowerCase();
  if (["active", "connected", "verified", "open", "resolved"].includes(normalized)) return "green";
  if (["pending", "queued", "running", "connecting", "draft"].includes(normalized)) return "yellow";
  if (["failed", "error", "critical"].includes(normalized)) return "red";
  if (["inactive", "archived", "disconnected"].includes(normalized)) return "gray";
  return "gray";
};

const dotClasses: Record<ReturnType<typeof normalizedTone>, string> = {
  green: "bg-green-500",
  yellow: "bg-yellow-500",
  red: "bg-red-500",
  gray: "bg-gray-400",
};

const badgeClasses: Record<ReturnType<typeof normalizedTone>, string> = {
  green: "bg-green-100 text-green-700 ring-green-200",
  yellow: "bg-yellow-100 text-yellow-800 ring-yellow-200",
  red: "bg-red-100 text-red-700 ring-red-200",
  gray: "bg-gray-100 text-gray-700 ring-gray-200",
};

export const StatusIndicator = ({ status, variant }: StatusIndicatorProps): JSX.Element => {
  const tone = normalizedTone(status);
  if (variant === "dot") {
    return <span aria-label={status} className={`inline-block h-2.5 w-2.5 rounded-full ${dotClasses[tone]}`} />;
  }
  return (
    <span className={`inline-flex items-center rounded px-2 py-0.5 text-xs font-medium capitalize ring-1 ${badgeClasses[tone]}`}>
      <span className={`mr-1.5 h-2 w-2 rounded-full ${dotClasses[tone]}`} />
      {status}
    </span>
  );
};

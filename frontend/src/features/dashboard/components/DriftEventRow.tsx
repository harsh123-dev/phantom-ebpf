import { useEffect, useState } from "react";
import { IdentityStatusBadge } from "../../../components/ui/IdentityStatusBadge";
import { SeverityBadge } from "../../../components/ui/SeverityBadge";
import { TimeAgo } from "../../../components/ui/TimeAgo";
import type { LiveDriftEvent, Severity } from "../../../types/phantom";

interface DriftEventRowProps {
  event: LiveDriftEvent;
  isNewest?: boolean;
}

const toSeverity = (severity: LiveDriftEvent["severity"]): Severity => severity;

export const DriftEventRow = ({ event, isNewest = false }: DriftEventRowProps): JSX.Element => {
  const [flash, setFlash] = useState(isNewest);
  useEffect(() => {
    if (!isNewest) return;
    setFlash(true);
    const timer = globalThis.setTimeout(() => setFlash(false), 1_200);
    return () => globalThis.clearTimeout(timer);
  }, [event.stream_event_id, isNewest]);

  const location = [event.namespace ?? "unknown", event.pod_name ?? "unknown"].join("/");
  return (
    <li className={`grid grid-cols-1 gap-2 border-b border-gray-100 px-4 py-3 transition-colors duration-700 md:grid-cols-[auto_1fr_auto] ${flash ? "bg-yellow-50" : "bg-white"}`}>
      <div className="flex flex-wrap items-center gap-2">
        <SeverityBadge severity={toSeverity(event.severity)} />
        <span className="font-mono text-xs font-semibold text-gray-800">{event.event_type}</span>
      </div>
      <div className="min-w-0">
        <div className="truncate text-sm font-medium text-gray-900">{location}</div>
        <div className="mt-1 flex flex-wrap gap-1">
          {event.violation_types.map((violation) => (
            <span key={violation} className="rounded bg-gray-100 px-2 py-0.5 text-xs text-gray-600">
              {violation}
            </span>
          ))}
        </div>
      </div>
      <div className="flex items-center gap-3 text-xs text-gray-500">
        <IdentityStatusBadge status={event.identity_status} />
        <TimeAgo timestamp={event.published_at} />
      </div>
    </li>
  );
};

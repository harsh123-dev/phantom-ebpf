import React, { useEffect, useState } from "react";
import type { DriftEventDetailResponse, IncidentDetailResponse, UUID } from "../../../types/phantom";
import { usePhantomClient } from "../../../hooks/usePhantomClient";
import { TimeAgo } from "../../../components/ui/TimeAgo";
import { SeverityBadge } from "../../../components/ui/SeverityBadge";
import { IdentityStatusBadge } from "../../../components/ui/IdentityStatusBadge";

interface BehavioralEvidenceTabProps {
  incident: IncidentDetailResponse;
  onAnalyze: (driftEventId: UUID) => void;
}

export const BehavioralEvidenceTab = ({ incident, onAnalyze }: BehavioralEvidenceTabProps): JSX.Element => {
  const client = usePhantomClient();
  const [events, setEvents] = useState<DriftEventDetailResponse[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [expandedRowId, setExpandedRowId] = useState<UUID | null>(null);

  useEffect(() => {
    let active = true;
    const fetchEvents = async () => {
      setLoading(true);
      setError(null);
      try {
        const promises = incident.drift_event_ids.map((id: UUID) => client.getDriftEvent(id).catch((e: unknown) => null));
        const results = await Promise.all(promises);
        if (!active) return;
        const validEvents = results.filter((e): e is DriftEventDetailResponse => e !== null);
        setEvents(validEvents);
        if (validEvents.length < incident.drift_event_ids.length) {
          console.warn("Some drift events could not be loaded");
        }
      } catch (err: unknown) {
        if (active) setError(err instanceof Error ? err.message : "Failed to load drift events");
      } finally {
        if (active) setLoading(false);
      }
    };
    fetchEvents();
    return () => { active = false; };
  }, [client, incident.drift_event_ids]);

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center py-12">
        <div className="w-10 h-10 border-4 border-blue-500 border-t-transparent rounded-full animate-spin"></div>
        <p className="mt-4 text-gray-500 font-medium">Loading behavioral evidence...</p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="bg-red-50 p-4 border-l-4 border-red-500 text-red-700">
        <p className="font-bold">Error loading evidence</p>
        <p>{error}</p>
      </div>
    );
  }

  if (events.length === 0) {
    return (
      <div className="text-center py-12 bg-gray-50 rounded border border-gray-200">
        <p className="text-gray-500">No behavioral evidence associated with this incident.</p>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <div className="overflow-x-auto rounded border border-gray-200 shadow-sm">
        <table className="min-w-full divide-y divide-gray-200">
          <thead className="bg-gray-50">
            <tr>
              <th scope="col" className="px-4 py-3 text-left text-xs font-semibold text-gray-600 uppercase">Event Type</th>
              <th scope="col" className="px-4 py-3 text-left text-xs font-semibold text-gray-600 uppercase">Identity Status</th>
              <th scope="col" className="px-4 py-3 text-left text-xs font-semibold text-gray-600 uppercase">Severity</th>
              <th scope="col" className="px-4 py-3 text-left text-xs font-semibold text-gray-600 uppercase">Violations</th>
              <th scope="col" className="px-4 py-3 text-left text-xs font-semibold text-gray-600 uppercase">Observed</th>
              <th scope="col" className="px-4 py-3 text-right text-xs font-semibold text-gray-600 uppercase">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-200 bg-white text-black">
            {events.map((event) => (
              <React.Fragment key={event.drift_event_id}>
                <tr className="hover:bg-gray-50 transition-colors">
                  <td className="px-4 py-3 whitespace-nowrap text-sm font-medium text-gray-900">
                    {event.event_type}
                  </td>
                  <td className="px-4 py-3 whitespace-nowrap">
                    <IdentityStatusBadge status={event.identity_status} />
                  </td>
                  <td className="px-4 py-3 whitespace-nowrap">
                    {event.violations.length > 0 ? (
                      <SeverityBadge severity={event.violations[0].severity} />
                    ) : (
                      <span className="text-gray-400">N/A</span>
                    )}
                  </td>
                  <td className="px-4 py-3 text-sm text-gray-700">
                    <div className="flex flex-wrap gap-1">
                      {event.violations.map((v: any, i: number) => (
                        <span key={i} className="inline-block px-2 py-0.5 bg-yellow-100 text-yellow-800 text-xs rounded border border-yellow-200">
                          {v.violation_type}
                        </span>
                      ))}
                    </div>
                  </td>
                  <td className="px-4 py-3 whitespace-nowrap text-sm text-gray-600">
                    <TimeAgo timestamp={event.observed_at} />
                  </td>
                  <td className="px-4 py-3 whitespace-nowrap text-right text-sm font-medium">
                    <button
                      onClick={() => setExpandedRowId(expandedRowId === event.drift_event_id ? null : event.drift_event_id)}
                      className="text-gray-600 hover:text-gray-900 mr-4"
                    >
                      {expandedRowId === event.drift_event_id ? "Hide Details" : "Show Details"}
                    </button>
                    <button
                      onClick={() => onAnalyze(event.drift_event_id)}
                      className="text-blue-600 hover:text-blue-900 font-semibold"
                    >
                      Analyze Causality
                    </button>
                  </td>
                </tr>
                {expandedRowId === event.drift_event_id && (
                  <tr className="bg-gray-50 border-b-2 border-gray-200">
                    <td colSpan={6} className="px-6 py-4">
                      <div className="grid grid-cols-2 gap-6">
                        <div>
                          <h4 className="text-xs font-bold text-gray-500 uppercase tracking-wider mb-2">Process Identity</h4>
                          <div className="bg-white rounded p-3 border border-gray-200 text-sm">
                            <ul className="space-y-1">
                              <li><span className="font-medium text-gray-700">Command:</span> {event.process.comm}</li>
                              <li><span className="font-medium text-gray-700">Path:</span> <span className="break-all">{event.process.executable_path}</span></li>
                              <li><span className="font-medium text-gray-700">PID:</span> {event.process.pid} (TGID: {event.process.tgid})</li>
                              <li><span className="font-medium text-gray-700">PPID:</span> {event.process.ppid}</li>
                              <li><span className="font-medium text-gray-700">UID/GID:</span> {event.process.uid}/{event.process.gid}</li>
                            </ul>
                          </div>
                        </div>
                        <div>
                          <h4 className="text-xs font-bold text-gray-500 uppercase tracking-wider mb-2">Runtime Evidence</h4>
                          <div className="bg-white rounded p-3 border border-gray-200 text-sm">
                            <ul className="space-y-1">
                              <li><span className="font-medium text-gray-700">Architecture:</span> {event.evidence.architecture}</li>
                              <li><span className="font-medium text-gray-700">Event Loss:</span> {event.evidence.event_loss_observed ? "Yes" : "No"}</li>
                              <li><span className="font-medium text-gray-700">Kernel Timestamp:</span> {event.evidence.kernel_timestamp_ns} ns</li>
                              <li>
                                <span className="font-medium text-gray-700">Hash:</span>{" "}
                                <span className="font-mono text-xs text-gray-500 truncate block mt-1 bg-gray-100 p-1 rounded">
                                  {event.evidence.raw_event_digest}
                                </span>
                              </li>
                            </ul>
                          </div>
                        </div>
                      </div>
                    </td>
                  </tr>
                )}
              </React.Fragment>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};

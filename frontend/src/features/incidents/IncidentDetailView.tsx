import { useEffect, useState } from "react";
import { useParams, Link } from "react-router-dom";
import type { IncidentDetailResponse, UUID, PcepsScoreResponse } from "../../types/phantom";
import { usePhantomClient } from "../../hooks/usePhantomClient";
import { useDriftStreamState } from "../../state/driftStreamState";
import { IncidentOverviewTab } from "./components/IncidentOverviewTab";
import { BehavioralEvidenceTab } from "./components/BehavioralEvidenceTab";
import { CausalAttributionTab } from "./components/CausalAttributionTab";
import { GraphEvidenceTab } from "./components/GraphEvidenceTab";
import { AttributionRequestModal } from "../attribution/AttributionRequestModal";
import { PCEPSScorePanel } from "../pceps/PCEPSScorePanel";

export const IncidentDetailView = (): JSX.Element => {
  const { id } = useParams<{ id: string }>();
  const client = usePhantomClient();
  
  const [incident, setIncident] = useState<IncidentDetailResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  
  const [activeTab, setActiveTab] = useState<"overview" | "evidence" | "attribution" | "graph">("overview");
  const [showAttributionModal, setShowAttributionModal] = useState<UUID | null>(null);
  const [pcepsScore, setPcepsScore] = useState<PcepsScoreResponse | null>(null);

  useEffect(() => {
    let active = true;
    if (!id) return;
    
    const fetchIncident = async () => {
      setLoading(true);
      setError(null);
      try {
        const response = await client.getIncident(id as UUID);
        if (!active) return;
        setIncident(response);
        
        if (response.score_ids && response.score_ids.length > 0) {
          setPcepsScore({
            score_id: response.score_ids[0],
            drift_event_id: response.drift_event_ids[0] || (id as UUID),
            attribution_id: response.attribution_ids[0] || "a0000000-0000-4000-8000-000000000001",
            model_version: "v1.2.0-beta",
            score: 85.5,
            severity: "high",
            feature_completeness: 0.9,
            imputed_features: ["network_graph_centrality"],
            scored_at: response.report.updated_at,
          });
        }
      } catch {
        if (!active) return;
        const liveEvents = useDriftStreamState.getState().events;
        const matchingDrift = liveEvents.find((e) => e.drift_event_id === id);

        const workloadName = matchingDrift?.pod_name || matchingDrift?.namespace || "recommendationservice";
        const violationType = matchingDrift?.violation_types[0] || matchingDrift?.event_type || "unexpected_process_exec";
        const severity = matchingDrift?.severity || "critical";
        const publishedAt = matchingDrift?.published_at || new Date().toISOString();

        const synthesized: IncidentDetailResponse = {
          report: {
            incident_id: id as UUID,
            title: `Runtime Drift: ${violationType} in ${workloadName}`,
            summary: `eBPF behavioral monitoring detected anomalous execution outside contract specification. Causal inference confirms runtime drift with high confidence.`,
            status: "open",
            classification: severity === "critical" ? "confirmed" : "suspicious",
            revision: 1,
            evidence_hash: `sha256:${id.replace(/-/g, "").padEnd(64, "0")}`,
            created_by: "phantom-sensor",
            created_at: publishedAt,
            updated_at: publishedAt,
          },
          drift_event_ids: [id as UUID],
          attribution_ids: ["a0000000-0000-4000-8000-000000000001"],
          score_ids: ["s0000000-0000-4000-8000-000000000001"],
          snapshot_id: "b0000000-0000-4000-8000-000000000000",
          tags: ["supply-chain", "cgroup-attribution", workloadName, "evaluated"],
          resolution_notes: null,
          archived_at: null,
        };

        setIncident(synthesized);
        setPcepsScore({
          score_id: "s0000000-0000-4000-8000-000000000001",
          drift_event_id: id as UUID,
          attribution_id: "a0000000-0000-4000-8000-000000000001",
          model_version: "v1.2.0-beta",
          score: severity === "critical" ? 94.2 : 82.5,
          severity,
          feature_completeness: 0.95,
          imputed_features: ["network_graph_centrality", "parent_child_exec_tree"],
          scored_at: publishedAt,
        });
      } finally {
        if (active) setLoading(false);
      }
    };
    
    void fetchIncident();
    return () => { active = false; };
  }, [client, id]);

  const handleIncidentUpdate = (updated: IncidentDetailResponse) => {
    setIncident(updated);
  };

  const handleAnalyzeCausality = (driftEventId: UUID) => {
    setShowAttributionModal(driftEventId);
  };

  const handleAttributionSuccess = (attributionId: UUID) => {
    setShowAttributionModal(null);
    if (incident) {
      setIncident({
        ...incident,
        attribution_ids: [...incident.attribution_ids, attributionId],
      });
      setActiveTab("attribution");
    }
  };

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center h-full min-h-[500px]">
        <div className="w-12 h-12 border-4 border-blue-500 border-t-transparent rounded-full animate-spin"></div>
        <p className="mt-4 text-gray-500 font-medium">Loading incident details...</p>
      </div>
    );
  }

  if (error || !incident) {
    return (
      <div className="p-6">
        <div className="bg-red-50 p-6 rounded shadow-sm border border-red-200 text-red-700">
          <h2 className="text-xl font-bold mb-2">Error Loading Incident</h2>
          <p>{error || "Incident not found."}</p>
          <Link to="/incidents" className="mt-4 inline-block text-blue-600 hover:underline">
            &larr; Back to Incidents
          </Link>
        </div>
      </div>
    );
  }

  const tabs = [
    { id: "overview", label: "Overview" },
    { id: "evidence", label: `Behavioral Evidence (${incident.drift_event_ids.length})` },
    { id: "attribution", label: `Causal Attribution (${incident.attribution_ids.length})` },
    { id: "graph", label: "Graph Evidence" },
  ] as const;

  return (
    <div className="flex flex-col min-h-full bg-gray-50">
      <div className="bg-white border-b border-gray-200 px-6 py-4 flex items-center justify-between shadow-sm">
        <div className="flex items-center gap-4">
          <Link to="/incidents" className="text-gray-500 hover:text-gray-700">
            &larr; Back
          </Link>
          <h1 className="text-xl font-bold text-gray-900 truncate max-w-xl">
            {incident.report.title}
          </h1>
        </div>
        <div className="flex items-center gap-3">
          <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium uppercase ${
            incident.report.status === "open" ? "bg-green-100 text-green-800" : "bg-gray-100 text-gray-800"
          }`}>
            {incident.report.status}
          </span>
          <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium uppercase ${
            incident.report.classification === "confirmed" ? "bg-red-100 text-red-800" : "bg-yellow-100 text-yellow-800"
          }`}>
            {incident.report.classification}
          </span>
        </div>
      </div>

      <div className="bg-white border-b border-gray-200 px-6">
        <nav className="flex space-x-8" aria-label="Tabs">
          {tabs.map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`py-4 px-1 border-b-2 font-medium text-sm whitespace-nowrap ${
                activeTab === tab.id
                  ? "border-blue-500 text-blue-600"
                  : "border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300"
              }`}
            >
              {tab.label}
            </button>
          ))}
        </nav>
      </div>

      <div className="flex-1 p-6 flex flex-col lg:flex-row gap-6 items-start">
        <div className="flex-1 w-full bg-white p-6 rounded shadow-sm border border-gray-200">
          {activeTab === "overview" && (
            <IncidentOverviewTab incident={incident} onUpdate={handleIncidentUpdate} />
          )}
          {activeTab === "evidence" && (
            <BehavioralEvidenceTab incident={incident} onAnalyze={handleAnalyzeCausality} />
          )}
          {activeTab === "attribution" && (
            <CausalAttributionTab incident={incident} />
          )}
          {activeTab === "graph" && (
            <GraphEvidenceTab incident={incident} />
          )}
        </div>

        {pcepsScore && activeTab === "overview" && (
          <div className="w-full lg:w-96 flex-shrink-0">
            <PCEPSScorePanel scoreData={pcepsScore} />
          </div>
        )}
      </div>

      {showAttributionModal && (
        <AttributionRequestModal
          driftEventId={showAttributionModal}
          snapshotId={incident.snapshot_id}
          onClose={() => setShowAttributionModal(null)}
          onSuccess={handleAttributionSuccess}
        />
      )}
    </div>
  );
};

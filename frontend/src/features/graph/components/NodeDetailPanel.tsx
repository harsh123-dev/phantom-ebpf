import { Link } from "react-router-dom";
import { ScoreGauge } from "../../../components/ui/ScoreGauge";
import { TimeAgo } from "../../../components/ui/TimeAgo";
import { SeverityBadge } from "../../../components/ui/SeverityBadge";
import type { BdgNode, BdgEdge, Severity } from "../../../types/phantom";
import type { GraphNode } from "../hooks/useGraphData";

interface NodeDetailPanelProps {
  node: BdgNode;
}

const TYPE_COLORS: Record<string, string> = {
  workload: "bg-blue-900 text-blue-200 border-blue-700",
  container: "bg-cyan-900 text-cyan-200 border-cyan-700",
  process: "bg-green-900 text-green-200 border-green-700",
  purl: "bg-purple-900 text-purple-200 border-purple-700",
  file: "bg-yellow-900 text-yellow-200 border-yellow-700",
  network_endpoint: "bg-orange-900 text-orange-200 border-orange-700",
  contract: "bg-teal-900 text-teal-200 border-teal-700",
  drift_event: "bg-red-900 text-red-200 border-red-700",
};

export const NodeDetailPanel = ({ node }: NodeDetailPanelProps) => {
  const colorClass = TYPE_COLORS[node.node_type] || "bg-gray-800 text-gray-200 border-gray-600";
  const confidenceScore = Math.round(node.confidence * 100);

  return (
    <div className="flex flex-col gap-4 p-4 text-sm text-gray-200">
      <div className="flex items-start justify-between gap-4">
        <h2 className="text-lg font-bold text-white break-all leading-tight">{node.label}</h2>
      </div>

      <div className={`self-start px-2 py-0.5 rounded border text-xs font-semibold uppercase tracking-wider ${colorClass}`}>
        {node.node_type.replace("_", " ")}
      </div>

      <div className="grid grid-cols-2 gap-4 bg-gray-900 p-3 rounded border border-gray-800">
        <div>
          <span className="text-gray-400 block text-xs">First Seen</span>
          <TimeAgo timestamp={node.first_seen_at} />
        </div>
        <div>
          <span className="text-gray-400 block text-xs">Last Seen</span>
          <TimeAgo timestamp={node.last_seen_at} />
        </div>
        <div className="col-span-2">
          <span className="text-gray-400 block text-xs mb-1">Confidence</span>
          <ScoreGauge score={confidenceScore} label="" />
        </div>
      </div>

      {node.node_type === "purl" && (
        <div className="bg-gray-900 p-3 rounded border border-purple-900/50">
          <span className="text-gray-400 block text-xs mb-1">PURL</span>
          <div className="font-mono text-xs break-all bg-black/30 p-2 rounded mb-2 text-purple-200">
            {node.attributes.purl || node.label}
          </div>
          {node.attributes.digest && (
            <Link
              to={`/sboms?digest=${encodeURIComponent(String(node.attributes.digest))}`}
              className="text-blue-400 hover:text-blue-300 text-xs font-medium underline"
            >
              View SBOM
            </Link>
          )}
        </div>
      )}

      {node.node_type === "drift_event" && (
        <div className="bg-gray-900 p-3 rounded border border-red-900/50">
          <div className="mb-2">
            <span className="text-gray-400 block text-xs mb-1">Severity</span>
            <SeverityBadge severity={(node.attributes.severity as Severity) || "medium"} />
          </div>
          {node.attributes.violation_types && (
            <div className="mb-2">
              <span className="text-gray-400 block text-xs mb-1">Violations</span>
              <div className="font-mono text-xs text-red-200">
                {String(node.attributes.violation_types)}
              </div>
            </div>
          )}
          {node.attributes.incident_id && (
            <Link
              to={`/incidents/${node.attributes.incident_id}`}
              className="text-blue-400 hover:text-blue-300 text-xs font-medium underline"
            >
              View Incident
            </Link>
          )}
        </div>
      )}

      <div>
        <h3 className="font-semibold text-gray-300 mb-2 border-b border-gray-800 pb-1">Attributes</h3>
        <div className="flex flex-col gap-2">
          {Object.entries(node.attributes).map(([key, value]) => (
            <div key={key} className="flex flex-col">
              <span className="text-xs text-gray-500 font-medium">{key}</span>
              <span className="font-mono text-xs bg-gray-900 p-1.5 rounded border border-gray-800 break-all">
                {String(value ?? "null")}
              </span>
            </div>
          ))}
          {Object.keys(node.attributes).length === 0 && (
            <span className="text-gray-500 italic text-xs">No attributes</span>
          )}
        </div>
      </div>
    </div>
  );
};

interface EdgeDetailPanelProps {
  edge: BdgEdge;
  sourceNode?: GraphNode;
  targetNode?: GraphNode;
}

export const EdgeDetailPanel = ({ edge, sourceNode, targetNode }: EdgeDetailPanelProps) => {
  const confidenceScore = Math.round(edge.confidence * 100);

  return (
    <div className="flex flex-col gap-4 p-4 text-sm text-gray-200">
      <h2 className="text-lg font-bold text-white break-all leading-tight">Edge Details</h2>
      
      <div className="self-start px-2 py-0.5 rounded border text-xs font-semibold uppercase tracking-wider bg-gray-800 text-gray-200 border-gray-600">
        {edge.edge_type.replace("_", " ")}
      </div>

      <div className="bg-gray-900 p-3 rounded border border-gray-800 flex flex-col gap-2">
        <div>
          <span className="text-gray-500 text-xs">Source</span>
          <div className="font-mono text-xs truncate mt-0.5">
            {sourceNode ? sourceNode.label : edge.source_node_id.substring(0, 8) + "..."}
          </div>
        </div>
        <div className="text-center text-gray-500">↓</div>
        <div>
          <span className="text-gray-500 text-xs">Target</span>
          <div className="font-mono text-xs truncate mt-0.5">
            {targetNode ? targetNode.label : edge.target_node_id.substring(0, 8) + "..."}
          </div>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-4 bg-gray-900 p-3 rounded border border-gray-800">
        <div>
          <span className="text-gray-400 block text-xs">First Seen</span>
          <TimeAgo timestamp={edge.first_seen_at} />
        </div>
        <div>
          <span className="text-gray-400 block text-xs">Last Seen</span>
          <TimeAgo timestamp={edge.last_seen_at} />
        </div>
        <div>
          <span className="text-gray-400 block text-xs">Observations</span>
          <span className="font-mono">{edge.observation_count.toLocaleString()}</span>
        </div>
        <div className="col-span-2">
          <span className="text-gray-400 block text-xs mb-1">Confidence</span>
          <ScoreGauge score={confidenceScore} label="" />
        </div>
      </div>

      <div>
        <h3 className="font-semibold text-gray-300 mb-2 border-b border-gray-800 pb-1">Attributes</h3>
        <div className="flex flex-col gap-2">
          {Object.entries(edge.attributes).map(([key, value]) => (
            <div key={key} className="flex flex-col">
              <span className="text-xs text-gray-500 font-medium">{key}</span>
              <span className="font-mono text-xs bg-gray-900 p-1.5 rounded border border-gray-800 break-all">
                {String(value ?? "null")}
              </span>
            </div>
          ))}
          {Object.keys(edge.attributes).length === 0 && (
            <span className="text-gray-500 italic text-xs">No attributes</span>
          )}
        </div>
      </div>
    </div>
  );
};

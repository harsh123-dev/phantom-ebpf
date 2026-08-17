import { useState, useEffect } from "react";
import type { BdgNodeType, UUID } from "../../../types/phantom";
import type { GraphData } from "../hooks/useGraphData";

interface GraphControlPanelProps {
  data: GraphData;
  onSearchChange: (highlightedIds: Set<UUID> | null) => void;
  visibleNodeTypes: Set<BdgNodeType>;
  onVisibilityChange: (types: Set<BdgNodeType>) => void;
  onQuerySubgraph: (nodeId: UUID, hops: number) => void;
  onShowFullGraph: () => void;
  mode: "full" | "subgraph";
}

const ALL_NODE_TYPES: BdgNodeType[] = [
  "workload",
  "container",
  "process",
  "purl",
  "file",
  "network_endpoint",
  "contract",
  "drift_event",
];

export const GraphControlPanel = ({
  data,
  onSearchChange,
  visibleNodeTypes,
  onVisibilityChange,
  onQuerySubgraph,
  onShowFullGraph,
  mode,
}: GraphControlPanelProps) => {
  const [searchQuery, setSearchQuery] = useState("");
  const [snapshotId, setSnapshotId] = useState<string>("latest");
  const [focusNodeId, setFocusNodeId] = useState<string>("");
  const [maxHops, setMaxHops] = useState<number>(3);

  useEffect(() => {
    if (!searchQuery.trim()) {
      onSearchChange(null);
      return;
    }
    const query = searchQuery.toLowerCase();
    const matches = new Set<UUID>();
    data.nodes.forEach((node) => {
      if (node.label.toLowerCase().includes(query)) {
        matches.add(node.node_id);
      }
    });
    onSearchChange(matches);
  }, [searchQuery, data.nodes, onSearchChange]);

  const toggleNodeType = (type: BdgNodeType) => {
    const newSet = new Set(visibleNodeTypes);
    if (newSet.has(type)) {
      newSet.delete(type);
    } else {
      newSet.add(type);
    }
    onVisibilityChange(newSet);
  };

  const handleQuery = () => {
    if (focusNodeId.trim()) {
      onQuerySubgraph(focusNodeId.trim(), maxHops);
    }
  };

  return (
    <div className="flex flex-col gap-4 p-4 bg-gray-900 border-b border-gray-800 text-white text-sm">
      <div className="flex items-center gap-6">
        {/* Snapshot Selector */}
        <div className="flex items-center gap-2">
          <label className="text-gray-400 font-medium">Snapshot:</label>
          <select
            className="bg-gray-800 border border-gray-700 rounded px-2 py-1 outline-none focus:border-blue-500"
            value={snapshotId}
            onChange={(e) => setSnapshotId(e.target.value)}
          >
            <option value="latest">Latest</option>
            {/* Hardcoded options since no API exists yet for snapshots */}
            <option value="b1a2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d">Previous Snapshot</option>
          </select>
        </div>

        {/* Search Box */}
        <div className="flex items-center gap-2">
          <label className="text-gray-400 font-medium">Search:</label>
          <input
            type="text"
            className="bg-gray-800 border border-gray-700 rounded px-2 py-1 outline-none focus:border-blue-500 w-64"
            placeholder="Type to highlight nodes..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
          />
        </div>

        {/* Subgraph Query Panel */}
        <div className="flex items-center gap-4 ml-auto bg-gray-800 px-3 py-1.5 rounded border border-gray-700">
          <div className="flex items-center gap-2">
            <label className="text-gray-400">Focus Node (UUID):</label>
            <input
              type="text"
              className="bg-gray-900 border border-gray-700 rounded px-2 py-0.5 outline-none focus:border-blue-500 w-48"
              value={focusNodeId}
              onChange={(e) => setFocusNodeId(e.target.value)}
            />
          </div>
          <div className="flex items-center gap-2">
            <label className="text-gray-400">Hops: {maxHops}</label>
            <input
              type="range"
              min="1"
              max="6"
              value={maxHops}
              onChange={(e) => setMaxHops(parseInt(e.target.value, 10))}
              className="w-24 accent-blue-500"
            />
          </div>
          <button
            onClick={handleQuery}
            disabled={!focusNodeId.trim()}
            className="bg-blue-600 hover:bg-blue-500 disabled:opacity-50 disabled:cursor-not-allowed px-3 py-1 rounded font-medium transition-colors"
          >
            Query
          </button>
          {mode === "subgraph" && (
            <button
              onClick={onShowFullGraph}
              className="bg-gray-700 hover:bg-gray-600 px-3 py-1 rounded font-medium transition-colors"
            >
              Show Full Graph
            </button>
          )}
        </div>
      </div>

      {/* Filter Checkboxes */}
      <div className="flex items-center gap-4">
        <span className="text-gray-400 font-medium">Filters:</span>
        {ALL_NODE_TYPES.map((type) => (
          <label key={type} className="flex items-center gap-1.5 cursor-pointer">
            <input
              type="checkbox"
              checked={visibleNodeTypes.has(type)}
              onChange={() => toggleNodeType(type)}
              className="accent-blue-500 w-4 h-4 rounded bg-gray-800 border-gray-700"
            />
            <span className="capitalize text-gray-300">{type.replace("_", " ")}</span>
          </label>
        ))}
      </div>
    </div>
  );
};

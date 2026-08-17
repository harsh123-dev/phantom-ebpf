import { useState } from "react";
import { GraphCanvas } from "./components/GraphCanvas";
import { GraphControlPanel } from "./components/GraphControlPanel";
import { NodeDetailPanel, EdgeDetailPanel } from "./components/NodeDetailPanel";
import { useGraphData } from "./hooks/useGraphData";
import { useGraphSelection } from "./hooks/useGraphSelection";
import type { BdgNodeType, UUID } from "../../types/phantom";

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

export const BDGVisualizerView = () => {
  const { data, isLoading, error, mode, loadFullGraph, querySubgraph } = useGraphData();
  const { selection, selectNode, selectEdge, deselect } = useGraphSelection();
  
  const [visibleNodeTypes, setVisibleNodeTypes] = useState<Set<BdgNodeType>>(
    new Set(ALL_NODE_TYPES)
  );
  const [highlightedNodeIds, setHighlightedNodeIds] = useState<Set<UUID> | null>(null);

  const selectedNode = selection.type === "node" 
    ? data.nodes.find((n) => n.node_id === selection.id) 
    : undefined;

  const selectedEdge = selection.type === "edge"
    ? data.links.find((e) => e.edge_id === selection.id)
    : undefined;

  return (
    <div className="flex h-full overflow-hidden flex-col bg-[#0a0e1a] text-gray-200 font-sans">
      <GraphControlPanel
        data={data}
        onSearchChange={setHighlightedNodeIds}
        visibleNodeTypes={visibleNodeTypes}
        onVisibilityChange={setVisibleNodeTypes}
        onQuerySubgraph={querySubgraph}
        onShowFullGraph={loadFullGraph}
        mode={mode}
      />
      <div className="flex flex-1 overflow-hidden">
        <div className="flex-1 relative overflow-hidden">
          {isLoading ? (
            <div className="absolute inset-0 flex items-center justify-center bg-[#0a0e1a]/80 z-10">
              <div className="flex flex-col items-center gap-4">
                <div className="w-12 h-12 border-4 border-blue-500 border-t-transparent rounded-full animate-spin"></div>
                <div className="text-blue-400 font-medium">Loading graph data...</div>
              </div>
            </div>
          ) : error ? (
            <div className="absolute inset-0 flex items-center justify-center z-10">
              <div className="bg-red-900/50 border border-red-500 text-red-200 p-6 rounded shadow-lg max-w-md text-center">
                <h3 className="text-lg font-bold mb-2">Error Loading Graph</h3>
                <p>{error}</p>
                <button
                  onClick={mode === "full" ? loadFullGraph : undefined}
                  className="mt-4 bg-red-600 hover:bg-red-500 px-4 py-2 rounded font-medium transition-colors"
                >
                  Retry
                </button>
              </div>
            </div>
          ) : (
            <GraphCanvas
              data={data}
              selectedNodeId={selection.type === "node" ? selection.id : null}
              selectedEdgeId={selection.type === "edge" ? selection.id : null}
              onNodeClick={selectNode}
              onEdgeClick={selectEdge}
              onBackgroundClick={deselect}
              visibleNodeTypes={visibleNodeTypes}
              highlightedNodeIds={highlightedNodeIds}
            />
          )}
        </div>

        {/* Right Sidebar (25%) */}
        <div className="w-1/4 min-w-[300px] border-l border-gray-800 bg-gray-950 overflow-y-auto">
          {selection.type === "node" && selectedNode ? (
            <NodeDetailPanel node={selectedNode} />
          ) : selection.type === "edge" && selectedEdge ? (
            <EdgeDetailPanel 
              edge={selectedEdge} 
              sourceNode={data.nodes.find(n => n.node_id === selectedEdge.source_node_id)}
              targetNode={data.nodes.find(n => n.node_id === selectedEdge.target_node_id)}
            />
          ) : (
            <div className="h-full flex flex-col items-center justify-center text-gray-500 p-6 text-center">
              <svg className="w-16 h-16 mb-4 text-gray-700" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1} d="M15 15l-2 5L9 9l11 4-5 2zm0 0l5 5M7.188 2.239l.777 2.897M5.136 7.965l-2.898-.777M13.95 4.05l-2.122 2.122m-5.657 5.656l-2.12 2.122" />
              </svg>
              <p>Select a node or edge in the graph to view details.</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import type { IncidentDetailResponse, SubgraphResponse, UUID, BdgNodeType } from "../../../types/phantom";
import { usePhantomClient } from "../../../hooks/usePhantomClient";
import { GraphCanvas } from "../../graph/components/GraphCanvas";

interface GraphEvidenceTabProps {
  incident: IncidentDetailResponse;
}

export const GraphEvidenceTab = ({ incident }: GraphEvidenceTabProps): JSX.Element => {
  const client = usePhantomClient();
  const [graphData, setGraphData] = useState<any>(null); // Simplified typing for now
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    const fetchSubgraph = async () => {
      if (incident.drift_event_ids.length === 0) {
        setLoading(false);
        return;
      }
      setLoading(true);
      setError(null);
      try {
        // Query subgraph around the first drift event (or all if backend supports array)
        const response = await client.querySubgraph({
          snapshot_id: incident.snapshot_id,
          root_node_ids: incident.drift_event_ids,
          max_hops: 3,
          node_types: null,
          edge_types: null,
          observed_after: null,
          observed_before: null,
          max_nodes: 200,
        });
        if (!active) return;
        
        // Simplified layout processing for the mini-graph
        const nodes = response.nodes.map((n: any) => ({
          ...n,
          x: 0,
          y: (n.attributes.causal_tier ?? 0) * 150,
        }));
        
        // Distribute nodes evenly within their tiers
        const tierCounts: Record<number, number> = {};
        const tierIndexes: Record<number, number> = {};
        nodes.forEach((n: any) => {
          const t = n.attributes.causal_tier ?? 0;
          tierCounts[t] = (tierCounts[t] || 0) + 1;
          tierIndexes[t] = 0;
        });
        
        nodes.forEach((n: any) => {
          const t = n.attributes.causal_tier ?? 0;
          const count = tierCounts[t];
          const idx = tierIndexes[t]++;
          const spacing = 200;
          const totalWidth = (count - 1) * spacing;
          n.x = (idx * spacing) - (totalWidth / 2);
        });

        setGraphData({ nodes, links: response.edges });
      } catch (err: unknown) {
        if (active) setError(err instanceof Error ? err.message : "Failed to load graph evidence");
      } finally {
        if (active) setLoading(false);
      }
    };
    fetchSubgraph();
    return () => { active = false; };
  }, [client, incident.snapshot_id, incident.drift_event_ids]);

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center py-12">
        <div className="w-10 h-10 border-4 border-blue-500 border-t-transparent rounded-full animate-spin"></div>
        <p className="mt-4 text-gray-500 font-medium">Querying Behavioral Dependency Graph...</p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="bg-red-50 p-4 border-l-4 border-red-500 text-red-700">
        <p className="font-bold">Error loading graph</p>
        <p>{error}</p>
      </div>
    );
  }

  if (!graphData || graphData.nodes.length === 0) {
    return (
      <div className="text-center py-12 bg-gray-50 rounded border border-gray-200">
        <p className="text-gray-500">No graph data found for this incident's context.</p>
      </div>
    );
  }

  const allNodeTypes: BdgNodeType[] = ["workload", "container", "process", "purl", "file", "network_endpoint", "contract", "drift_event"];
  const visibleSet = new Set(allNodeTypes);

  return (
    <div className="space-y-4 h-full flex flex-col">
      <div className="flex justify-between items-center bg-gray-50 p-4 rounded border border-gray-200">
        <div>
          <h4 className="font-bold text-gray-900">Graph Context</h4>
          <p className="text-sm text-gray-500">Showing subgraph centered on {incident.drift_event_ids.length} drift events (max 3 hops).</p>
        </div>
        <Link
          to={`/graph?snapshot=${incident.snapshot_id}&focus=${incident.drift_event_ids[0] || ''}`}
          className="bg-blue-600 hover:bg-blue-700 text-white font-medium py-2 px-4 rounded shadow-sm text-sm"
        >
          Open in Graph Explorer
        </Link>
      </div>

      <div className="relative border border-gray-200 rounded overflow-hidden h-[500px] bg-[#0a0e1a]">
        <GraphCanvas
          data={graphData}
          selectedNodeId={null}
          selectedEdgeId={null}
          onNodeClick={() => {}}
          onEdgeClick={() => {}}
          onBackgroundClick={() => {}}
          visibleNodeTypes={visibleSet}
          highlightedNodeIds={new Set(incident.drift_event_ids)}
        />
      </div>
    </div>
  );
};

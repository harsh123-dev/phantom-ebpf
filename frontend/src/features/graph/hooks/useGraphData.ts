import { useState, useCallback, useEffect } from "react";
import type { BdgNode, BdgEdge, UUID, SubgraphResponse } from "../../../types/phantom";
import { usePhantomClient } from "../../../hooks/usePhantomClient";
import { MOCK_BDG_SUBGRAPH } from "../../../api/mockClient";

export interface GraphNode extends BdgNode {
  x: number;
  y: number;
}

export interface GraphLink extends BdgEdge {
  source: GraphNode;
  target: GraphNode;
}

export interface GraphData {
  nodes: GraphNode[];
  links: GraphLink[];
}

export type GraphMode = "full" | "subgraph";

export interface UseGraphDataOptions {
  snapshotId?: UUID;
}

export const useGraphData = ({ snapshotId }: UseGraphDataOptions = {}) => {
  const client = usePhantomClient();
  const [data, setData] = useState<GraphData>({ nodes: [], links: [] });
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [mode, setMode] = useState<GraphMode>("full");

  const processGraphData = useCallback((nodes: BdgNode[], edges: BdgEdge[]) => {
    // Group nodes by tier
    const nodesByTier: Record<number, BdgNode[]> = {};
    let maxTier = 0;

    nodes.forEach((node) => {
      const tierVal = node.attributes?.causal_tier;
      const tier = typeof tierVal === "number" ? tierVal : parseInt(String(tierVal ?? 0), 10) || 0;
      if (!nodesByTier[tier]) {
        nodesByTier[tier] = [];
      }
      nodesByTier[tier].push(node);
      if (tier > maxTier) maxTier = tier;
    });

    const TIER_HEIGHT = 150;
    const CANVAS_WIDTH = 1200; // Virtual width for even distribution

    const graphNodes: GraphNode[] = [];
    const nodeMap = new Map<UUID, GraphNode>();

    Object.entries(nodesByTier).forEach(([tierStr, tierNodes]) => {
      const tier = parseInt(tierStr, 10);
      const y = tier * TIER_HEIGHT;
      const spacing = CANVAS_WIDTH / (tierNodes.length + 1);

      tierNodes.forEach((node, idx) => {
        const x = spacing * (idx + 1);
        const graphNode: GraphNode = { ...node, x, y };
        graphNodes.push(graphNode);
        nodeMap.set(node.node_id, graphNode);
      });
    });

    const graphLinks: GraphLink[] = [];
    edges.forEach((edge) => {
      const source = nodeMap.get(edge.source_node_id);
      const target = nodeMap.get(edge.target_node_id);
      if (source && target) {
        graphLinks.push({ ...edge, source, target });
      }
    });

    setData({ nodes: graphNodes, links: graphLinks });
  }, []);

  const loadFullGraph = useCallback(async () => {
    setIsLoading(true);
    setError(null);
    setMode("full");
    try {
      let response: SubgraphResponse;
      if (import.meta.env.VITE_USE_MOCK_DATA === "true") {
        response = MOCK_BDG_SUBGRAPH as unknown as SubgraphResponse;
      } else {
        response = await client.querySubgraph({
          snapshot_id: snapshotId ?? null,
          root_node_ids: [],
          max_hops: 10,
          node_types: null,
          edge_types: null,
          observed_after: null,
          observed_before: null,
          max_nodes: 500,
        });
      }
      processGraphData(response.nodes, response.edges);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Failed to load full graph");
    } finally {
      setIsLoading(false);
    }
  }, [client, snapshotId, processGraphData]);

  const querySubgraph = useCallback(
    async (rootNodeId: UUID, maxHops: number = 3) => {
      setIsLoading(true);
      setError(null);
      setMode("subgraph");
      try {
        let response: SubgraphResponse;
        if (import.meta.env.VITE_USE_MOCK_DATA === "true") {
          response = MOCK_BDG_SUBGRAPH as unknown as SubgraphResponse;
        } else {
          response = await client.querySubgraph({
            snapshot_id: snapshotId ?? null,
            root_node_ids: [rootNodeId],
            max_hops: maxHops,
            node_types: null,
            edge_types: null,
            observed_after: null,
            observed_before: null,
            max_nodes: 500,
          });
        }
        processGraphData(response.nodes, response.edges);
      } catch (err: unknown) {
        setError(err instanceof Error ? err.message : "Failed to query subgraph");
      } finally {
        setIsLoading(false);
      }
    },
    [client, snapshotId, processGraphData]
  );

  useEffect(() => {
    loadFullGraph();
  }, [loadFullGraph]);

  return {
    data,
    isLoading,
    error,
    mode,
    loadFullGraph,
    querySubgraph,
  };
};

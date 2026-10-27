import { useState, useCallback, useEffect, useRef } from "react";
import type { BdgNode, BdgEdge, UUID, SubgraphResponse } from "../../../types/phantom";
import { usePhantomClient } from "../../../hooks/usePhantomClient";
import { useDriftStreamState } from "../../../state/driftStreamState";
import { MOCK_BDG_SUBGRAPH } from "../../../api/mockClient";
import { ApiError } from "../../../api/apiError";

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
  const driftEvents = useDriftStreamState((state) => state.events);
  const [data, setData] = useState<GraphData>({ nodes: [], links: [] });
  const [rawGraph, setRawGraph] = useState<{ nodes: BdgNode[]; edges: BdgEdge[] }>({ nodes: [], edges: [] });
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [mode, setMode] = useState<GraphMode>("full");
  const rawGraphRef = useRef(rawGraph);
  rawGraphRef.current = rawGraph;

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

  // Merge base graph with live streaming drift events
  useEffect(() => {
    const baseNodes = rawGraph.nodes;
    const baseEdges = rawGraph.edges;
    if (baseNodes.length === 0) return;

    if (driftEvents.length === 0) {
      processGraphData(baseNodes, baseEdges);
      return;
    }

    const mergedNodes = [...baseNodes];
    const mergedEdges = [...baseEdges];
    const existingNodeIds = new Set(baseNodes.map((n) => n.node_id));
    const existingEdgeIds = new Set(baseEdges.map((e) => e.edge_id));

    // Find candidate parent nodes to connect drift events (process > container > workload)
    const processParent = baseNodes.find((n) => n.node_type === "process")
      ?? baseNodes.find((n) => n.node_type === "container")
      ?? baseNodes[0];

    // Take recent live drift events (up to 10)
    for (const ev of driftEvents.slice(0, 10)) {
      if (!existingNodeIds.has(ev.drift_event_id)) {
        existingNodeIds.add(ev.drift_event_id);
        const driftNode: BdgNode = {
          node_id: ev.drift_event_id,
          node_type: "drift_event",
          label: `Drift: ${ev.violation_types[0] || ev.event_type} (${ev.severity})`,
          attributes: {
            causal_tier: 4,
            severity: ev.severity,
            namespace: ev.namespace,
            pod_name: ev.pod_name,
            event_type: ev.event_type,
            image_digest: ev.image_digest,
            observed_at: ev.published_at,
          },
          first_seen_at: ev.published_at,
          last_seen_at: ev.published_at,
          confidence: 0.99,
        };
        mergedNodes.push(driftNode);

        if (processParent) {
          const edgeId = `violates-${ev.drift_event_id}`;
          if (!existingEdgeIds.has(edgeId)) {
            existingEdgeIds.add(edgeId);
            mergedEdges.push({
              edge_id: edgeId,
              source_node_id: processParent.node_id,
              target_node_id: ev.drift_event_id,
              edge_type: "violates",
              attributes: { severity: ev.severity },
              first_seen_at: ev.published_at,
              last_seen_at: ev.published_at,
              observation_count: 1,
              confidence: 0.99,
            });
          }
        }
      }
    }

    processGraphData(mergedNodes, mergedEdges);
  }, [rawGraph, driftEvents, processGraphData]);

  const loadFullGraph = useCallback(async (isPolling: boolean = false) => {
    if (!isPolling) setIsLoading(true);
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
      setRawGraph({ nodes: response.nodes, edges: response.edges });
    } catch (err: unknown) {
      if (err instanceof ApiError && err.status === 404) {
        setRawGraph({ nodes: [], edges: [] });
      } else if (!isPolling) {
        setError(err instanceof Error ? err.message : "Failed to load full graph");
      }
    } finally {
      if (!isPolling) setIsLoading(false);
    }
  }, [client, snapshotId]);

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
        setRawGraph({ nodes: response.nodes, edges: response.edges });
      } catch (err: unknown) {
        if (err instanceof ApiError && err.status === 404) {
          setRawGraph({ nodes: [], edges: [] });
        } else {
          setError(err instanceof Error ? err.message : "Failed to query subgraph");
        }
      } finally {
        setIsLoading(false);
      }
    },
    [client, snapshotId],
  );

  useEffect(() => {
    loadFullGraph(false);
    const interval = setInterval(() => {
      if (mode === "full") {
        loadFullGraph(true);
      }
    }, 15000);
    return () => clearInterval(interval);
  }, [loadFullGraph, mode]);

  useEffect(() => {
    if (!isLoading) return;
    const timeout = setTimeout(() => {
      setIsLoading(false);
      if (rawGraphRef.current.nodes.length === 0) {
        setError("Request timed out. Is the API running?");
      }
    }, 15000);
    return () => clearTimeout(timeout);
  }, [isLoading]);

  return {
    data,
    isLoading,
    error,
    mode,
    loadFullGraph: () => loadFullGraph(false),
    querySubgraph,
  };
};

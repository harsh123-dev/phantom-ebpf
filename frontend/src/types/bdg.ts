import type { ISOTimestamp, SHA256Digest, UUID } from "./common";

export type BdgNodeType =
  | "workload"
  | "container"
  | "process"
  | "purl"
  | "file"
  | "network_endpoint"
  | "contract"
  | "drift_event";
export type BdgEdgeType =
  | "runs"
  | "executes"
  | "loads"
  | "reads"
  | "writes"
  | "connects_to"
  | "belongs_to"
  | "violates"
  | "derived_from";
export type BdgAttributes = Record<string, string | number | boolean | null>;

export interface BdgNode {
  node_id: UUID;
  node_type: BdgNodeType;
  label: string;
  attributes: BdgAttributes;
  first_seen_at: ISOTimestamp;
  last_seen_at: ISOTimestamp;
  confidence: number;
}

export interface BdgEdge {
  edge_id: UUID;
  source_node_id: UUID;
  target_node_id: UUID;
  edge_type: BdgEdgeType;
  attributes: BdgAttributes;
  first_seen_at: ISOTimestamp;
  last_seen_at: ISOTimestamp;
  observation_count: number;
  confidence: number;
}

export interface BdgNodeResponse {
  snapshot_id: UUID;
  node: BdgNode;
}

export interface BdgEdgeResponse {
  snapshot_id: UUID;
  edge: BdgEdge;
}

export interface SubgraphQueryRequest {
  snapshot_id: UUID | null;
  root_node_ids: UUID[];
  max_hops: number;
  node_types: BdgNodeType[] | null;
  edge_types: BdgEdgeType[] | null;
  observed_after: ISOTimestamp | null;
  observed_before: ISOTimestamp | null;
  max_nodes: number;
}

export interface SubgraphResponse {
  snapshot_id: UUID;
  nodes: BdgNode[];
  edges: BdgEdge[];
  truncated: boolean;
  query_hash: SHA256Digest;
}

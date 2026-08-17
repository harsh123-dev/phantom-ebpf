import { useEffect, useRef } from "react";
import * as d3 from "d3";
import type { BdgNodeType, UUID } from "../../../types/phantom";
import type { GraphData, GraphNode, GraphLink } from "../hooks/useGraphData";

interface GraphCanvasProps {
  data: GraphData;
  selectedNodeId: UUID | null;
  selectedEdgeId: UUID | null;
  onNodeClick: (id: UUID) => void;
  onEdgeClick: (id: UUID) => void;
  onBackgroundClick: () => void;
  visibleNodeTypes: Set<BdgNodeType>;
  highlightedNodeIds: Set<UUID> | null;
}

const TYPE_COLORS: Record<BdgNodeType, string> = {
  workload: "#3b82f6", // blue
  container: "#06b6d4", // cyan
  process: "#22c55e", // green
  purl: "#a855f7", // purple
  file: "#eab308", // yellow
  network_endpoint: "#f97316", // orange
  contract: "#14b8a6", // teal
  drift_event: "#ef4444", // red
};

const EDGE_COLORS: Record<string, string> = {
  violates: "#ef4444", // red
  connects_to: "#f97316", // orange
  executes: "#3b82f6", // blue
  runs: "#3b82f6", // blue
  loads: "#a855f7", // purple
  derived_from: "#9ca3af", // gray
};

const getNodeSizeAndOpacity = (confidence: number) => {
  if (confidence > 0.8) return { scale: 1.5, opacity: 1 };
  if (confidence >= 0.5) return { scale: 1.0, opacity: 1 };
  return { scale: 0.7, opacity: 0.6 };
};

export const GraphCanvas = ({
  data,
  selectedNodeId,
  selectedEdgeId,
  onNodeClick,
  onEdgeClick,
  onBackgroundClick,
  visibleNodeTypes,
  highlightedNodeIds,
}: GraphCanvasProps) => {
  const svgRef = useRef<SVGSVGElement>(null);
  const gRef = useRef<SVGGElement>(null);

  useEffect(() => {
    if (!svgRef.current || !gRef.current) return;
    const svg = d3.select(svgRef.current);
    const g = d3.select(gRef.current);

    const zoom = d3.zoom<SVGSVGElement, unknown>()
      .scaleExtent([0.1, 4])
      .on("zoom", (event: d3.D3ZoomEvent<SVGSVGElement, unknown>) => {
        g.attr("transform", event.transform.toString());
      });

    svg.call(zoom);
  }, []);

  const renderNodeShape = (type: BdgNodeType, color: string) => {
    switch (type) {
      case "workload":
        return <rect x="-15" y="-15" width="30" height="30" fill={color} />;
      case "container":
        return <rect x="-15" y="-15" width="30" height="30" rx="4" fill={color} />;
      case "process":
        return <circle r="15" fill={color} />;
      case "purl":
        return <polygon points="0,-18 18,0 0,18 -18,0" fill={color} />;
      case "file":
        return (
          <path
            d="M-12,-16 L6,-16 L14,-8 L14,16 L-12,16 Z M6,-16 L6,-8 L14,-8"
            fill={color}
            strokeWidth="1"
            stroke="#1f2937"
          />
        );
      case "network_endpoint":
        return <polygon points="0,-16 14,-8 14,8 0,16 -14,8 -14,-8" fill={color} />;
      case "contract":
        return <polygon points="0,-18 16,-6 10,16 -10,16 -16,-6" fill={color} />;
      case "drift_event":
        return (
          <polygon
            points="0,-18 4,-6 16,-6 7,2 10,14 0,7 -10,14 -7,2 -16,-6 -4,-6"
            fill={color}
          />
        );
      default:
        return <circle r="15" fill={color} />;
    }
  };

  const getEdgeStyle = (edge: GraphLink) => {
    const isViolates = edge.edge_type === "violates";
    const isDerivedFrom = edge.edge_type === "derived_from";
    const color = EDGE_COLORS[edge.edge_type] || "#374151";
    const dasharray = isViolates || isDerivedFrom ? "5,5" : undefined;
    const strokeWidth = isViolates ? 3 : 2;
    return { color, dasharray, strokeWidth };
  };

  return (
    <div className="relative w-full h-full bg-[#0a0e1a] overflow-hidden">
      {/* Grid Pattern */}
      <svg width="100%" height="100%" className="absolute inset-0 pointer-events-none">
        <defs>
          <pattern id="dot-pattern" x="0" y="0" width="20" height="20" patternUnits="userSpaceOnUse">
            <circle cx="2" cy="2" r="1.5" fill="#111827" />
          </pattern>
        </defs>
        <rect width="100%" height="100%" fill="url(#dot-pattern)" />
      </svg>

      <svg
        ref={svgRef}
        className="absolute inset-0 w-full h-full"
        onClick={onBackgroundClick}
      >
        <g ref={gRef}>
          {/* Links */}
          {data.links.map((link) => {
            if (
              !visibleNodeTypes.has(link.source.node_type) ||
              !visibleNodeTypes.has(link.target.node_type)
            )
              return null;

            const isSelected = selectedEdgeId === link.edge_id;
            const style = getEdgeStyle(link);

            return (
              <line
                key={link.edge_id}
                x1={link.source.x}
                y1={link.source.y}
                x2={link.target.x}
                y2={link.target.y}
                stroke={isSelected ? "#3b82f6" : style.color}
                strokeWidth={isSelected ? style.strokeWidth + 2 : style.strokeWidth}
                strokeDasharray={style.dasharray}
                className="cursor-pointer transition-colors duration-200"
                onClick={(e) => {
                  e.stopPropagation();
                  onEdgeClick(link.edge_id);
                }}
              />
            );
          })}

          {/* Nodes */}
          {data.nodes.map((node) => {
            if (!visibleNodeTypes.has(node.node_type)) return null;

            const isSelected = selectedNodeId === node.node_id;
            const isFaded = highlightedNodeIds !== null && !highlightedNodeIds.has(node.node_id);
            const { scale, opacity } = getNodeSizeAndOpacity(node.confidence);
            const finalOpacity = isFaded ? 0.2 : opacity;
            const color = TYPE_COLORS[node.node_type] || "#ffffff";

            return (
              <g
                key={node.node_id}
                transform={`translate(${node.x},${node.y}) scale(${scale})`}
                opacity={finalOpacity}
                className={`cursor-pointer transition-all duration-200 ${
                  isSelected ? "stroke-[#3b82f6] stroke-[3px]" : "stroke-[#1f2937] stroke-[1px] hover:stroke-[#60a5fa] hover:stroke-[2px]"
                }`}
                onClick={(e) => {
                  e.stopPropagation();
                  onNodeClick(node.node_id);
                }}
              >
                {renderNodeShape(node.node_type, color)}
                <title>{`${node.label} (${node.node_type})`}</title>
              </g>
            );
          })}
        </g>
      </svg>
    </div>
  );
};

import { describe, it, expect, vi, beforeEach } from "vitest";
import React from "react";
import { NodeDetailPanel } from "../src/features/graph/components/NodeDetailPanel";
import { GraphControlPanel } from "../src/features/graph/components/GraphControlPanel";
import type { BdgNode } from "../src/types/phantom";
import type { GraphData } from "../src/features/graph/hooks/useGraphData";

let stateStore: any[] = [];
let stateIndex = 0;

vi.mock("react", async (importOriginal) => {
  const actual: any = await importOriginal();
  return {
    ...actual,
    useState: vi.fn((init) => {
      const currentIndex = stateIndex++;
      if (stateStore[currentIndex] === undefined) {
        stateStore[currentIndex] = init;
      }
      return [
        stateStore[currentIndex],
        (newVal: any) => {
          stateStore[currentIndex] = typeof newVal === "function" ? newVal(stateStore[currentIndex]) : newVal;
        },
      ];
    }),
    useEffect: vi.fn((cb) => cb()),
  };
});

const findElementWithText = (element: any, text: string): boolean => {
  if (typeof element === "string" || typeof element === "number") {
    return String(element).includes(text);
  }
  if (!element || !element.props) return false;
  if (element.props.children) {
    const children = Array.isArray(element.props.children)
      ? element.props.children.flat(Infinity)
      : [element.props.children];
    for (const child of children) {
      if (findElementWithText(child, text)) return true;
    }
  }
  return false;
};

const findAllCheckboxes = (element: any, results: any[] = []): any[] => {
  if (!element || typeof element !== "object") return results;
  if (element.type === "input" && element.props && element.props.type === "checkbox") {
    results.push(element);
  }
  if (element.props && element.props.children) {
    const children = Array.isArray(element.props.children)
      ? element.props.children.flat(Infinity)
      : [element.props.children];
    for (const child of children) {
      findAllCheckboxes(child, results);
    }
  }
  return results;
};

const findSearchInput = (element: any): any => {
  if (!element || typeof element !== "object") return null;
  if (
    element.type === "input" &&
    element.props &&
    element.props.type === "text" &&
    element.props.placeholder?.includes("highlight")
  ) {
    return element;
  }
  if (element.props && element.props.children) {
    const children = Array.isArray(element.props.children)
      ? element.props.children.flat(Infinity)
      : [element.props.children];
    for (const child of children) {
      const found = findSearchInput(child);
      if (found) return found;
    }
  }
  return null;
};

describe("Graph Visualizer Components", () => {
  beforeEach(() => {
    stateStore = [];
    stateIndex = 0;
    vi.clearAllMocks();
  });

  describe("NodeDetailPanel", () => {
    it("renders correct content for purl node type", () => {
      const mockPurlNode: BdgNode = {
        node_id: "123e4567-e89b-12d3-a456-426614174000",
        node_type: "purl",
        label: "pkg:npm/express@4.17.1",
        attributes: {
          purl: "pkg:npm/express@4.17.1",
          digest: "sha256:1234567890abcdef",
        },
        first_seen_at: "2026-07-25T12:00:00Z",
        last_seen_at: "2026-07-25T14:00:00Z",
        confidence: 0.95,
      };

      const elementTree = NodeDetailPanel({ node: mockPurlNode });

      expect(findElementWithText(elementTree, "pkg:npm/express@4.17.1")).toBe(true);
      expect(findElementWithText(elementTree, "purl")).toBe(true);
      expect(findElementWithText(elementTree, "PURL")).toBe(true);
      expect(findElementWithText(elementTree, "View SBOM")).toBe(true);
    });
  });

  describe("GraphControlPanel", () => {
    const mockData: GraphData = {
      nodes: [
        {
          node_id: "n1",
          node_type: "process",
          label: "node-server",
          attributes: {},
          first_seen_at: "2026-07-25T12:00:00Z",
          last_seen_at: "2026-07-25T14:00:00Z",
          confidence: 0.9,
          x: 0,
          y: 0,
        },
        {
          node_id: "n2",
          node_type: "file",
          label: "/etc/passwd",
          attributes: {},
          first_seen_at: "2026-07-25T12:00:00Z",
          last_seen_at: "2026-07-25T14:00:00Z",
          confidence: 0.8,
          x: 0,
          y: 0,
        },
      ],
      links: [],
    };

    it("filter toggles hide/show correct node types", () => {
      const onVisibilityChange = vi.fn();
      const visibleTypes = new Set([
        "workload",
        "container",
        "process",
        "purl",
        "file",
        "network_endpoint",
        "contract",
        "drift_event",
      ] as const);

      const renderPanel = () => {
        stateIndex = 0; // Reset index for each render
        return GraphControlPanel({
          data: mockData,
          onSearchChange: () => {},
          visibleNodeTypes: visibleTypes,
          onVisibilityChange,
          onQuerySubgraph: () => {},
          onShowFullGraph: () => {},
          mode: "full",
        });
      };

      const elementTree = renderPanel();
      const checkboxes = findAllCheckboxes(elementTree);
      expect(checkboxes.length).toBe(8); // 8 node types

      // "process" is the 3rd in ALL_NODE_TYPES
      const processCheckbox = checkboxes[2];
      expect(processCheckbox.props.checked).toBe(true);

      processCheckbox.props.onChange();

      expect(onVisibilityChange).toHaveBeenCalledTimes(1);
      const newSet = onVisibilityChange.mock.calls[0][0];
      expect(newSet.has("process")).toBe(false);
      expect(newSet.has("file")).toBe(true);
    });

    it("searching highlights matching nodes", () => {
      const onSearchChange = vi.fn();

      const renderPanel = () => {
        stateIndex = 0; // Reset index for each render
        return GraphControlPanel({
          data: mockData,
          onSearchChange,
          visibleNodeTypes: new Set(["process", "file"]),
          onVisibilityChange: () => {},
          onQuerySubgraph: () => {},
          onShowFullGraph: () => {},
          mode: "full",
        });
      };

      let elementTree = renderPanel();
      const searchInput = findSearchInput(elementTree);
      expect(searchInput).not.toBeNull();

      // Clear the first call that happens on mount (searchQuery is "")
      onSearchChange.mockClear();

      // Simulate typing "etc"
      searchInput.props.onChange({ target: { value: "etc" } });

      // Re-render the component so it uses the new state and fires useEffect
      elementTree = renderPanel();

      expect(onSearchChange).toHaveBeenCalledTimes(1);
      const matchSet = onSearchChange.mock.calls[0][0];
      expect(matchSet).not.toBeNull();
      expect(matchSet.has("n2")).toBe(true);
      expect(matchSet.has("n1")).toBe(false);
    });
  });
});

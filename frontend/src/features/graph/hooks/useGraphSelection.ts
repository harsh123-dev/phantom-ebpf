import { useState, useCallback } from "react";
import type { UUID } from "../../../types/phantom";

export interface SelectionState {
  type: "node" | "edge" | null;
  id: UUID | null;
}

export const useGraphSelection = () => {
  const [selection, setSelection] = useState<SelectionState>({ type: null, id: null });

  const selectNode = useCallback((id: UUID) => {
    setSelection({ type: "node", id });
  }, []);

  const selectEdge = useCallback((id: UUID) => {
    setSelection({ type: "edge", id });
  }, []);

  const deselect = useCallback(() => {
    setSelection({ type: null, id: null });
  }, []);

  return {
    selection,
    selectNode,
    selectEdge,
    deselect,
  };
};

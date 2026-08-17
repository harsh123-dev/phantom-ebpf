import { create } from "zustand";
import type { LiveDriftEvent, Severity, UUID } from "../types/phantom";

export type DriftConnectionStatus = "connecting" | "connected" | "disconnected" | "error";

export interface DriftFilters {
  namespaces: string[];
  minSeverity: Severity;
}

interface DriftStreamState {
  events: LiveDriftEvent[];
  connectionStatus: DriftConnectionStatus;
  filters: DriftFilters;
  lastEventId: UUID | null;
  errorCode: number | null;
  addEvent: (event: LiveDriftEvent) => void;
  setConnectionStatus: (status: DriftConnectionStatus) => void;
  setFilters: (filters: DriftFilters) => void;
  setErrorCode: (errorCode: number | null) => void;
  clearEvents: () => void;
}

const MAX_EVENTS = 500;

export const useDriftStreamState = create<DriftStreamState>((set) => ({
  events: [],
  connectionStatus: "disconnected",
  filters: { namespaces: [], minSeverity: "low" },
  lastEventId: null,
  errorCode: null,
  addEvent: (event) => set((state) => ({
    events: [event, ...state.events].slice(0, MAX_EVENTS),
    lastEventId: event.stream_event_id,
  })),
  setConnectionStatus: (connectionStatus) => set({ connectionStatus }),
  setFilters: (filters) => set({ filters }),
  setErrorCode: (errorCode) => set({ errorCode }),
  clearEvents: () => set({ events: [], lastEventId: null }),
}));

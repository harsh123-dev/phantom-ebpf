import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";
import { DriftEventRow } from "../src/features/dashboard/components/DriftEventRow";
import { LiveDriftFeed } from "../src/features/dashboard/components/LiveDriftFeed";
import { SeverityBarChart, severityBarHeight } from "../src/features/dashboard/components/SeverityBarChart";
import type { DriftConnectionStatus } from "../src/state/driftStreamState";
import { useDriftStreamState } from "../src/state/driftStreamState";
import type { LiveDriftEvent } from "../src/types/phantom";

const mockSetFilters = vi.fn();
let mockStatus: DriftConnectionStatus = "connecting";
let mockEvents: LiveDriftEvent[] = [];

vi.mock("../src/hooks/useDriftStream", () => ({
  useDriftStream: () => ({
    events: mockEvents,
    connectionStatus: mockStatus,
    setFilters: mockSetFilters,
  }),
}));

const sampleEvent: LiveDriftEvent = {
  schema_version: "v1",
  type: "drift_event",
  stream_event_id: "11111111-1111-4111-8111-111111111111",
  published_at: "2026-07-24T12:00:00.000Z",
  drift_event_id: "22222222-2222-4222-8222-222222222222",
  event_type: "exec",
  severity: "critical",
  namespace: "payments",
  pod_name: "api-7f9",
  image_digest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  identity_status: "resolved",
  violation_types: ["unexpected_executable"],
  attribution_id: null,
  pceps_score: 88,
};

describe("dashboard components", () => {
  it("DriftEventRow renders severity badge correctly", () => {
    const html = renderToStaticMarkup(<DriftEventRow event={sampleEvent} />);
    expect(html).toContain("CRITICAL");
    expect(html).toContain("bg-red-100");
  });

  it("SeverityBarChart renders correct bar heights", () => {
    const data = [
      { severity: "informational" as const, count: 1 },
      { severity: "low" as const, count: 2 },
      { severity: "medium" as const, count: 4 },
      { severity: "high" as const, count: 0 },
      { severity: "critical" as const, count: 8 },
    ];
    const html = renderToStaticMarkup(<SeverityBarChart data={data} />);
    expect(severityBarHeight(8, 8, 150)).toBe(150);
    expect(severityBarHeight(4, 8, 150)).toBe(75);
    expect(html).toContain('data-height="150"');
    expect(html).toContain('data-height="75"');
  });

  it("Live feed shows Connecting... when status is connecting", () => {
    mockStatus = "connecting";
    mockEvents = [];
    useDriftStreamState.setState({ filters: { namespaces: [], minSeverity: "low" } });
    const html = renderToStaticMarkup(<LiveDriftFeed />);
    expect(html).toContain("Connecting...");
  });

  it("Live feed shows Disconnected with reconnect button on error", () => {
    mockStatus = "error";
    mockEvents = [];
    useDriftStreamState.setState({ filters: { namespaces: [], minSeverity: "low" } });
    const html = renderToStaticMarkup(<LiveDriftFeed />);
    expect(html).toContain("Disconnected");
    expect(html).toContain("Reconnect");
  });
});

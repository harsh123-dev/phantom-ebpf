import { afterEach, describe, expect, it, vi } from "vitest";
import { PhantomGatewayClient } from "../src/api/gatewayClient";
import { DriftStreamClient } from "../src/api/websocketClient";
import { appendPage } from "../src/hooks/usePaginatedQuery";
import type { DriftStreamSubscribe, LiveDriftEvent } from "../src/types/phantom";

class FakeWebSocket {
  public static instances: FakeWebSocket[] = [];
  public onopen: (() => void) | null = null;
  public onmessage: ((event: MessageEvent<string>) => void) | null = null;
  public onclose: ((event: CloseEvent) => void) | null = null;
  public onerror: (() => void) | null = null;
  public readonly sent: string[] = [];

  public constructor(public readonly url: string) {
    FakeWebSocket.instances.push(this);
  }

  public send(data: string): void {
    this.sent.push(data);
  }

  public close(code = 1000, reason = ""): void {
    this.onclose?.({ code, reason } as CloseEvent);
  }

  public open(): void {
    this.onopen?.();
  }

  public message(data: string): void {
    this.onmessage?.(new MessageEvent("message", { data }));
  }
}

const subscription: DriftStreamSubscribe = {
  schema_version: "v1",
  type: "subscribe",
  namespace_filters: [],
  minimum_severity: "low",
  resume_after_event_id: null,
};

const liveEvent: LiveDriftEvent = {
  schema_version: "v1",
  type: "drift_event",
  stream_event_id: "11111111-1111-1111-1111-111111111111",
  published_at: "2026-07-24T00:00:00Z",
  drift_event_id: "22222222-2222-2222-2222-222222222222",
  event_type: "exec",
  severity: "high",
  namespace: "phantom",
  pod_name: "gateway-0",
  image_digest: null,
  identity_status: "resolved",
  violation_types: ["unexpected_executable"],
  attribution_id: null,
  pceps_score: null,
};

afterEach(() => {
  vi.unstubAllGlobals();
  vi.useRealTimers();
  FakeWebSocket.instances = [];
});

describe("PhantomGatewayClient", () => {
  it("returns a typed attribution result", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(JSON.stringify({
      attribution_id: "11111111-1111-1111-1111-111111111111",
      status: "completed",
    }), { status: 200 })));
    const client = new PhantomGatewayClient("https://phantom.example", () => "token");

    const result = await client.getAttribution("11111111-1111-1111-1111-111111111111");

    expect(result.status).toBe("completed");
  });

  it("throws ApiError with response fields for a 404", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(JSON.stringify({
      schema_version: "v1",
      error_code: "ATTRIBUTION_NOT_FOUND",
      message: "Attribution was not found.",
      request_id: "33333333-3333-3333-3333-333333333333",
      details: {},
    }), { status: 404, headers: { "X-Request-ID": "request-123" } })));
    const client = new PhantomGatewayClient("https://phantom.example", () => "token");

    const request = client.getAttribution("11111111-1111-1111-1111-111111111111");

    await expect(request).rejects.toMatchObject({
      status: 404,
      errorCode: "ATTRIBUTION_NOT_FOUND",
      requestId: "request-123",
    });
  });
});

describe("DriftStreamClient", () => {
  it("reconnects after close code 1013 using the last stream event ID", async () => {
    vi.useFakeTimers();
    vi.stubGlobal("WebSocket", FakeWebSocket);
    const client = new DriftStreamClient("ws://phantom.example/api/v1/streams/drift", () => "token");

    client.connect(subscription);
    const first = FakeWebSocket.instances[0];
    first.open();
    first.message(JSON.stringify({ type: "drift_event", data: liveEvent }));
    first.close(1013, "overloaded");
    await vi.advanceTimersByTimeAsync(1_000);

    expect(FakeWebSocket.instances).toHaveLength(2);
    FakeWebSocket.instances[1].open();
    expect(FakeWebSocket.instances[1].sent[0]).toContain(liveEvent.stream_event_id);
  });
});

describe("usePaginatedQuery", () => {
  it("appends the next page fetched by fetchNext", () => {
    const firstPage = { items: ["first"], next_cursor: "cursor-2" };
    const nextPage = { items: ["second"], next_cursor: null };

    expect(appendPage(firstPage.items, nextPage)).toEqual(["first", "second"]);
  });
});

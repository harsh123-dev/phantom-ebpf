import { isLiveDriftEvent, isRecord } from "./guards";
import type { DriftStreamSubscribe, LiveDriftEvent, UUID } from "../types/phantom";

type EventHandler = (event: LiveDriftEvent) => void;
type ErrorHandler = (code: number, reason: string) => void;
type ReconnectHandler = () => void;
type ConnectedHandler = () => void;

export class DriftStreamClient {
  private socket: WebSocket | null = null;
  private subscription: DriftStreamSubscribe | null = null;
  private lastEventId: UUID | null = null;
  private reconnectAttempts = 0;
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  private heartbeatTimer: ReturnType<typeof setInterval> | null = null;
  private pongTimer: ReturnType<typeof setTimeout> | null = null;
  private manuallyDisconnected = false;
  private readonly eventHandlers = new Set<EventHandler>();
  private readonly errorHandlers = new Set<ErrorHandler>();
  private readonly reconnectHandlers = new Set<ReconnectHandler>();
  private readonly connectedHandlers = new Set<ConnectedHandler>();

  public constructor(
    private readonly wsUrl: string,
    private readonly getToken: () => string | null,
  ) {}

  public connect(subscription: DriftStreamSubscribe): void {
    this.subscription = subscription;
    this.manuallyDisconnected = false;
    this.open();
  }

  public disconnect(): void {
    this.manuallyDisconnected = true;
    this.clearTimers();
    this.socket?.close(1000, "client disconnect");
    this.socket = null;
  }

  public onEvent(handler: EventHandler): () => void {
    this.eventHandlers.add(handler);
    return () => this.eventHandlers.delete(handler);
  }

  public onError(handler: ErrorHandler): () => void {
    this.errorHandlers.add(handler);
    return () => this.errorHandlers.delete(handler);
  }

  public onReconnect(handler: ReconnectHandler): () => void {
    this.reconnectHandlers.add(handler);
    return () => this.reconnectHandlers.delete(handler);
  }

  public onConnected(handler: ConnectedHandler): () => void {
    this.connectedHandlers.add(handler);
    return () => this.connectedHandlers.delete(handler);
  }

  private open(): void {
    const token = this.getToken();
    if (token === null || token.length === 0 || this.subscription === null) {
      this.emitError(4401, "A PHANTOM access token is required.");
      return;
    }
    const url = new URL(this.wsUrl);
    url.searchParams.set("token", token);
    this.socket = new WebSocket(url.toString());
    this.socket.onopen = () => this.handleOpen();
    this.socket.onmessage = (event) => this.handleMessage(event.data);
    this.socket.onclose = (event) => this.handleClose(event.code, event.reason);
    this.socket.onerror = () => this.emitError(0, "The live drift connection encountered an error.");
  }

  private handleOpen(): void {
    if (this.socket === null || this.subscription === null) return;
    this.reconnectAttempts = 0;
    this.socket.send(JSON.stringify({
      ...this.subscription,
      resume_after_event_id: this.lastEventId ?? this.subscription.resume_after_event_id,
    }));
    this.connectedHandlers.forEach((handler) => handler());
    this.startHeartbeat();
  }

  private handleMessage(raw: unknown): void {
    if (typeof raw !== "string") return;
    this.clearPongTimer();
    let message: unknown;
    try {
      message = JSON.parse(raw) as unknown;
    } catch {
      this.emitError(4408, "The live drift stream sent malformed data.");
      return;
    }
    if (isRecord(message) && message.type === "pong") {
      this.clearPongTimer();
      return;
    }
    if (isRecord(message) && message.type === "ping") {
      this.socket?.send(JSON.stringify({ type: "pong" }));
      return;
    }
    const payload = isRecord(message) && "data" in message ? message.data : message;
    if (!isLiveDriftEvent(payload)) return;
    this.lastEventId = payload.stream_event_id;
    this.eventHandlers.forEach((handler) => handler(payload));
  }

  private handleClose(code: number, reason: string): void {
    this.clearHeartbeat();
    if (this.manuallyDisconnected) return;
    if (code === 4401 || code === 4403) {
      this.emitError(code, reason || "The live drift connection was not authorized.");
      return;
    }
    if (code === 4408) {
      this.scheduleReconnect(0);
      return;
    }
    this.scheduleReconnect();
  }

  private scheduleReconnect(delay?: number): void {
    this.reconnectTimer = globalThis.setTimeout(() => {
      this.reconnectHandlers.forEach((handler) => handler());
      this.open();
    }, delay ?? Math.min(1_000 * 2 ** this.reconnectAttempts++, 30_000));
  }

  private startHeartbeat(): void {
    this.heartbeatTimer = globalThis.setInterval(() => {
      this.socket?.send(JSON.stringify({ type: "ping" }));
      this.clearPongTimer();
      this.pongTimer = globalThis.setTimeout(() => this.socket?.close(1013, "heartbeat timeout"), 10_000);
    }, 30_000);
  }

  private emitError(code: number, reason: string): void {
    this.errorHandlers.forEach((handler) => handler(code, reason));
  }

  private clearPongTimer(): void {
    if (this.pongTimer !== null) globalThis.clearTimeout(this.pongTimer);
    this.pongTimer = null;
  }

  private clearHeartbeat(): void {
    if (this.heartbeatTimer !== null) globalThis.clearInterval(this.heartbeatTimer);
    this.heartbeatTimer = null;
    this.clearPongTimer();
  }

  private clearTimers(): void {
    if (this.reconnectTimer !== null) globalThis.clearTimeout(this.reconnectTimer);
    this.reconnectTimer = null;
    this.clearHeartbeat();
  }
}

import { ApiError } from "./apiError";
import { isErrorResponse, isRecord } from "./guards";
import type {
  AttributionJobResponse,
  AttributionRequest,
  AttributionResultResponse,
  BdgEdge,
  BdgEdgeResponse,
  BdgNode,
  BdgNodeResponse,
  BehavioralContractDetailResponse,
  BehavioralContractRecord,
  ContractListParams,
  DriftEventDetailResponse,
  ErrorResponse,
  IncidentArchiveResponse,
  IncidentCreateRequest,
  IncidentDetailResponse,
  IncidentListParams,
  IncidentReport,
  IncidentUpdateRequest,
  PaginatedResponse,
  PcepsScoreRequest,
  PcepsScoreResponse,
  SbomDetailResponse,
  SbomListParams,
  SbomRecord,
  SbomVerificationRequest,
  SbomVerificationResponse,
  SubgraphQueryRequest,
  SubgraphResponse,
  UUID,
  VerificationJobResponse,
} from "../types/phantom";

type QueryValue = string | number | boolean | null | undefined;

interface RequestOptions {
  method?: "GET" | "POST" | "PATCH" | "DELETE";
  body?: unknown;
}

export class PhantomGatewayClient {
  public constructor(
    private readonly baseUrl: string,
    private readonly getToken: () => string | null,
    private readonly timeoutMs = 30_000,
  ) {}

  public getSbom(sbomId: UUID): Promise<SbomDetailResponse> {
    return this.request(`/sboms/${encodeURIComponent(sbomId)}`);
  }

  public listSboms(params: SbomListParams): Promise<PaginatedResponse<SbomRecord>> {
    return this.request(this.withQuery("/sboms", params));
  }

  public submitSbomVerification(
    sbomId: UUID,
    request: SbomVerificationRequest,
  ): Promise<VerificationJobResponse> {
    return this.request(`/sboms/${encodeURIComponent(sbomId)}/verification`, { method: "POST", body: request });
  }

  public getSbomVerification(sbomId: UUID): Promise<SbomVerificationResponse> {
    return this.request(`/sboms/${encodeURIComponent(sbomId)}/verification`);
  }

  public getContract(contractId: UUID): Promise<BehavioralContractDetailResponse> {
    return this.request(`/contracts/${encodeURIComponent(contractId)}`);
  }

  public listContracts(
    params: ContractListParams,
  ): Promise<PaginatedResponse<BehavioralContractRecord>> {
    return this.request(this.withQuery("/contracts", params));
  }

  public getBdgNode(nodeId: UUID, snapshotId?: UUID): Promise<BdgNodeResponse> {
    return this.request(this.withQuery(`/bdg/nodes/${encodeURIComponent(nodeId)}`, { snapshot_id: snapshotId }));
  }

  public getBdgEdge(edgeId: UUID, snapshotId?: UUID): Promise<BdgEdgeResponse> {
    return this.request(this.withQuery(`/bdg/edges/${encodeURIComponent(edgeId)}`, { snapshot_id: snapshotId }));
  }

  public querySubgraph(request: SubgraphQueryRequest): Promise<SubgraphResponse> {
    return this.request("/bdg/subgraphs:query", { method: "POST", body: request });
  }

  public submitAttribution(request: AttributionRequest): Promise<AttributionJobResponse> {
    return this.request("/attributions", { method: "POST", body: request });
  }

  public getAttribution(attributionId: UUID): Promise<AttributionResultResponse> {
    return this.request(`/attributions/${encodeURIComponent(attributionId)}`);
  }

  public submitPcepsScore(request: PcepsScoreRequest): Promise<PcepsScoreResponse> {
    return this.request("/pceps:scores", { method: "POST", body: request });
  }

  public createIncident(request: IncidentCreateRequest): Promise<IncidentReport> {
    return this.request("/incidents", { method: "POST", body: request });
  }

  public getIncident(incidentId: UUID): Promise<IncidentDetailResponse> {
    return this.request(`/incidents/${encodeURIComponent(incidentId)}`);
  }

  public listIncidents(params: IncidentListParams): Promise<PaginatedResponse<IncidentReport>> {
    return this.request(this.withQuery("/incidents", params));
  }

  public updateIncident(incidentId: UUID, request: IncidentUpdateRequest): Promise<IncidentReport> {
    return this.request(`/incidents/${encodeURIComponent(incidentId)}`, { method: "PATCH", body: request });
  }

  public archiveIncident(incidentId: UUID): Promise<IncidentArchiveResponse> {
    return this.request(`/incidents/${encodeURIComponent(incidentId)}`, { method: "DELETE" });
  }

  public getDriftEvent(driftEventId: UUID): Promise<DriftEventDetailResponse> {
    return this.request(`/drift-events/${encodeURIComponent(driftEventId)}`);
  }

  private async request<T>(path: string, options: RequestOptions = {}): Promise<T> {
    const token = this.getToken();
    if (token === null || token.length === 0) {
      throw new ApiError(401, "AUTH_TOKEN_MISSING", "A PHANTOM access token is required.", null);
    }

    const controller = new AbortController();
    const timeoutId = globalThis.setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      const response = await fetch(`${this.baseUrl.replace(/\/$/, "")}/api/v1${path}`, {
        method: options.method ?? "GET",
        headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
        body: options.body === undefined ? undefined : JSON.stringify(options.body),
        signal: controller.signal,
      });
      const payload: unknown = await response.json().catch(() => null);
      if (!response.ok) {
        this.throwApiError(response.status, response.headers.get("X-Request-ID"), payload);
      }
      if (!isRecord(payload)) {
        throw new ApiError(response.status, "INVALID_RESPONSE", "The API returned an invalid response.", null);
      }
      return payload as T;
    } catch (error: unknown) {
      if (error instanceof ApiError) throw error;
      const message = error instanceof DOMException && error.name === "AbortError"
        ? "The API request timed out."
        : "The API request could not be completed.";
      throw new ApiError(0, "NETWORK_ERROR", message, null);
    } finally {
      globalThis.clearTimeout(timeoutId);
    }
  }

  private throwApiError(status: number, requestId: string | null, payload: unknown): never {
    const error: ErrorResponse | null = isErrorResponse(payload) ? payload : null;
    throw new ApiError(
      status,
      error?.error_code ?? "API_ERROR",
      error?.message ?? "The API request failed.",
      requestId ?? error?.request_id ?? null,
      error?.details,
    );
  }

  private withQuery(path: string, params: object): string {
    const query = new URLSearchParams();
    Object.keys(params).forEach((key) => {
      const value = Reflect.get(params, key) as QueryValue;
      if (value !== null && value !== undefined) query.set(key, String(value));
    });
    const encoded = query.toString();
    return encoded.length > 0 ? `${path}?${encoded}` : path;
  }
}
